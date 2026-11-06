const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const Color = require('./public/color.js');
const { WebSocketServer } = require('ws');
const { db, q, getSetting, setSetting, delSetting, hashPassword, verifyPassword, newCode, questionWithOptions, tally, resultsForSession } = require('./db');

const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const SECURE_COOKIE = PUBLIC_URL.startsWith('https://');
const TALLY_INTERVAL_MS = 250;

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ---------------------------------------------------------------- security: headers, rate limits, origin checks
const MAX_VOTES_PER_IP = parseInt(process.env.MAX_VOTES_PER_IP || '500', 10); // venue Wi-Fi shares one address; raise for very large rooms
const BIND_HOST = process.env.HOST || '127.0.0.1'; // only reachable through the web server, never directly from the internet
const CSP = ["default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  'font-src https://fonts.gstatic.com', "img-src 'self' data:", "connect-src 'self' ws: wss:", "object-src 'none'", "base-uri 'none'", "form-action 'self'"];
app.use((req, res, next) => {
  const embeddable = req.path === '/screen'; // the big screen may be shown inside another page or slide; nothing else may
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (SECURE_COOKIE) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  res.setHeader('Content-Security-Policy', CSP.concat(embeddable ? 'frame-ancestors *' : "frame-ancestors 'none'").join('; '));
  if (!embeddable) res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Fixed-window counters. hit() counts one request and returns seconds to wait if over the limit (0 = fine).
function bucket(windowMs, max) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, windowMs).unref();
  const wait = r => Math.max(1, Math.ceil((r.reset - Date.now()) / 1000));
  return {
    hit(k) {
      const now = Date.now(); let r = hits.get(k);
      if (!r || r.reset < now) { r = { n: 0, reset: now + windowMs }; hits.set(k, r); }
      r.n++; return r.n > max ? wait(r) : 0;
    },
    over(k) { const r = hits.get(k); return r && r.reset >= Date.now() && r.n >= max ? wait(r) : 0; },
    clear(k) { hits.delete(k); },
  };
}
const globalB = bucket(60_000, 20000);   // per address, all requests (high: a whole room can share one address)
const joinB = bucket(60_000, 120);       // session lookups and QR images
const probeB = bucket(60_000, 40);       // wrong session codes (blocks code guessing)
const adminB = bucket(60_000, 1500);     // signed-in admin/host requests
const voteTokenB = bucket(60_000, 30);   // per voter device
const pollTokenB = bucket(60_000, 120);  // per voter device (polling fallback runs about 40 a minute)
const wsConnB = bucket(60_000, 1500);    // WebSocket connection attempts per address
const loginB = bucket(10 * 60_000, 8);   // failed sign-ins per address
const limit = (b, keyFn = req => req.ip) => (req, res, next) => {
  const w = b.hit(keyFn(req));
  if (!w) return next();
  res.setHeader('Retry-After', w);
  res.status(429).json({ error: 'Too many requests. Wait a moment and try again.' });
};
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); // async route errors go to the error handler
const isLoopback = ip => ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
const wsIp = req => { // same rule as express "trust proxy 1": the last address is the one our web server added
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : req.socket.remoteAddress;
};
function originOk(req) { // blocks other websites from making a signed-in browser change things
  const o = req.headers.origin;
  if (!o) return true;
  try {
    if (PUBLIC_URL && o === new URL(PUBLIC_URL).origin) return true;
    return new URL(o).host === req.get('host');
  } catch { return false; }
}
const ipVotes = new Map(); // "sessionId:questionId:ip" -> accepted votes
app.use(limit(globalB));
app.use(express.json({ limit: '50kb' }));
app.use('/api', (req, res, next) => (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || originOk(req)) ? next() : res.status(403).json({ error: 'Request blocked.' }));

// ---------------------------------------------------------------- auth
// Sign-ins live in SQLite (hashed) so an app restart doesn't log anyone out.
const AUTH_TTL_MS = 24 * 60 * 60 * 1000;
const hashToken = t => crypto.createHash('sha256').update(t).digest('hex');
db.prepare('DELETE FROM auth_sessions WHERE exp < ?').run(Date.now());
setInterval(() => db.prepare('DELETE FROM auth_sessions WHERE exp < ?').run(Date.now()), 60 * 60 * 1000).unref();

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function userFromRequest(req) {
  const t = parseCookies(req.headers.cookie).sid;
  if (!t) return null;
  const rec = db.prepare('SELECT username, exp FROM auth_sessions WHERE token_hash = ?').get(hashToken(t));
  if (!rec) return null;
  if (rec.exp < Date.now()) { db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(hashToken(t)); return null; }
  return rec.username;
}
function requireAuth(req, res, next) {
  const u = userFromRequest(req);
  if (!u) return res.status(401).json({ error: 'Sign in to continue.' });
  req.user = u;
  next();
}
function requireAuthPage(req, res, next) {
  if (!userFromRequest(req)) return res.redirect('/login?next=' + encodeURIComponent(req.path));
  next();
}

const DUMMY_HASH = hashPassword('not-a-real-password'); // verified when the username doesn't exist, so timing doesn't reveal valid usernames
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const wait = loginB.over(ip);
  if (wait) { res.setHeader('Retry-After', wait); return res.status(429).json({ error: 'Too many attempts. Wait a few minutes and try again.' }); }
  const { username, password } = req.body || {};
  const user = typeof username === 'string' ? q.userByName.get(username) : null;
  let ok = false;
  try {
    const good = typeof password === 'string' && password.length <= 200 ? verifyPassword(password, user ? user.pass_hash : DUMMY_HASH) : false;
    ok = !!user && good;
  } catch { ok = false; }
  if (!ok) { loginB.hit(ip); return res.status(401).json({ error: 'Username or password is incorrect.' }); }
  loginB.clear(ip);
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO auth_sessions (token_hash, username, exp) VALUES (?, ?, ?)').run(hashToken(token), user.username, Date.now() + AUTH_TTL_MS);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${AUTH_TTL_MS / 1000}${SECURE_COOKIE ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  const t = parseCookies(req.headers.cookie).sid;
  if (t) db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?').run(hashToken(t));
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.user }));
app.post('/api/password', requireAuth, (req, res) => {
  const { current, next } = req.body || {};
  const user = q.userByName.get(req.user);
  if (typeof current !== 'string' || !verifyPassword(current, user.pass_hash)) return res.status(400).json({ error: 'Current password is incorrect.' });
  if (typeof next !== 'string' || next.length < 12 || next.length > 200) return res.status(400).json({ error: 'New password must be 12 to 200 characters.' });
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPassword(next), user.id);
  // sign out every other browser that was signed in with the old password
  db.prepare('DELETE FROM auth_sessions WHERE username = ? AND token_hash != ?').run(user.username, hashToken(parseCookies(req.headers.cookie).sid || ''));
  res.json({ ok: true });
});

// ---------------------------------------------------------------- branding (public read)
function themeColors() {
  const out = {};
  for (const k of ['primary', 'dark', 'light']) { const v = getSetting('color_' + k); out[k] = Color.isHex(v) ? v : Color.DEFAULTS[k]; }
  return out;
}
const LOGO_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'];
function brandInfo() {
  const logo = getSetting('logo_b64');
  return { colors: themeColors(), name: getSetting('brand_name', 'Live Poll'), showName: getSetting('show_name', '1') === '1', logo: !!logo, v: logo ? crypto.createHash('md5').update(logo).digest('hex').slice(0, 8) : '' };
}
app.get('/theme.css', (req, res) => {
  const vars = Color.derive(themeColors());
  res.type('text/css').setHeader('Cache-Control', 'no-cache');
  res.send(':root {\n' + Object.entries(vars).map(([k, v]) => `  ${k}: ${v};`).join('\n') + '\n}\n');
});
app.get('/api/brand', (req, res) => { res.setHeader('Cache-Control', 'no-cache'); res.json(brandInfo()); });
app.get('/brand/logo', (req, res) => {
  const b64 = getSetting('logo_b64');
  if (!b64) return res.status(404).end();
  res.setHeader('Content-Type', getSetting('logo_mime', 'image/png'));
  res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(Buffer.from(b64, 'base64'));
});

// ---------------------------------------------------------------- pages
const pub = path.join(__dirname, 'public');
const page = f => (req, res) => { res.setHeader('Cache-Control', 'no-cache'); res.sendFile(path.join(pub, f)); };
app.get('/', page('voter.html'));
app.get('/screen', page('screen.html'));
app.get('/login', page('login.html'));
app.get('/host', requireAuthPage, page('host.html'));
app.get('/admin', requireAuthPage, page('admin.html'));
app.get('/qrpage', requireAuthPage, page('qrpage.html'));
// no-cache = the browser re-checks with the server each time (a cheap 304 when unchanged), so updates always show up
app.use(express.static(pub, { index: false, setHeaders: res => res.setHeader('Cache-Control', 'no-cache') }));

// ---------------------------------------------------------------- QR on the fly
function joinUrl(req, code) {
  const base = PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  return `${base}/?s=${code}`;
}
app.get('/qr.svg', limit(joinB), ah(async (req, res) => {
  const s = q.sessionByCode.get(String(req.query.s || '').toUpperCase());
  if (!s) return res.status(404).send('Unknown session');
  const svg = await QRCode.toString(joinUrl(req, s.code), { type: 'svg', margin: 1, errorCorrectionLevel: 'M', color: { dark: Color.isHex(req.query.fg) ? req.query.fg : themeColors().dark, light: Color.isHex(req.query.bg) ? req.query.bg : '#ffffff' } });
  res.type('image/svg+xml').setHeader('Cache-Control', 'no-store');
  res.send(svg);
}));
app.get('/qr.png', limit(joinB), ah(async (req, res) => {
  const s = q.sessionByCode.get(String(req.query.s || '').toUpperCase());
  if (!s) return res.status(404).send('Unknown session');
  const buf = await QRCode.toBuffer(joinUrl(req, s.code), { margin: 2, width: 1200, errorCorrectionLevel: 'M' });
  res.type('png');
  if (req.query.download) res.setHeader('Content-Disposition', `attachment; filename="poll-${s.code}.png"`);
  res.send(buf);
}));
app.get('/api/join/:code', limit(joinB), (req, res) => {
  if (probeB.over(req.ip)) return res.status(429).json({ error: 'Too many requests. Wait a moment and try again.' });
  const s = q.sessionByCode.get(req.params.code.toUpperCase());
  if (!s) { probeB.hit(req.ip); return res.status(404).json({ error: 'Session not found.' }); }
  res.json({ code: s.code, name: s.name, state: s.state, url: joinUrl(req, s.code) });
});

// ---------------------------------------------------------------- live state
const rooms = new Map(); // code -> Set<ws>
function room(code) { if (!rooms.has(code)) rooms.set(code, new Set()); return rooms.get(code); }

function snapshot(code, role, token) {
  const s = q.sessionByCode.get(code);
  if (!s) return null;
  const qs = q.questionsOfPoll.all(s.poll_id);
  const idx = s.current_question_id ? qs.findIndex(x => x.id === s.current_question_id) : -1;
  const out = {
    type: 'state',
    session: { code: s.code, name: s.name, state: s.state, phase: s.phase, showProgress: !!s.show_progress },
    index: idx + 1, total: qs.length, question: null,
  };
  const privileged = role === 'screen' || role === 'host';
  if (s.state === 'live' && s.current_question_id) {
    const showQuestion = privileged || s.phase === 'open' || s.phase === 'closed';
    if (showQuestion) out.question = questionWithOptions(s.current_question_id);
    if (out.question && (privileged || s.phase === 'closed')) out.tally = tally(s.id, s.current_question_id);
    if (out.question && token) {
      const mine = q.myVote.get(s.id, s.current_question_id, token);
      out.mine = mine ? mine.option_id : null;
    }
  }
  if (role === 'host') out.questions = qs.map(x => ({ id: x.id, text: x.text }));
  return out;
}
function pushState(code) {
  for (const ws of room(code)) {
    if (ws.readyState !== 1) continue;
    const snap = snapshot(code, ws.role, ws.token);
    if (snap) ws.send(JSON.stringify(snap));
  }
}
const tallyDirty = new Set();
setInterval(() => {
  for (const code of tallyDirty) {
    const s = q.sessionByCode.get(code);
    if (!s || !s.current_question_id) continue;
    const msg = JSON.stringify({ type: 'tally', questionId: s.current_question_id, ...tally(s.id, s.current_question_id) });
    for (const ws of room(code)) if (ws.readyState === 1 && (ws.role === 'screen' || ws.role === 'host')) ws.send(msg);
  }
  tallyDirty.clear();
}, TALLY_INTERVAL_MS);

// ---------------------------------------------------------------- host controls
const HOST_ACTIONS = {
  golive(s) {
    const qs = q.questionsOfPoll.all(s.poll_id);
    if (!qs.length) throw new Error('This poll has no questions yet.');
    db.prepare("UPDATE sessions SET state='live', current_question_id=?, phase='waiting' WHERE id=?")
      .run(s.current_question_id && s.state === 'live' ? s.current_question_id : qs[0].id, s.id);
  },
  open(s) {
    if (s.state !== 'live' || !s.current_question_id) throw new Error('Go live first.');
    db.prepare("UPDATE sessions SET phase='open' WHERE id=?").run(s.id);
  },
  close(s) {
    if (s.phase !== 'open') throw new Error('Voting is not open.');
    db.prepare("UPDATE sessions SET phase='closed' WHERE id=?").run(s.id);
  },
  next(s) {
    const qs = q.questionsOfPoll.all(s.poll_id);
    const i = qs.findIndex(x => x.id === s.current_question_id);
    if (i === -1 || i === qs.length - 1) {
      db.prepare("UPDATE sessions SET phase='done' WHERE id=?").run(s.id);
    } else {
      db.prepare("UPDATE sessions SET current_question_id=?, phase='waiting' WHERE id=?").run(qs[i + 1].id, s.id);
    }
  },
  prev(s) {
    const qs = q.questionsOfPoll.all(s.poll_id);
    const i = qs.findIndex(x => x.id === s.current_question_id);
    if (i > 0) db.prepare("UPDATE sessions SET current_question_id=?, phase='waiting' WHERE id=?").run(qs[i - 1].id, s.id);
  },
  goto(s, body) {
    const qu = q.question.get(parseInt(body.questionId, 10));
    if (!qu || qu.poll_id !== s.poll_id) throw new Error('That question is not in this poll.');
    db.prepare("UPDATE sessions SET state='live', current_question_id=?, phase='waiting' WHERE id=?").run(qu.id, s.id);
  },
  progress(s, body) { db.prepare('UPDATE sessions SET show_progress = ? WHERE id = ?').run(body.show ? 1 : 0, s.id); },
  end(s) { db.prepare("UPDATE sessions SET state='ended', phase='done' WHERE id=?").run(s.id); },
  restart(s) { db.prepare("UPDATE sessions SET state='scheduled', current_question_id=NULL, phase='waiting' WHERE id=?").run(s.id); },
};
app.post('/api/host/:code/:action', requireAuth, (req, res) => {
  const code = req.params.code.toUpperCase();
  const s = q.sessionByCode.get(code);
  const fn = HOST_ACTIONS[req.params.action];
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  if (!fn) return res.status(400).json({ error: 'Unknown action.' });
  try { fn(s, req.body || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
  pushState(code);
  res.json({ ok: true });
});

// ---------------------------------------------------------------- admin API
const admin = express.Router();
admin.use(requireAuth);
admin.use(limit(adminB));
// Shows how the server sees your connection, so you can confirm the proxy passes your real address on.
admin.get('/debug/ip', (req, res) => res.json({ ip: req.ip, forwardedFor: req.headers['x-forwarded-for'] || null, proxyHeaderSeen: !!req.headers['x-forwarded-for'], protocol: req.protocol, host: req.get('host') }));
const int = v => parseInt(v, 10);
const cleanText = (v, max = 400) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function pollTree(id) {
  const p = db.prepare('SELECT * FROM polls WHERE id = ?').get(id);
  if (!p) return null;
  return { id: p.id, title: p.title, questions: q.questionsOfPoll.all(id).map(qu => ({ id: qu.id, position: qu.position, text: qu.text, options: q.optionsOfQuestion.all(qu.id).map(o => ({ id: o.id, label: o.label })) })) };
}
admin.get('/polls', (req, res) => res.json(db.prepare('SELECT id FROM polls ORDER BY id').all().map(r => pollTree(r.id))));
admin.post('/polls', (req, res) => {
  const title = cleanText(req.body.title, 200);
  if (!title) return res.status(400).json({ error: 'Give the poll a title.' });
  res.json(pollTree(db.prepare('INSERT INTO polls (title) VALUES (?)').run(title).lastInsertRowid));
});
admin.put('/polls/:id', (req, res) => {
  const title = cleanText(req.body.title, 200);
  if (!title) return res.status(400).json({ error: 'Give the poll a title.' });
  db.prepare('UPDATE polls SET title = ? WHERE id = ?').run(title, int(req.params.id));
  res.json(pollTree(int(req.params.id)));
});
admin.delete('/polls/:id', (req, res) => {
  db.prepare('DELETE FROM polls WHERE id = ?').run(int(req.params.id));
  res.json({ ok: true });
});
admin.post('/polls/:id/duplicate', (req, res) => {
  const src = pollTree(int(req.params.id));
  if (!src) return res.status(404).json({ error: 'Poll not found.' });
  const tx = db.transaction(() => {
    const pid = db.prepare('INSERT INTO polls (title) VALUES (?)').run(src.title + ' (copy)').lastInsertRowid;
    src.questions.forEach(qu => {
      const qid = db.prepare('INSERT INTO questions (poll_id, position, text) VALUES (?, ?, ?)').run(pid, qu.position, qu.text).lastInsertRowid;
      qu.options.forEach((o, j) => db.prepare('INSERT INTO options (question_id, position, label) VALUES (?, ?, ?)').run(qid, j + 1, o.label));
    });
    return pid;
  });
  res.json(pollTree(tx()));
});

function saveOptions(questionId, labels) {
  const existing = q.optionsOfQuestion.all(questionId);
  labels.forEach((label, i) => {
    if (existing[i]) db.prepare('UPDATE options SET label = ?, position = ? WHERE id = ?').run(label, i + 1, existing[i].id);
    else db.prepare('INSERT INTO options (question_id, position, label) VALUES (?, ?, ?)').run(questionId, i + 1, label);
  });
  for (let i = labels.length; i < existing.length; i++) db.prepare('DELETE FROM options WHERE id = ?').run(existing[i].id);
}
function parseQuestionBody(body) {
  const text = cleanText(body.text);
  const labels = (Array.isArray(body.options) ? body.options : []).map(o => cleanText(o, 200)).filter(Boolean);
  if (!text) return { error: 'Enter the question text.' };
  if (labels.length < 2) return { error: 'Add at least two answer choices.' };
  if (labels.length > 12) return { error: 'Use 12 answer choices or fewer.' };
  return { text, labels };
}
admin.post('/polls/:id/questions', (req, res) => {
  const b = parseQuestionBody(req.body);
  if (b.error) return res.status(400).json({ error: b.error });
  const pid = int(req.params.id);
  db.transaction(() => {
    const pos = (db.prepare('SELECT COALESCE(MAX(position),0) AS m FROM questions WHERE poll_id = ?').get(pid).m) + 1;
    const qid = db.prepare('INSERT INTO questions (poll_id, position, text) VALUES (?, ?, ?)').run(pid, pos, b.text).lastInsertRowid;
    saveOptions(qid, b.labels);
  })();
  res.json(pollTree(pid));
});
admin.put('/questions/:id', (req, res) => {
  const b = parseQuestionBody(req.body);
  if (b.error) return res.status(400).json({ error: b.error });
  const qu = q.question.get(int(req.params.id));
  if (!qu) return res.status(404).json({ error: 'Question not found.' });
  db.transaction(() => {
    db.prepare('UPDATE questions SET text = ? WHERE id = ?').run(b.text, qu.id);
    saveOptions(qu.id, b.labels);
  })();
  res.json(pollTree(qu.poll_id));
});
admin.delete('/questions/:id', (req, res) => {
  const qu = q.question.get(int(req.params.id));
  if (!qu) return res.status(404).json({ error: 'Question not found.' });
  db.prepare('DELETE FROM questions WHERE id = ?').run(qu.id);
  q.questionsOfPoll.all(qu.poll_id).forEach((x, i) => db.prepare('UPDATE questions SET position = ? WHERE id = ?').run(i + 1, x.id));
  res.json(pollTree(qu.poll_id));
});
admin.post('/questions/:id/move', (req, res) => {
  const qu = q.question.get(int(req.params.id));
  if (!qu) return res.status(404).json({ error: 'Question not found.' });
  const list = q.questionsOfPoll.all(qu.poll_id);
  const i = list.findIndex(x => x.id === qu.id);
  const j = req.body.dir === 'up' ? i - 1 : i + 1;
  if (j >= 0 && j < list.length) {
    [list[i], list[j]] = [list[j], list[i]];
    db.transaction(() => list.forEach((x, k) => db.prepare('UPDATE questions SET position = ? WHERE id = ?').run(k + 1, x.id)))();
  }
  res.json(pollTree(qu.poll_id));
});

// branding (admin)
admin.put('/brand', (req, res) => {
  const name = cleanText(req.body.name, 80);
  if (!name) return res.status(400).json({ error: 'Enter an organization name.' });
  setSetting('brand_name', name);
  if (typeof req.body.showName === 'boolean') setSetting('show_name', req.body.showName ? '1' : '0');
  res.json(brandInfo());
});
admin.put('/brand/colors', (req, res) => {
  const b = req.body || {};
  if (!['primary', 'dark', 'light'].every(k => Color.isHex(b[k]))) return res.status(400).json({ error: 'Choose all three colors.' });
  for (const k of ['primary', 'dark', 'light']) setSetting('color_' + k, b[k].toLowerCase());
  res.json(brandInfo());
});
admin.delete('/brand/colors', (req, res) => { for (const k of ['primary', 'dark', 'light']) delSetting('color_' + k); res.json(brandInfo()); });
admin.post('/brand/logo', express.raw({ type: LOGO_TYPES, limit: '1mb' }), (req, res) => {
  const type = (req.headers['content-type'] || '').split(';')[0];
  if (!LOGO_TYPES.includes(type) || !Buffer.isBuffer(req.body) || !req.body.length) {
    return res.status(400).json({ error: 'Upload a PNG, JPG, WebP or SVG file under 1 MB.' });
  }
  setSetting('logo_b64', req.body.toString('base64'));
  setSetting('logo_mime', type);
  setSetting('show_name', '0'); // a logo usually carries the name already; Admin can turn it back on
  res.json(brandInfo());
});
admin.delete('/brand/logo', (req, res) => { delSetting('logo_b64'); delSetting('logo_mime'); setSetting('show_name', '1'); res.json(brandInfo()); });

function sessionRow(s) {
  const poll = db.prepare('SELECT title FROM polls WHERE id = ?').get(s.poll_id);
  const votes = db.prepare('SELECT COUNT(*) AS n FROM votes WHERE session_id = ?').get(s.id).n;
  return { id: s.id, code: s.code, name: s.name, pollId: s.poll_id, pollTitle: poll ? poll.title : '', eventDate: s.event_date, showProgress: !!s.show_progress, state: s.state, phase: s.phase, votes };
}
admin.get('/sessions', (req, res) => res.json(db.prepare('SELECT * FROM sessions ORDER BY id DESC').all().map(sessionRow)));
admin.post('/sessions', (req, res) => {
  const name = cleanText(req.body.name, 200);
  const pollId = int(req.body.pollId);
  if (!name) return res.status(400).json({ error: 'Name the session.' });
  if (!db.prepare('SELECT 1 FROM polls WHERE id = ?').get(pollId)) return res.status(400).json({ error: 'Choose a poll.' });
  const date = cleanText(req.body.eventDate, 40) || null;
  const id = db.prepare('INSERT INTO sessions (code, name, poll_id, event_date, show_progress) VALUES (?, ?, ?, ?, ?)').run(newCode(), name, pollId, date, req.body.showProgress === false ? 0 : 1).lastInsertRowid;
  res.json(sessionRow(db.prepare('SELECT * FROM sessions WHERE id = ?').get(id)));
});
admin.patch('/sessions/:id', (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(int(req.params.id));
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  if (typeof req.body.showProgress === 'boolean') db.prepare('UPDATE sessions SET show_progress = ? WHERE id = ?').run(req.body.showProgress ? 1 : 0, s.id);
  pushState(s.code);
  res.json(sessionRow(db.prepare('SELECT * FROM sessions WHERE id = ?').get(s.id)));
});
admin.delete('/sessions/:id', (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(int(req.params.id));
  if (s) { db.prepare('DELETE FROM sessions WHERE id = ?').run(s.id); pushState(s.code); }
  res.json({ ok: true });
});
admin.post('/sessions/:id/clear-votes', (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(int(req.params.id));
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  db.prepare('DELETE FROM votes WHERE session_id = ?').run(s.id);
  for (const k of ipVotes.keys()) if (k.startsWith(s.id + ':')) ipVotes.delete(k);
  pushState(s.code);
  res.json({ ok: true });
});
admin.get('/sessions/:id/results', (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(int(req.params.id));
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  res.json(resultsForSession(s.id));
});
admin.get('/sessions/:id/results.csv', (req, res) => {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(int(req.params.id));
  if (!s) return res.status(404).send('Session not found.');
  const esc = v => `"${String(v).replace(/"/g, '""')}"`;
  const rows = [['Question', 'Answer', 'Votes', 'Percent'].map(esc).join(',')];
  for (const qu of resultsForSession(s.id)) {
    for (const o of qu.options) rows.push([qu.text, o.label, o.count, qu.total ? (o.count * 100 / qu.total).toFixed(1) + '%' : '0.0%'].map(esc).join(','));
  }
  res.type('text/csv').setHeader('Content-Disposition', `attachment; filename="results-${s.code}.csv"`);
  res.send(rows.join('\r\n'));
});
app.use('/api/admin', admin);

// ---------------------------------------------------------------- websockets
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 2048 });

const wsPerIp = new Map(); // address -> open sockets
const MAX_SOCKETS_PER_IP = 3000;
server.on('upgrade', (req, socket, head) => {
  socket.on('error', () => {});
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws') return socket.destroy();
  const ip = wsIp(req);
  if (req.headers.origin && !originOk(req)) return socket.destroy(); // another website trying to open a connection
  if (wsConnB.hit(ip) || probeB.over(ip) || (wsPerIp.get(ip) || 0) >= MAX_SOCKETS_PER_IP) return socket.destroy();
  const role = url.searchParams.get('role');
  const code = (url.searchParams.get('s') || '').toUpperCase();
  const token = url.searchParams.get('t') || '';
  if (!['voter', 'screen', 'host'].includes(role)) return socket.destroy();
  if (!q.sessionByCode.get(code)) { probeB.hit(ip); return socket.destroy(); }
  if (role === 'host' && !userFromRequest(req)) return socket.destroy();
  wss.handleUpgrade(req, socket, head, ws => {
    ws.role = role; ws.code = code; ws.ip = ip;
    ws.token = /^[A-Za-z0-9_-]{16,64}$/.test(token) ? token : '';
    ws.alive = true; ws.msgs = 0;
    wsPerIp.set(ip, (wsPerIp.get(ip) || 0) + 1);
    room(code).add(ws);
    ws.on('pong', () => { ws.alive = true; });
    ws.on('close', () => { room(code).delete(ws); const n = (wsPerIp.get(ip) || 1) - 1; if (n > 0) wsPerIp.set(ip, n); else wsPerIp.delete(ip); });
    ws.on('error', () => {});
    ws.on('message', data => onMessage(ws, data));
    const snap = snapshot(code, role, ws.token);
    ws.send(JSON.stringify(snap));
  });
});
setInterval(() => { for (const set of rooms.values()) for (const ws of set) ws.msgs = 0; }, 10000).unref();

// Shared by the WebSocket and the HTTP fallback. Returns the ack payload.
function castVote(code, token, optionIdRaw, ip) {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(token || '')) return { ok: false, error: 'Reload the page and try again.' };
  const s = q.sessionByCode.get(code);
  if (!s || s.state !== 'live' || s.phase !== 'open' || !s.current_question_id) {
    return { ok: false, error: 'Voting is closed for this question.' };
  }
  const optionId = int(optionIdRaw);
  const opt = db.prepare('SELECT 1 FROM options WHERE id = ? AND question_id = ?').get(optionId, s.current_question_id);
  if (!opt) return { ok: false, error: 'That choice is not part of this question.' };
  // Cap accepted votes per network address (a whole room can share one, so the cap is generous). Skipped if the proxy didn't tell us the real address.
  const ipKey = `${s.id}:${s.current_question_id}:${ip}`;
  const capped = ip && !isLoopback(ip) && (ipVotes.get(ipKey) || 0) >= MAX_VOTES_PER_IP;
  if (capped && !q.myVote.get(s.id, s.current_question_id, token)) return { ok: false, error: 'Too many votes from this network. Ask the host for help.' };
  const r = q.insertVote.run(s.id, s.current_question_id, optionId, token);
  if (r.changes === 0) {
    const mine = q.myVote.get(s.id, s.current_question_id, token);
    return { ok: false, error: 'You already voted on this question.', optionId: mine ? mine.option_id : null };
  }
  if (ip) ipVotes.set(ipKey, (ipVotes.get(ipKey) || 0) + 1);
  tallyDirty.add(code);
  return { ok: true, optionId };
}

function onMessage(ws, data) {
  let msg;
  try { msg = JSON.parse(data.toString()); } catch { return; }
  if (ws.role !== 'voter' || msg.type !== 'vote') return;
  if (++ws.msgs > 30) return ws.close(1008, 'Too many messages'); // a person taps once; this is a script
  if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'ack', ...castVote(ws.code, ws.token, msg.optionId, ws.ip) }));
}

// ---------------------------------------------------------------- HTTP fallback (when WebSockets are blocked)
app.get('/api/poll/:code', (req, res) => {
  const role = req.query.role;
  const ip = req.ip;
  if (probeB.over(ip)) return res.status(429).json({ error: 'Too many requests. Wait a moment and try again.' });
  if (!['voter', 'screen', 'host'].includes(role)) return res.status(400).json({ error: 'Bad role.' });
  if (role === 'host' && !userFromRequest(req)) return res.status(401).json({ error: 'Sign in to continue.' });
  const token = /^[A-Za-z0-9_-]{16,64}$/.test(String(req.query.t || '')) ? String(req.query.t) : '';
  const wait = pollTokenB.hit(token || ip);
  if (wait) { res.setHeader('Retry-After', wait); return res.status(429).json({ error: 'Too many requests. Wait a moment and try again.' }); }
  const snap = snapshot(req.params.code.toUpperCase(), role, token);
  if (!snap) { probeB.hit(ip); return res.status(404).json({ error: 'Session not found.' }); }
  res.setHeader('Cache-Control', 'no-store');
  res.json(snap);
});
app.post('/api/vote/:code', (req, res) => {
  const body = req.body || {};
  res.setHeader('Cache-Control', 'no-store');
  if (voteTokenB.hit(String(body.t || req.ip))) return res.status(429).json({ ok: false, error: 'Too many attempts. Wait a moment and try again.' });
  res.json(castVote(req.params.code.toUpperCase(), String(body.t || ''), body.optionId, req.ip));
});

setInterval(() => {
  for (const set of rooms.values()) for (const ws of set) {
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; ws.ping();
  }
}, 25000);

// Errors never show stack traces to visitors.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'That upload is too large.' });
  if (err instanceof SyntaxError || (err && err.type === 'entity.parse.failed')) return res.status(400).json({ error: 'Bad request.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong.' });
});

process.on('uncaughtException', e => console.error('uncaughtException', e));
process.on('unhandledRejection', e => console.error('unhandledRejection', e));

server.listen(PORT, BIND_HOST, () => console.log(`Polling app listening on ${BIND_HOST}:${PORT}`));
