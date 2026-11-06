// Security checks against a running server. Usage: ADMIN_PASSWORD=... node securitytest.js
// Start the server with MAX_VOTES_PER_IP=5 first (the per-address vote cap check needs a small cap).
// Fake visitor addresses are made with X-Forwarded-For, the same header the real web server adds.
const WebSocket = require('ws');
const BASE = process.env.BASE || 'http://localhost:3000';
const WS = BASE.replace(/^http/, 'ws');
const user = process.env.ADMIN_USER || 'admin', pass = process.env.ADMIN_PASSWORD;
let failures = 0;
const check = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); if (!ok) failures++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function req(path, { method = 'GET', body, headers = {}, cookie = '', ip = '203.0.113.1', raw } = {}) {
  const h = { 'X-Forwarded-For': ip, ...headers };
  if (cookie) h.cookie = cookie;
  if (body !== undefined && !raw) h['Content-Type'] = 'application/json';
  const r = await fetch(BASE + path, { method, headers: h, body: raw ? body : body !== undefined ? JSON.stringify(body) : undefined, redirect: 'manual' });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, headers: r.headers, text, json };
}
async function login(ip = '203.0.113.2', password = pass) {
  const r = await req('/api/login', { method: 'POST', body: { username: user, password }, ip });
  const sc = r.headers.get('set-cookie');
  return { status: r.status, cookie: sc ? sc.split(';')[0] : '' };
}

(async () => {
  const a = await login();
  check('admin can sign in', a.status === 200 && a.cookie);

  // ---- headers
  const home = await req('/'), screen = await req('/screen');
  check('pages send a content security policy', /default-src 'self'/.test(home.headers.get('content-security-policy') || ''));
  check('normal pages cannot be framed by other sites', home.headers.get('x-frame-options') === 'DENY' && /frame-ancestors 'none'/.test(home.headers.get('content-security-policy')));
  check('big screen can be embedded', !screen.headers.get('x-frame-options') && /frame-ancestors \*/.test(screen.headers.get('content-security-policy')));
  check('nosniff and referrer policy set', home.headers.get('x-content-type-options') === 'nosniff' && !!home.headers.get('referrer-policy'));
  check('server does not announce Express', !home.headers.get('x-powered-by'));

  // ---- files that must never be served
  for (const p of ['/server.js', '/.env', '/polling.db', '/package.json', '/%2e%2e/server.js', '/..%2fserver.js', '/public/../server.js']) {
    const r = await req(p);
    check(`not served: ${p}`, r.status === 404 || r.status === 400 || (r.status === 200 && !/require\('express'\)|"dependencies"/.test(r.text)), `status ${r.status}`);
  }

  // ---- protected pages and API
  check('/admin redirects to login without sign-in', (await req('/admin')).status === 302);
  check('/host redirects to login without sign-in', (await req('/host')).status === 302);
  check('admin API refuses without sign-in', (await req('/api/admin/sessions')).status === 401);
  check('debug address check needs sign-in', (await req('/api/admin/debug/ip')).status === 401);
  const dbg = await req('/api/admin/debug/ip', { cookie: a.cookie, ip: '198.51.100.9' });
  check('server sees the address from the proxy header', dbg.json && dbg.json.ip === '198.51.100.9' && dbg.json.proxyHeaderSeen === true);

  // ---- cross-site requests
  const evil = await req('/api/admin/sessions', { method: 'POST', cookie: a.cookie, headers: { Origin: 'https://evil.example' }, body: { name: 'x', pollId: 1 } });
  check('state change from another website is blocked', evil.status === 403, `status ${evil.status}`);
  const evilLogin = await req('/api/login', { method: 'POST', headers: { Origin: 'https://evil.example' }, body: { username: user, password: pass }, ip: '203.0.113.30' });
  check('sign-in from another website is blocked', evilLogin.status === 403, `status ${evilLogin.status}`);
  const same = await req('/api/admin/sessions', { cookie: a.cookie, headers: { Origin: BASE } });
  check('same-site requests still work', same.status === 200);
  const evilWs = await new Promise(res => { const w = new WebSocket(`${WS}/ws?role=screen&s=ZZZZZ`, { headers: { Origin: 'https://evil.example' } }); w.on('error', () => res(true)); w.on('open', () => res(false)); });
  check('websocket from another website is refused', evilWs);

  // ---- bad input
  const bad = await req('/api/login', { method: 'POST', raw: true, body: '{"username": ', headers: { 'Content-Type': 'application/json' }, ip: '203.0.113.31' });
  check('malformed JSON gets a short JSON error, no stack trace', bad.status === 400 && bad.json && !/at |node_modules/.test(bad.text), bad.text.slice(0, 80));
  const big = await req('/api/login', { method: 'POST', body: { username: 'x', password: 'y'.repeat(100000) }, ip: '203.0.113.32' });
  check('oversized request body is rejected', big.status === 413, `status ${big.status}`);
  const longpw = await req('/api/login', { method: 'POST', body: { username: user, password: 'y'.repeat(5000) }, ip: '203.0.113.33' });
  check('very long password is refused quickly', longpw.status === 401);
  const badlogo = await req('/api/admin/brand/logo', { method: 'POST', cookie: a.cookie, raw: true, body: '<script>alert(1)</script>', headers: { 'Content-Type': 'text/html' } });
  check('non-image upload is refused', badlogo.status === 400);

  // ---- login throttling (uses its own fake address so other tests are unaffected)
  let last;
  for (let i = 0; i < 8; i++) last = await login('203.0.113.50', 'wrong-password-' + i);
  check('wrong passwords get 401', last.status === 401);
  const locked = await login('203.0.113.50', pass);
  check('after 8 failures that address is blocked, even with the right password', locked.status === 429, `status ${locked.status}`);
  const other = await login('203.0.113.51', pass);
  check('a different address is not affected', other.status === 200);

  // ---- session code guessing
  let probeStatus = 0;
  for (let i = 0; i < 45; i++) probeStatus = (await req('/api/join/NOPE' + (i % 10), { ip: '203.0.113.60' })).status;
  check('guessing session codes gets throttled', probeStatus === 429, `status ${probeStatus}`);
  const realIpUnaffected = await req('/api/join/NOPE1', { ip: '203.0.113.61' });
  check('other addresses can still look up codes', realIpUnaffected.status === 404);

  // ---- vote stuffing
  const polls = (await req('/api/admin/polls', { cookie: a.cookie })).json;
  const s = (await req('/api/admin/sessions', { method: 'POST', cookie: a.cookie, body: { name: 'Security test', pollId: polls[0].id } })).json;
  const host = (act, body) => req(`/api/host/${s.code}/${act}`, { method: 'POST', cookie: a.cookie, body: body || {} });
  await host('golive'); await host('open');
  const state = (await req(`/api/poll/${s.code}?role=voter&t=${'q'.repeat(20)}`, { ip: '203.0.113.70' })).json;
  const opt = state.question.options[0].id;
  const vote = (tok, ip) => req(`/api/vote/${s.code}`, { method: 'POST', body: { t: tok, optionId: opt }, ip });
  const results = [];
  for (let i = 0; i < 8; i++) results.push((await vote(`stuff${String(i).padStart(2, '0')}${'a'.repeat(14)}`, '203.0.113.80')).json.ok);
  const accepted = results.filter(Boolean).length;
  check(`one address is capped (${accepted} of 8 accepted, cap is 5)`, accepted === 5, JSON.stringify(results));
  check('a different address can still vote', (await vote(`other00${'b'.repeat(14)}`, '203.0.113.81')).json.ok === true);
  const again = await vote(`stuff00${'a'.repeat(14)}`, '203.0.113.80');
  check('a voter already counted is told "already voted", not blocked', /already voted/.test(again.json.error || ''), again.text);
  let tokStatus = 0;
  for (let i = 0; i < 35; i++) tokStatus = (await vote(`hammer0${'c'.repeat(14)}`, '203.0.113.82')).status;
  check('one device hammering the vote endpoint gets throttled', tokStatus === 429, `status ${tokStatus}`);

  // ---- websocket flooding
  const floodClosed = await new Promise(res => {
    const w = new WebSocket(`${WS}/ws?role=voter&s=${s.code}&t=${'f'.repeat(20)}`, { headers: { 'X-Forwarded-For': '203.0.113.90' } });
    w.on('open', () => { for (let i = 0; i < 60; i++) w.send(JSON.stringify({ type: 'vote', optionId: opt })); });
    w.on('close', code => res(code)); w.on('error', () => res(-1));
    setTimeout(() => res(0), 3000);
  });
  check('a socket sending a flood of messages is disconnected', floodClosed === 1008, `close code ${floodClosed}`);

  // ---- password rules and session revocation
  const c1 = await login('203.0.113.100'), c2 = await login('203.0.113.101');
  const short = await req('/api/password', { method: 'POST', cookie: c1.cookie, body: { current: pass, next: 'short123' } });
  check('short new password is refused', short.status === 400);
  const newPass = pass + '-changed';
  const chg = await req('/api/password', { method: 'POST', cookie: c1.cookie, body: { current: pass, next: newPass } });
  check('long new password is accepted', chg.status === 200);
  check('the browser that changed it stays signed in', (await req('/api/me', { cookie: c1.cookie })).status === 200);
  check('every other signed-in browser is signed out', (await req('/api/me', { cookie: c2.cookie })).status === 401);
  const back = await req('/api/password', { method: 'POST', cookie: c1.cookie, body: { current: newPass, next: pass } });
  check('password restored for later tests', back.status === 200);

  await req('/api/admin/sessions/' + s.id, { method: 'DELETE', cookie: (await login('203.0.113.110')).cookie });
  console.log(failures ? `\n${failures} security check(s) failed` : '\nAll security checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
