// End-to-end check + load test. Usage: node loadtest.js [voters] (server must be running).
// Env: BASE (default http://localhost:3000), ADMIN_USER, ADMIN_PASSWORD.
const WebSocket = require('ws');
const BASE = process.env.BASE || 'http://localhost:3000';
const WS = BASE.replace(/^http/, 'ws');
const VOTERS = parseInt(process.argv[2] || '300', 10);
const user = process.env.ADMIN_USER || 'admin', pass = process.env.ADMIN_PASSWORD;

let cookie = '';
async function api(path, method = 'GET', body) {
  const r = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined });
  const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${path}: ${j.error || r.status}`);
  return j;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
const check = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`); if (!ok) failures++; };

function client(role, code, token = '') {
  return new Promise(resolve => {
    const ws = new WebSocket(`${WS}/ws?role=${role}&s=${code}&t=${token}`, { headers: { cookie } });
    const c = { ws, last: null, acks: [], tally: null };
    ws.on('message', d => { const m = JSON.parse(d); if (m.type === 'state') c.last = m; if (m.type === 'ack') c.acks.push(m); if (m.type === 'tally') c.tally = m; });
    ws.on('open', () => setTimeout(() => resolve(c), 100));
    ws.on('error', () => resolve(c));
  });
}

(async () => {
  await api('/api/login', 'POST', { username: user, password: pass });
  const polls = await api('/api/admin/polls');
  const s = await api('/api/admin/sessions', 'POST', { name: 'Load test', pollId: polls[0].id });
  const host = (a, b) => api(`/api/host/${s.code}/${a}`, 'POST', b);

  const screen = await client('screen', s.code);
  const v0 = await client('voter', s.code, 'a'.repeat(20));
  check('voter in scheduled session sees lobby', v0.last.session.state === 'scheduled' && !v0.last.question);

  await host('golive'); await sleep(150);
  check('after go live, voter sees no question while waiting', v0.last.session.phase === 'waiting' && !v0.last.question);
  check('screen sees the question while waiting', !!screen.last.question);

  v0.ws.send(JSON.stringify({ type: 'vote', optionId: screen.last.question.options[0].id })); await sleep(150);
  check('vote before voting opens is rejected', v0.acks.at(-1) && v0.acks.at(-1).ok === false);

  await host('open'); await sleep(150);
  check('voter sees question once open', !!v0.last.question);
  const opts = screen.last.question.options.map(o => o.id);
  v0.ws.send(JSON.stringify({ type: 'vote', optionId: opts[0] })); await sleep(150);
  check('first vote accepted', v0.acks.at(-1).ok === true);
  v0.ws.send(JSON.stringify({ type: 'vote', optionId: opts[1] })); await sleep(150);
  check('second vote from same device rejected', v0.acks.at(-1).ok === false);
  v0.ws.send(JSON.stringify({ type: 'vote', optionId: 999999 })); await sleep(100);
  check('vote for option outside question rejected', v0.acks.at(-1).ok === false);

  const voters = [];
  for (let i = 0; i < VOTERS; i++) voters.push(await client('voter', s.code, `load${String(i).padStart(4, '0')}${'x'.repeat(12)}`));
  const t0 = Date.now();
  voters.forEach((v, i) => v.ws.send(JSON.stringify({ type: 'vote', optionId: opts[i % opts.length] })));
  await sleep(1200);
  const accepted = voters.filter(v => v.acks.some(a => a.ok)).length;
  check(`${VOTERS} concurrent voters all accepted (${accepted})`, accepted === VOTERS);
  const total = Object.values(screen.tally.counts).reduce((a, b) => a + b, 0);
  check(`screen tally matches (${total} = ${VOTERS + 1}) in ${Date.now() - t0}ms`, total === VOTERS + 1);

  await host('close'); await sleep(200);
  check('voters receive results after close', !!v0.last.tally);
  voters[0].ws.send(JSON.stringify({ type: 'vote', optionId: opts[0] })); await sleep(100);
  check('late vote after close rejected', voters[0].acks.at(-1).ok === false);

  const re = await client('voter', s.code, 'a'.repeat(20));
  check('reconnecting voter gets their earlier answer back', re.last.mine === opts[0]);

  await host('next'); await sleep(150);
  check('next question moves to waiting', v0.last.session.phase === 'waiting' && v0.last.index === 2);

  // ---- HTTP polling fallback (used when WebSockets are blocked) ----
  await host('open'); await sleep(100);
  const pv = await (await fetch(`${BASE}/api/poll/${s.code}?role=voter&t=${'p'.repeat(20)}`)).json();
  check('polling voter sees the open question', !!pv.question);
  const post = (t, optionId) => fetch(`${BASE}/api/vote/${s.code}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ t, optionId }) }).then(r => r.json());
  const rs = await Promise.all(Array.from({ length: VOTERS }, (_, i) => post(`poll${String(i).padStart(4, '0')}${'y'.repeat(12)}`, pv.question.options[i % pv.question.options.length].id)));
  check(`${VOTERS} polling voters accepted`, rs.every(r => r.ok));
  check('duplicate polling vote rejected', (await post(`poll0000${'y'.repeat(12)}`, pv.question.options[0].id)).ok === false);
  const sc = await (await fetch(`${BASE}/api/poll/${s.code}?role=screen`)).json();
  check(`polled screen tally matches (${sc.tally.total})`, sc.tally.total === VOTERS);
  const pv2 = await (await fetch(`${BASE}/api/poll/${s.code}?role=voter&t=poll0000${'y'.repeat(12)}`)).json();
  check('polling voter gets own answer back', pv2.mine === pv.question.options[0].id);
  check('voter poll hides tally while open', !pv2.tally);
  check('host poll without login is denied (401)', (await fetch(`${BASE}/api/poll/${s.code}?role=host`)).status === 401);
  await host('close'); await sleep(100);

  const noAuth = await fetch(`${BASE}/api/host/${s.code}/open`, { method: 'POST' });
  check('host action without login is denied (401)', noAuth.status === 401);
  const bad = await new Promise(res => { const w = new WebSocket(`${WS}/ws?role=host&s=${s.code}`); w.on('error', () => res(true)); w.on('open', () => res(false)); });
  check('host websocket without login is refused', bad);

  await api(`/api/admin/sessions/${s.id}`, 'DELETE');
  console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
