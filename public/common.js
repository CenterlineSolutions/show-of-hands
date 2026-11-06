/* Shared helpers: DOM, percentages, bars, and a reconnecting WebSocket. */
const $ = (sel, root = document) => root.querySelector(sel);
function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(k));
  return e;
}

// Largest-remainder rounding so the displayed percentages always add to 100.
function percentages(counts, optionIds) {
  const total = optionIds.reduce((a, id) => a + (counts[id] || 0), 0);
  const out = {};
  if (!total) { optionIds.forEach(id => (out[id] = 0)); return { pct: out, total: 0 }; }
  const raw = optionIds.map(id => ({ id, exact: (counts[id] || 0) * 100 / total }));
  raw.forEach(r => (out[r.id] = Math.floor(r.exact)));
  let left = 100 - Object.values(out).reduce((a, b) => a + b, 0);
  raw.sort((a, b) => (b.exact - Math.floor(b.exact)) - (a.exact - Math.floor(a.exact)));
  for (let i = 0; left > 0; i = (i + 1) % raw.length, left--) out[raw[i].id]++;
  return { pct: out, total };
}

// Build once per question, then update in place so the bars animate.
function createBars(container, options, { showCounts = false } = {}) {
  container.replaceChildren();
  const rows = new Map();
  for (const o of options) {
    const label = h('span', { class: 'bar-label' }, o.label);
    const pct = h('span', { class: 'bar-pct' }, '0%');
    const count = showCounts ? h('span', { class: 'bar-count' }, '0') : null;
    const fill = h('div', { class: 'bar-fill' });
    const row = h('div', { class: 'bar-row' },
      h('div', { class: 'bar-head' }, label, h('span', {}, pct, count)),
      h('div', { class: 'bar-track', role: 'presentation' }, fill));
    container.append(row);
    rows.set(o.id, { row, pct, count, fill });
  }
  return {
    update(counts, mineId) {
      const ids = options.map(o => o.id);
      const { pct, total } = percentages(counts || {}, ids);
      const top = Math.max(...ids.map(id => (counts && counts[id]) || 0));
      for (const id of ids) {
        const r = rows.get(id);
        r.pct.textContent = pct[id] + '%';
        if (r.count) r.count.textContent = (counts && counts[id]) || 0;
        r.fill.style.width = pct[id] + '%';
        r.row.classList.toggle('lead', top > 0 && ((counts && counts[id]) || 0) === top);
        r.row.classList.toggle('mine', mineId === id);
      }
      return total;
    },
  };
}

// Live connection. Uses a WebSocket and reconnects on its own. If WebSockets never connect
// (blocked by a proxy or the host), it switches to polling the server over plain HTTP.
// Add ?poll=1 to any page URL to force polling. onMessage gets parsed JSON.
function connect(params, onMessage, onStatus = () => {}) {
  let ws, wait = 500, closed = false, everOpened = false, failures = 0, polling = false, timer = null, lastJson = '';
  const forcePoll = new URLSearchParams(location.search).get('poll') === '1';

  const pollOnce = async () => {
    try {
      const qs = new URLSearchParams({ role: params.role, t: params.t || '' });
      const r = await fetch(`/api/poll/${encodeURIComponent(params.s)}?${qs}`, { credentials: 'same-origin', cache: 'no-store' });
      if (!r.ok) throw new Error('poll');
      const text = await r.text();
      onStatus(true);
      if (text !== lastJson) { lastJson = text; onMessage(JSON.parse(text)); } // skip identical snapshots so the page doesn't redraw
    } catch { onStatus(false); }
  };
  const startPolling = () => {
    if (polling || closed) return;
    polling = true;
    pollOnce();
    timer = setInterval(pollOnce, params.role === 'voter' ? 1500 : 1000);
  };

  const open = () => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws?${new URLSearchParams(params)}`);
    ws.onopen = () => { everOpened = true; wait = 500; onStatus(true); };
    ws.onmessage = e => { try { onMessage(JSON.parse(e.data)); } catch {} };
    ws.onclose = () => {
      onStatus(false);
      if (closed || polling) return;
      if (!everOpened && ++failures >= 2) return startPolling();
      setTimeout(open, wait = Math.min(wait * 1.6, 5000));
    };
  };
  if (forcePoll) startPolling(); else open();

  return {
    send: async o => {
      if (!polling) return ws && ws.readyState === 1 && ws.send(JSON.stringify(o));
      if (o.type !== 'vote') return;
      try {
        const r = await fetch(`/api/vote/${encodeURIComponent(params.s)}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ t: params.t, optionId: o.optionId }) });
        onMessage({ type: 'ack', ...(await r.json()) });
      } catch { onMessage({ type: 'ack', ok: false, error: 'No connection. Check your signal and try again.' }); }
      lastJson = ''; pollOnce();
    },
    close: () => { closed = true; clearInterval(timer); if (ws) ws.close(); },
  };
}

async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  if (r.status === 401 && !path.startsWith('/api/login')) { location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); throw new Error('auth'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Something went wrong.');
  return data;
}

// Fills every .brand element with the organization name and logo from Admin > Branding.
async function applyBrand() {
  try {
    const b = await (await fetch('/api/brand', { cache: 'no-store' })).json();
    document.querySelectorAll('.brand').forEach(el => {
      el.replaceChildren();
      el.classList.toggle('has-logo', !!b.logo);
      if (b.logo) el.append(h('img', { src: '/brand/logo?v=' + b.v, alt: '' }));
      const suffix = el.dataset.suffix || '';
      const text = b.logo && !b.showName ? suffix.replace(/^\s*\u00b7\s*/, '') : b.name + suffix;
      if (text) el.append(document.createTextNode(text));
    });
  } catch {}
}
applyBrand();
