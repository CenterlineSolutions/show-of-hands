const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'polling.db'));
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS polls (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY,
  poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  text TEXT NOT NULL,
  allow_multiple INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS options (
  id INTEGER PRIMARY KEY,
  question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  event_date TEXT,
  state TEXT NOT NULL DEFAULT 'scheduled',   -- scheduled | live | ended
  current_question_id INTEGER,
  phase TEXT NOT NULL DEFAULT 'waiting'      -- waiting | open | closed | done
);
CREATE TABLE IF NOT EXISTS votes (
  id INTEGER PRIMARY KEY,
  session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  option_id INTEGER NOT NULL REFERENCES options(id) ON DELETE CASCADE,
  voter_token TEXT NOT NULL,
  UNIQUE (session_id, question_id, voter_token)
);
CREATE INDEX IF NOT EXISTS votes_q ON votes (session_id, question_id);
`);

// ---------- settings (branding) ----------
const getSetting = (k, fallback = '') => { const r = db.prepare('SELECT value FROM settings WHERE key = ?').get(k); return r ? r.value : fallback; };
const setSetting = (k, v) => db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
const delSetting = k => db.prepare('DELETE FROM settings WHERE key = ?').run(k);

// Add columns introduced after first release (safe to run on an existing database).
if (!db.prepare('PRAGMA table_info(sessions)').all().some(c => c.name === 'show_progress')) {
  db.exec('ALTER TABLE sessions ADD COLUMN show_progress INTEGER NOT NULL DEFAULT 1');
}

// ---------- passwords (scrypt, no native deps) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64);
  return `${salt.toString('hex')}:${key.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [saltHex, keyHex] = stored.split(':');
  const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 64);
  return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));
}

// ---------- session codes ----------
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no look-alikes
function newCode() {
  for (;;) {
    let c = '';
    for (let i = 0; i < 5; i++) c += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
    if (!db.prepare('SELECT 1 FROM sessions WHERE code = ?').get(c)) return c;
  }
}

// ---------- reads ----------
const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  sessionByCode: db.prepare('SELECT * FROM sessions WHERE code = ?'),
  question: db.prepare('SELECT * FROM questions WHERE id = ?'),
  questionsOfPoll: db.prepare('SELECT * FROM questions WHERE poll_id = ? ORDER BY position, id'),
  optionsOfQuestion: db.prepare('SELECT id, position, label FROM options WHERE question_id = ? ORDER BY position, id'),
  counts: db.prepare('SELECT option_id, COUNT(*) AS n FROM votes WHERE session_id = ? AND question_id = ? GROUP BY option_id'),
  myVote: db.prepare('SELECT option_id FROM votes WHERE session_id = ? AND question_id = ? AND voter_token = ?'),
  insertVote: db.prepare('INSERT OR IGNORE INTO votes (session_id, question_id, option_id, voter_token) VALUES (?, ?, ?, ?)'),
};

function questionWithOptions(id) {
  const qu = q.question.get(id);
  if (!qu) return null;
  return { id: qu.id, text: qu.text, allowMultiple: !!qu.allow_multiple, options: q.optionsOfQuestion.all(id) };
}

function tally(sessionId, questionId) {
  const opts = q.optionsOfQuestion.all(questionId);
  const rows = q.counts.all(sessionId, questionId);
  const map = new Map(rows.map(r => [r.option_id, r.n]));
  const counts = {};
  let total = 0;
  for (const o of opts) {
    const n = map.get(o.id) || 0;
    counts[o.id] = n;
    total += n;
  }
  return { counts, total };
}

// Votes for the session's questions in order, for admin results and CSV.
function resultsForSession(sessionId) {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
  return q.questionsOfPoll.all(s.poll_id).map(qu => {
    const opts = q.optionsOfQuestion.all(qu.id);
    const t = tally(sessionId, qu.id);
    return {
      id: qu.id, text: qu.text, total: t.total,
      options: opts.map(o => ({ id: o.id, label: o.label, count: t.counts[o.id] })),
    };
  });
}

// ---------- seed ----------
const SEED_POLL = {
  title: 'Sample poll: getting to know the room',
  questions: [
    ['Have you used a live polling tool before?', ['Yes, often', 'Once or twice', 'Never']],
    ['How do you like to learn something new?', ['Reading about it', 'Watching someone do it', 'Trying it hands-on', 'Talking it through with others']],
    ['How is your day going so far?', ['Great', 'Fine', 'Needs more coffee']],
  ],
};

function seedPoll() {
  const tx = db.transaction(() => {
    const pollId = db.prepare('INSERT INTO polls (title) VALUES (?)').run(SEED_POLL.title).lastInsertRowid;
    SEED_POLL.questions.forEach(([text, opts], i) => {
      const qid = db.prepare('INSERT INTO questions (poll_id, position, text) VALUES (?, ?, ?)').run(pollId, i + 1, text).lastInsertRowid;
      opts.forEach((label, j) => db.prepare('INSERT INTO options (question_id, position, label) VALUES (?, ?, ?)').run(qid, j + 1, label));
    });
    return pollId;
  });
  return tx();
}

module.exports = { db, q, getSetting, setSetting, delSetting, hashPassword, verifyPassword, newCode, questionWithOptions, tally, resultsForSession, seedPoll };
