// Creates the first admin user and a small sample poll.
// Safe to re-run: it only adds what is missing.
const { db, q, hashPassword, seedPoll } = require('./db');

const user = process.env.ADMIN_USER || 'admin';
const pass = process.env.ADMIN_PASSWORD;

if (!q.userByName.get(user)) {
  if (!pass || pass.length < 12) {
    console.error('Set ADMIN_PASSWORD (12+ characters) to create the first admin user.');
    process.exit(1);
  }
  db.prepare('INSERT INTO users (username, pass_hash) VALUES (?, ?)').run(user, hashPassword(pass));
  console.log(`Created admin user "${user}".`);
} else {
  console.log(`Admin user "${user}" already exists.`);
}

if (db.prepare('SELECT COUNT(*) AS n FROM polls').get().n === 0) {
  seedPoll();
  console.log('Loaded the sample poll.');
} else {
  console.log('Polls already present, skipping question seed.');
}
