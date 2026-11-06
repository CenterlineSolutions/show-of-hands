# show-of-hands

**show-of-hands** is a small self-hosted live polling app for talks and events. The audience scans a QR code and answers on their phones, **one question at a time, only when the host opens voting**. Results build live on the big screen as percentages.

- Host-controlled: phones can't see or answer a question until you open it. The server enforces this.
- Live bars on a projector-friendly screen, or a split layout with the QR code beside the results.
- Easy editing: an admin area for polls, questions, sessions, branding and results export.
- Works without WebSockets: if a network or proxy blocks them, pages fall back to plain HTTP updates on their own.
- One Node.js process, one SQLite file. No external services.

## Pages

| URL | Who | What |
|---|---|---|
| `/?s=CODE` | Audience | Phone voting page (the QR code points here) |
| `/screen?s=CODE` | Projector | QR code before the poll, then live percentage bars |
| `/screen?layout=split&s=CODE` | Projector or slide | QR code on the left, live results on the right |
| `/host?s=CODE` | You (login) | One big button: Go live, Open voting, Close voting, Next question. Jump list for out-of-order slides |
| `/admin` | You (login) | Sessions, QR downloads, questions, branding, colors, results CSV, password |
| `/qrpage?s=CODE` | You (login) | Full-screen QR slide to share or screenshot into a deck |

## Quick start (local)

Requires Node.js 22 or newer (20 works but no longer gets security fixes).

```bash
npm install
ADMIN_USER=admin ADMIN_PASSWORD='use-at-least-12-characters' node seed.js
PORT=3000 node server.js
```

Open <http://localhost:3000/login>, sign in, and create a session in **Admin**. `seed.js` creates the admin user and a sample poll. It only adds what's missing, so it's safe to re-run.

Settings come from environment variables (the app does not read a `.env` file; export them or set them in your process manager).

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `HOST` | `127.0.0.1` | Address to bind. Keep it local and put a web server in front |
| `PUBLIC_URL` | (none) | Your public address, e.g. `https://poll.example.org`. Used in QR codes, and turns on secure cookies and HSTS when it starts with `https://` |
| `DB_PATH` | `./polling.db` | SQLite file. Keep it outside any web-served folder |
| `MAX_VOTES_PER_IP` | `500` | Votes accepted per network address per question. A whole room can share one address, so raise it for very large rooms |
| `ADMIN_USER`, `ADMIN_PASSWORD` | `admin`, (none) | Used only by `seed.js` to create the first admin. Password must be 12+ characters |

## Run an event

1. **Days before:** in **Admin**, create a session. It gets a permanent 5-character code and a QR code you can download (PNG or SVG) for the speaker's deck. People who scan early see "starting soon" and move on by themselves when you start.
2. **At the event:** open `/host?s=CODE` on your laptop and `/screen?s=CODE` (or the split screen) on the projector or shared screen. Press **Go live**.
3. When the speaker reaches a question, press **Open voting**. Press **Close voting and show results** when ready, then **Next question**.
4. Afterward, download **Results CSV** from Admin.

Handy options:
- **Show question number:** each session can hide "Question 3 of 7" from the audience. Change it in Admin or live on the Host page.
- **Branding:** set an organization name and logo in **Admin → Branding**. The logo shows on every page and sits on a white tile on the big screen.
- **Colors:** pick a main, dark and light color in **Admin → Branding**. The app derives the other shades and shows readability (contrast) checks, so you can aim for WCAG AA.

## Deploy

You need Node.js, a way to keep it running, and a web server that provides HTTPS and forwards traffic to the app.

1. Upload the app, then `npm install --omit=dev`.
2. Run `node seed.js` once with `DB_PATH` set to a folder outside your website's public folder.
3. Keep it running with a process manager such as [pm2](https://pm2.keymetrics.io/). See `ecosystem.config.js` for an example (it starts the app as `show-of-hands`). Set `PUBLIC_URL` and `DB_PATH` there.
4. Put a web server in front, with HTTPS. The app only listens on `127.0.0.1`.

**Nginx**

```nginx
location / {
  proxy_pass http://127.0.0.1:3000;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 3600s;
}
```

**Apache** (needs `mod_proxy`, `mod_proxy_http`, `mod_proxy_wstunnel`, `mod_rewrite`; works in `.htaccess` on many hosts)

```apache
DirectoryIndex disabled
RewriteEngine On
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule ^(.*)$ ws://127.0.0.1:3000/$1 [P,L]
RewriteRule ^(.*)$ http://127.0.0.1:3000/$1 [P,L]
```

The proxy must pass the visitor's real address in `X-Forwarded-For`. The app uses it for rate limits and the per-network vote cap. After deploying, open **Admin → Account → Connection check** to confirm it sees real addresses.

**No root access?** Install Node with [nvm](https://github.com/nvm-sh/nvm) in your home folder, and use cron instead of `pm2 startup`: add `@reboot` with a command that loads nvm and runs `pm2 resurrect`.

**Updating:** upload the new files over the old ones (leave your `ecosystem.config.js` and database alone) and run `pm2 restart`. Sign-ins and votes survive restarts. Take a copy of the app folder first so you can roll back.

## Security

Built in:
- Passwords are hashed (scrypt). Sign-ins are stored hashed in the database, in `HttpOnly`, `SameSite=Lax` cookies (`Secure` when `PUBLIC_URL` is https). Changing your password signs out other browsers.
- Rate limits on sign-in, session-code guessing, voting and connections. A script that floods the socket is disconnected.
- Requests that change anything are refused when they come from another website (origin check), including WebSocket connections.
- Content security policy, anti-framing (except the big screen, which can be embedded), `nosniff`, referrer and permissions policies, and HSTS over HTTPS.
- All SQL uses placeholders and pages never build HTML from user text. Uploaded SVG logos are served sandboxed.
- The app binds to `127.0.0.1` only. Error responses never include stack traces.

Your part:
- Use a long admin password (a few random words works well), and keep Node.js on a supported version.
- Serve it over HTTPS only.
- When you're not running an event, stop the app (`pm2 stop`) and start it before the next one.
- Back up the SQLite file if the results matter.

Limits to be honest about: voting is anonymous, with one vote per device (a token in the browser). Someone who clears site data, or uses several networks, can vote more than once. The per-network cap makes ballot stuffing harder, not impossible, so don't rely on this for high-stakes votes.

To report a vulnerability, open a private security advisory on the repository rather than a public issue.

## Tests

With the server running:

```bash
ADMIN_PASSWORD='...' node loadtest.js 300     # voting rules, polling fallback, 300 simultaneous voters
```

The security checks need a server started with a small vote cap and its own throwaway database:

```bash
DB_PATH=/tmp/test.db ADMIN_PASSWORD='a-12-character-password' node seed.js
DB_PATH=/tmp/test.db MAX_VOTES_PER_IP=5 PORT=3100 node server.js &
BASE=http://localhost:3100 ADMIN_PASSWORD='a-12-character-password' node securitytest.js
```

Both scripts create and delete their own test session.

## Project layout

```
server.js        web server, WebSockets, voting rules, admin API, security
db.js            SQLite schema, queries, sample poll
seed.js          creates the first admin and sample poll
public/          pages (voter, screen, host, admin, login, qrpage), style.css, common.js, color.js
loadtest.js      end-to-end and load test
securitytest.js  security checks
```

## Notes

- Fonts load from Google Fonts. Without internet they fall back to system fonts.
- Built with Express, `ws`, `better-sqlite3` and `qrcode`. Front end is plain HTML and JavaScript with no build step.

## License

[MIT](LICENSE) © 2026 Centerline Solutions
