# Handle: Personal Web Profile System

A multi-user profile site. People sign up, pick a username, and get a public page at `/u/<username>` with a photo, bio, and links. Built with **Node.js, Express, EJS, and SQLite**. No separate database server to install.

## Run it

```bash
npm install
npm start          # http://localhost:3000
```

Optional:

```bash
npm run seed       # add demo profiles (password for all: demo-password-1)
npm test           # 15 end-to-end checks against a throwaway database
npm run dev        # restart on file changes
```

Needs Node 22 or newer (required by the SQLite driver).

## Features

- Sign up, log in, log out (username or email works for login)
- Public profile at `/u/<username>`: name, headline, bio, location, website, GitHub, LinkedIn, photo
- Edit profile with photo upload (PNG, JPG, WebP, up to 2 MB)
- Public/private switch. Private profiles are hidden from the home page and return 404 to everyone but the owner
- Home page directory with search and paging
- Account page: change email, change password (signs out other devices), delete account

## Project layout

```
server.js            App setup, sessions, security headers, error pages
db.js                SQLite connection and schema (created on first run)
routes/
  auth.js            /signup  /login  /logout
  profiles.js        /  (directory)   /u/:username   /profile/edit
  account.js         /account  and its email / password / delete actions
lib/
  middleware.js      CSRF check, auth guards, flash messages, login helper
  validate.js        Input validation for every field
  upload.js          Avatar upload (type, size, and file-header checks)
  sessionStore.js    Sessions stored in SQLite, so logins survive restarts
views/               EJS templates (partials/ holds shared pieces)
public/css/          Stylesheet
data/                Created at runtime: app.db, uploads/, session-secret
test/                End-to-end tests
scripts/seed.js      Demo data
```

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Port to listen on |
| `NODE_ENV` | unset | Set to `production` for secure cookies (needs HTTPS) and proxy trust |
| `SESSION_SECRET` | auto-generated in `data/session-secret` | Signs the session cookie |
| `DATA_DIR` | `./data` | Where the database and uploads live |

## Database

One `users` table holds accounts and profile fields; a `sessions` table backs login sessions. Usernames and emails are unique and case-insensitive. Open `data/app.db` with any SQLite viewer to inspect it.

## Security notes

- Passwords are hashed with bcrypt (cost 12). Login takes similar time whether or not the account exists.
- Every form carries a CSRF token. The session cookie is `HttpOnly` and `SameSite=Lax`, and a fresh session is issued on login.
- Login, signup, and password-check routes are rate limited per IP.
- All output is escaped by EJS. Website links are limited to `http(s)`. A Content Security Policy is set through Helmet.
- Uploads get random filenames, are size limited, and the file header is checked, not just the declared type.
- Before going live: serve over HTTPS, set `NODE_ENV=production`, and back up `data/`.

## Ideas to extend

Email verification and password reset (needs an email service), image resizing with `sharp`, more link types, profile view counts, an admin page, or moving from SQLite to PostgreSQL.
