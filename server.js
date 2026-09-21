const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { db, dataDir, uploadDir } = require('./db');
const SqliteStore = require('./lib/sessionStore');
const { attachContext } = require('./lib/middleware');

const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

/** Use SESSION_SECRET if set; otherwise create one once and keep it in data/. */
function loadSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const file = path.join(dataDir, 'session-secret');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(file, secret, { mode: 0o600 });
  return secret;
}

const app = express();
app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
if (isProd) app.set('trust proxy', 1); // required for secure cookies behind a proxy/HTTPS host

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        'default-src': ["'self'"],
        'style-src': ["'self'", 'https://fonts.googleapis.com'],
        'font-src': ['https://fonts.gstatic.com'],
        'img-src': ["'self'", 'data:'],
        'form-action': ["'self'"],
        'upgrade-insecure-requests': isProd ? [] : null,
      },
    },
  })
);

app.use(express.static(path.join(__dirname, 'public'), { maxAge: isProd ? '7d' : 0 }));
app.use(
  '/uploads',
  express.static(uploadDir, { maxAge: '7d', immutable: true, index: false, dotfiles: 'deny' })
);
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

app.use(
  session({
    name: 'sid',
    secret: loadSessionSecret(),
    store: new SqliteStore(db),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd,
      maxAge: 14 * 24 * 60 * 60 * 1000,
    },
  })
);
app.use(attachContext);

// Template helpers
app.locals.initials = (name) =>
  String(name)
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => Array.from(part)[0].toUpperCase())
    .join('') || '?';
app.locals.tone = (username) => {
  let hash = 0;
  for (const ch of String(username)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return hash % 5;
};
app.locals.formatDate = (ms) =>
  new Date(ms).toLocaleDateString('en-US', { month: 'long', year: 'numeric' });

app.use(require('./routes/auth'));
app.use(require('./routes/account'));
app.use(require('./routes/profiles'));

app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Not found',
    heading: 'Page not found',
    message: 'Check the address, or head back to the home page.',
  });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).render('error', {
    title: 'Something broke',
    heading: 'Something went wrong',
    message: 'Try again in a moment. If it keeps happening, check the server log.',
  });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Handle is running at http://localhost:${PORT}`));
}

module.exports = app;
