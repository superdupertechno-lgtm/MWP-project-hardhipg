const crypto = require('crypto');
const fs = require('fs');
const { db } = require('../db');

const findSessionUser = db.prepare(
  'SELECT id, username, display_name, avatar FROM users WHERE id = ?'
);

/** Loads the signed-in user (if any) and exposes template helpers. */
function attachContext(req, res, next) {
  let user = null;
  if (req.session.userId) {
    user = findSessionUser.get(req.session.userId) || null;
    if (!user) delete req.session.userId; // account was deleted
  }
  req.user = user;
  res.locals.currentUser = user;

  res.locals.flash = null;
  if (req.session.flash) {
    res.locals.flash = req.session.flash;
    delete req.session.flash;
  }
  req.flash = (type, message) => {
    req.session.flash = { type, message };
  };

  // Lazy token: anonymous visitors only get a session once a form is rendered.
  res.locals.csrf = () => {
    if (!req.session) return ''; // session already destroyed (e.g. after account deletion)
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
    return req.session.csrf;
  };
  next();
}

function verifyCsrf(req, res, next) {
  const sent = req.body && typeof req.body._csrf === 'string' ? req.body._csrf : '';
  const expected = req.session.csrf || '';
  const ok =
    sent.length > 0 &&
    sent.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected));
  if (ok) return next();

  // An upload may already be on disk by now (multer runs first); don't keep it.
  if (req.file) fs.unlink(req.file.path, () => {});
  res.status(403).render('error', {
    title: 'Request blocked',
    heading: 'That form expired',
    message: 'Go back, refresh the page, and try again.',
  });
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  if (req.method === 'GET') req.session.returnTo = req.originalUrl;
  req.flash('info', 'Log in to continue.');
  res.redirect('/login');
}

function requireGuest(req, res, next) {
  if (req.user) return res.redirect(`/u/${req.user.username}`);
  next();
}

/** Only allow same-site relative redirects. */
function safeReturnTo(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : null;
}

/** Start a fresh session for a user (prevents session fixation). */
function logIn(req, user, done) {
  req.session.regenerate((err) => {
    if (err) return done(err);
    req.session.userId = user.id;
    req.session.save(done);
  });
}

module.exports = { attachContext, verifyCsrf, requireAuth, requireGuest, safeReturnTo, logIn };
