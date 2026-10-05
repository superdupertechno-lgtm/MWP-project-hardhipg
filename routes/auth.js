const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { db } = require('../db');
const v = require('../lib/validate');
const { verifyCsrf, requireGuest, safeReturnTo, logIn } = require('../lib/middleware');

const router = express.Router();

const BCRYPT_COST = 12;
// Compared against when a login names an unknown account, so both paths take similar time.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', BCRYPT_COST);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT) || 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).render('error', {
      title: 'Slow down',
      heading: 'Too many attempts',
      message: 'Wait a few minutes, then try again.',
    }),
});

const insertUser = db.prepare(`
  INSERT INTO users (username, email, password_hash, display_name, created_at, updated_at)
  VALUES (@username, @email, @password_hash, @display_name, @now, @now)
`);
const findByLogin = db.prepare(
  'SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1'
);

// ---------- Sign up ----------

router.get('/signup', requireGuest, (req, res) => {
  const wanted = v.str(req.query.username).slice(0, 20);
  res.render('signup', { title: 'Create your profile', values: { username: wanted }, errors: {} });
});

router.post('/signup', requireGuest, authLimiter, verifyCsrf, async (req, res, next) => {
  try {
    const values = { username: v.str(req.body.username), email: v.str(req.body.email) };
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const confirm = typeof req.body.confirm === 'string' ? req.body.confirm : '';

    const errors = {};
    const usernameError = v.username(values.username);
    if (usernameError) errors.username = usernameError;
    const emailError = v.email(values.email);
    if (emailError) errors.email = emailError;
    const passwordError = v.password(password);
    if (passwordError) errors.password = passwordError;
    else if (password !== confirm) errors.confirm = 'Passwords do not match.';

    const fail = () =>
      res.status(422).render('signup', { title: 'Create your profile', values, errors });
    if (Object.keys(errors).length) return fail();

    const now = Date.now();
    let userId;
    try {
      const result = insertUser.run({
        username: values.username,
        email: values.email,
        password_hash: await bcrypt.hash(password, BCRYPT_COST),
        display_name: values.username,
        now,
      });
      userId = Number(result.lastInsertRowid);
    } catch (err) {
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      if (/users\.email/.test(err.message)) errors.email = 'An account already uses this email.';
      else errors.username = 'That username is taken.';
      return fail();
    }

    logIn(req, { id: userId }, (err) => {
      if (err) return next(err);
      req.flash('success', 'Account created. Add a few details so people know who you are.');
      res.redirect('/profile/edit');
    });
  } catch (err) {
    next(err);
  }
});

// ---------- Log in ----------

router.get('/login', requireGuest, (req, res) => {
  res.render('login', { title: 'Log in', values: {}, error: null });
});

router.post('/login', requireGuest, authLimiter, verifyCsrf, async (req, res, next) => {
  try {
    const identifier = v.str(req.body.identifier);
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    const user = identifier ? findByLogin.get(identifier, identifier) : null;
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !ok) {
      return res.status(401).render('login', {
        title: 'Log in',
        values: { identifier },
        error: 'Username, email, or password is incorrect.',
      });
    }

    const returnTo = safeReturnTo(req.session.returnTo);
    logIn(req, user, (err) => {
      if (err) return next(err);
      res.redirect(returnTo || `/u/${user.username}`);
    });
  } catch (err) {
    next(err);
  }
});

// ---------- Log out ----------

router.post('/logout', verifyCsrf, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    res.redirect('/');
  });
});

module.exports = router;
