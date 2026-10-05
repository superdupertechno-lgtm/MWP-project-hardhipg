const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { db } = require('../db');
const v = require('../lib/validate');
const { verifyCsrf, requireAuth } = require('../lib/middleware');
const { removeAvatarFile } = require('../lib/upload');

const router = express.Router();
const BCRYPT_COST = 12;

// These routes check the current password, so throttle guessing.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT) || 15,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).render('error', {
      title: 'Slow down',
      heading: 'Too many attempts',
      message: 'Wait a few minutes, then try again.',
    }),
});

const findById = db.prepare('SELECT * FROM users WHERE id = ?');
const setEmail = db.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?');
const setPassword = db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?');
const deleteUser = db.prepare('DELETE FROM users WHERE id = ?');
// Sign out every other device that belongs to this user.
const endOtherSessions = db.prepare(
  "DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ? AND sid != ?"
);
const endAllSessions = db.prepare("DELETE FROM sessions WHERE json_extract(sess, '$.userId') = ?");

function renderAccount(res, status, user, extra = {}) {
  res.status(status).render('account', {
    title: 'Account',
    account: user,
    errors: {},
    values: {},
    ...extra,
  });
}

const pw = (value) => (typeof value === 'string' ? value : '');

router.get('/account', requireAuth, (req, res) => {
  renderAccount(res, 200, findById.get(req.user.id));
});

router.post('/account/email', requireAuth, limiter, verifyCsrf, async (req, res, next) => {
  try {
    const user = findById.get(req.user.id);
    const email = v.str(req.body.email);
    const errors = {};

    const emailError = v.email(email);
    if (emailError) errors.email = emailError;
    if (!(await bcrypt.compare(pw(req.body.current_password), user.password_hash)))
      errors.email_password = 'Current password is incorrect.';

    if (Object.keys(errors).length)
      return renderAccount(res, 422, user, { errors, values: { email } });

    try {
      setEmail.run(email, Date.now(), user.id);
    } catch (err) {
      if (err.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      return renderAccount(res, 422, user, {
        errors: { email: 'An account already uses this email.' },
        values: { email },
      });
    }

    req.flash('success', 'Email updated.');
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
});

router.post('/account/password', requireAuth, limiter, verifyCsrf, async (req, res, next) => {
  try {
    const user = findById.get(req.user.id);
    const newPw = pw(req.body.new_password);
    const errors = {};

    if (!(await bcrypt.compare(pw(req.body.current_password), user.password_hash)))
      errors.password_current = 'Current password is incorrect.';
    const strength = v.password(newPw);
    if (strength) errors.password_new = strength;
    else if (newPw !== pw(req.body.confirm_password)) errors.password_confirm = 'Passwords do not match.';

    if (Object.keys(errors).length) return renderAccount(res, 422, user, { errors });

    setPassword.run(await bcrypt.hash(newPw, BCRYPT_COST), Date.now(), user.id);
    endOtherSessions.run(user.id, req.sessionID);

    req.flash('success', 'Password changed. Other devices were signed out.');
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
});

router.post('/account/delete', requireAuth, limiter, verifyCsrf, async (req, res, next) => {
  try {
    const user = findById.get(req.user.id);
    const errors = {};

    if (v.str(req.body.confirm_username).toLowerCase() !== user.username.toLowerCase())
      errors.delete_username = 'Type your username exactly to confirm.';
    if (!(await bcrypt.compare(pw(req.body.current_password), user.password_hash)))
      errors.delete_password = 'Current password is incorrect.';

    if (Object.keys(errors).length) return renderAccount(res, 422, user, { errors });

    deleteUser.run(user.id);
    removeAvatarFile(user.avatar);
    endAllSessions.run(user.id);

    req.session.destroy((err) => {
      if (err) return next(err);
      res.clearCookie('sid');
      res.locals.currentUser = null;
      res.render('error', {
        title: 'Account deleted',
        heading: 'Your account is deleted',
        message: 'Your profile and photo were removed. You can sign up again any time.',
      });
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
