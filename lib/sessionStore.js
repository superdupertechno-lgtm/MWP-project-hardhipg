const session = require('express-session');

const DAY = 24 * 60 * 60 * 1000;

class SqliteStore extends session.Store {
  constructor(db) {
    super();
    this.q = {
      get: db.prepare('SELECT sess FROM sessions WHERE sid = ? AND expires > ?'),
      set: db.prepare(`
        INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires = excluded.expires`),
      del: db.prepare('DELETE FROM sessions WHERE sid = ?'),
      touch: db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?'),
      sweep: db.prepare('DELETE FROM sessions WHERE expires <= ?'),
    };
    this.q.sweep.run(Date.now());
    setInterval(() => this.q.sweep.run(Date.now()), 15 * 60 * 1000).unref();
  }

  static expiryOf(sess) {
    const exp = sess && sess.cookie && sess.cookie.expires;
    return exp ? new Date(exp).getTime() : Date.now() + DAY;
  }

  get(sid, cb) {
    try {
      const row = this.q.get.get(sid, Date.now());
      cb(null, row ? JSON.parse(row.sess) : null);
    } catch (err) {
      cb(err);
    }
  }

  set(sid, sess, cb) {
    try {
      this.q.set.run(sid, JSON.stringify(sess), SqliteStore.expiryOf(sess));
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      this.q.del.run(sid);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  touch(sid, sess, cb) {
    try {
      this.q.touch.run(SqliteStore.expiryOf(sess), sid);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }
}

module.exports = SqliteStore;
