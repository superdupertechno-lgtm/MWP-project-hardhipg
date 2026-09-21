const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
const uploadDir = path.join(dataDir, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    headline      TEXT NOT NULL DEFAULT '',
    bio           TEXT NOT NULL DEFAULT '',
    location      TEXT NOT NULL DEFAULT '',
    website       TEXT NOT NULL DEFAULT '',
    github        TEXT NOT NULL DEFAULT '',
    linkedin      TEXT NOT NULL DEFAULT '',
    avatar        TEXT,
    is_public     INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_users_public_created
    ON users (is_public, created_at DESC);

  CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    sess    TEXT NOT NULL,
    expires INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires);
`);

module.exports = { db, dataDir, uploadDir };
