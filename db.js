import Database from 'better-sqlite3';

export const db = new Database('app.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,          -- WebAuthn user handle (base64url)
  username    TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS credentials (
  id          TEXT PRIMARY KEY,          -- credential ID (base64url)
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key  BLOB NOT NULL,
  counter     INTEGER NOT NULL DEFAULT 0,
  transports  TEXT,                      -- JSON 配列
  device_type TEXT,
  backed_up   INTEGER,
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

export const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (id, username) VALUES (?, ?)'),
  credsByUser: db.prepare('SELECT * FROM credentials WHERE user_id = ?'),
  credById: db.prepare('SELECT * FROM credentials WHERE id = ?'),
  insertCred: db.prepare(
    `INSERT INTO credentials (id, user_id, public_key, counter, transports, device_type, backed_up)
     VALUES (@id, @user_id, @public_key, @counter, @transports, @device_type, @backed_up)`
  ),
  updateCounter: db.prepare('UPDATE credentials SET counter = ? WHERE id = ?'),
};
