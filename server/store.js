import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
export function openStore(directory) {
  mkdirSync(directory, { recursive: true });
  const masterPath = join(directory, 'master.key');
  if (!existsSync(masterPath)) writeFileSync(masterPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
  const master = readFileSync(masterPath);
  if (master.length !== 32) throw new Error('Invalid at-rest master key');
  const db = new DatabaseSync(join(directory, 'cipherroom.sqlite'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      role TEXT NOT NULL, totp TEXT NOT NULL, last_totp INTEGER DEFAULT -1,
      active INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), label TEXT NOT NULL,
      signing TEXT NOT NULL, exchange TEXT NOT NULL, certificate TEXT NOT NULL, revision INTEGER DEFAULT 1,
      trusted INTEGER DEFAULT 1, created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (
      hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), device_id TEXT NOT NULL REFERENCES devices(id),
      csrf TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, seen INTEGER NOT NULL,
      stepup INTEGER NOT NULL, revoked INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, owner TEXT NOT NULL REFERENCES users(id), created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS members (
      room_id TEXT NOT NULL REFERENCES rooms(id), user_id TEXT NOT NULL REFERENCES users(id),
      PRIMARY KEY(room_id,user_id));
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY, room_id TEXT NOT NULL REFERENCES rooms(id), sender TEXT NOT NULL REFERENCES devices(id),
      envelope TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS replays (id TEXT PRIMARY KEY, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY, user_id TEXT, kind TEXT NOT NULL, severity TEXT NOT NULL,
      detail TEXT NOT NULL, created INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS message_room ON messages(room_id,created);
    CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id,created);
  `);
  return { db, master };
}
