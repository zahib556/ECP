"""База данных пользователей (SQLite): таблицы users и sessions по заданию + служебные."""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    device_id TEXT,
    created_at TEXT NOT NULL,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS login_attempts (
    login TEXT PRIMARY KEY,
    failed INTEGER NOT NULL,
    locked_until TEXT
);
CREATE TABLE IF NOT EXISTS update_audit (
    id INTEGER PRIMARY KEY,
    user_id INTEGER, device_id TEXT,
    from_version TEXT, to_version TEXT,
    status TEXT,  -- verified | installed | failed | rolled_back | sbom_mismatch
    ip TEXT, ts TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS reset_codes (
    user_id INTEGER PRIMARY KEY,
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
"""


@dataclass
class UserRow:
    id: int
    login: str
    password_hash: str
    salt: str
    device_id: Optional[str]
    created_at: str
    last_seen: Optional[str]


@dataclass
class SessionRow:
    token: str
    user_id: int
    device_id: Optional[str]
    created_at: str
    expires_at: str


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _one(self, sql: str, args: tuple = ()):
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    def _run(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.rowcount

    # ---- users
    def add_user(self, login: str, password_hash: str, salt: str, device_id: Optional[str], now: str) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO users (login, password_hash, salt, device_id, created_at) VALUES (?,?,?,?,?)",
                (login, password_hash, salt, device_id, now))
            self._db.commit()
            return int(cur.lastrowid)

    def get_user(self, login: str) -> Optional[UserRow]:
        row = self._one("SELECT id, login, password_hash, salt, device_id, created_at, last_seen "
                        "FROM users WHERE login = ?", (login,))
        return UserRow(*row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[UserRow]:
        row = self._one("SELECT id, login, password_hash, salt, device_id, created_at, last_seen "
                        "FROM users WHERE id = ?", (user_id,))
        return UserRow(*row) if row else None

    def set_device(self, user_id: int, device_id: Optional[str]) -> None:
        self._run("UPDATE users SET device_id = ? WHERE id = ?", (device_id, user_id))

    def touch(self, user_id: int, now: str) -> None:
        self._run("UPDATE users SET last_seen = ? WHERE id = ?", (now, user_id))

    # ---- sessions
    def add_session(self, token: str, user_id: int, device_id: str, created: str, expires: str) -> None:
        self._run("INSERT INTO sessions (token, user_id, device_id, created_at, expires_at) VALUES (?,?,?,?,?)",
                  (token, user_id, device_id, created, expires))

    def get_session(self, token: str) -> Optional[SessionRow]:
        row = self._one("SELECT token, user_id, device_id, created_at, expires_at FROM sessions WHERE token = ?",
                        (token,))
        return SessionRow(*row) if row else None

    def delete_session(self, token: str) -> bool:
        return self._run("DELETE FROM sessions WHERE token = ?", (token,)) > 0

    def delete_user_sessions(self, user_id: int) -> None:
        self._run("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    def purge_expired(self, now: str) -> int:
        return self._run("DELETE FROM sessions WHERE expires_at <= ?", (now,))

    def count_sessions(self) -> int:
        return int(self._one("SELECT COUNT(*) FROM sessions")[0])

    # ---- ограничение попыток входа
    def get_attempts(self, login: str):
        row = self._one("SELECT failed, locked_until FROM login_attempts WHERE login = ?", (login,))
        return (row[0], row[1]) if row else (0, None)

    def set_attempts(self, login: str, failed: int, locked_until: Optional[str]) -> None:
        self._run("INSERT INTO login_attempts (login, failed, locked_until) VALUES (?,?,?) "
                  "ON CONFLICT(login) DO UPDATE SET failed = excluded.failed, locked_until = excluded.locked_until",
                  (login, failed, locked_until))

    def clear_attempts(self, login: str) -> None:
        self._run("DELETE FROM login_attempts WHERE login = ?", (login,))

    # ---- код сброса привязки устройства
    def set_reset_code(self, user_id: int, code_hash: str, salt: str) -> None:
        self._run("INSERT INTO reset_codes (user_id, code_hash, salt) VALUES (?,?,?) "
                  "ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, salt = excluded.salt",
                  (user_id, code_hash, salt))

    def get_reset_code(self, user_id: int):
        row = self._one("SELECT code_hash, salt FROM reset_codes WHERE user_id = ?", (user_id,))
        return (row[0], row[1]) if row else None

    def delete_reset_code(self, user_id: int) -> None:
        self._run("DELETE FROM reset_codes WHERE user_id = ?", (user_id,))

    # ---- журнал обновлений (update_audit)
    def add_update_audit(self, user_id, device_id, from_version, to_version, status, ip, ts) -> None:
        self._run("INSERT INTO update_audit (user_id, device_id, from_version, to_version, status, ip, ts) "
                  "VALUES (?,?,?,?,?,?,?)", (user_id, device_id, from_version, to_version, status, ip, ts))

    def list_update_audit(self, limit: int = 50):
        with self._lock:
            return self._db.execute(
                "SELECT ts, status, from_version, to_version, user_id, device_id, ip FROM update_audit "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
