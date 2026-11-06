"""Логика аутентификации: регистрация, вход, выход, проверка сессии, привязка к устройству.

Ограничение попыток входа, сброс привязки устройства по одноразовому коду и запись входов
в журнал событий входят в дополнительные задания и реализованы здесь же.
Пароли и токены в журнал не пишутся.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from ..audit import AuditLog
from ..errors import EcpError
from . import device as devmod
from . import passwords, tokens
from .store import Database, UserRow

TOKEN_TTL = timedelta(minutes=30)
MAX_ATTEMPTS = 5
LOCKOUT = timedelta(minutes=5)
KEY_BYTES = 32
_LOGIN = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_DUMMY_SALT = "00" * passwords.SALT_BYTES

BAD_CREDENTIALS = "Ошибка: неверный логин или пароль"
UNKNOWN_DEVICE = "Ошибка: вход с незнакомого устройства"


class AuthError(EcpError):
    """Отказ в аутентификации; текст сообщения можно показывать пользователю."""


class SessionExpired(AuthError):
    """Токен просрочен или сессия завершена: клиент должен вернуться на экран входа."""


@dataclass
class Registration:
    login: str
    reset_code: str  # показывается один раз; в базе хранится только хэш


@dataclass
class LoginResult:
    token: str
    login: str
    expires_at: str


@dataclass
class UserInfo:
    login: str
    device_id: Optional[str]
    created_at: str
    last_seen: Optional[str]
    expires_at: str


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def normalize_login(login: str) -> str:
    login = (login or "").strip()
    if not _LOGIN.match(login):
        raise AuthError("Ошибка: логин — от 3 до 32 символов (латинские буквы, цифры, «_», «.», «-»)")
    return login.lower()


class AuthService:
    def __init__(self, db_path: Path, key_path: Path, audit: Optional[AuditLog] = None,
                 clock: Optional[Callable[[], datetime]] = None, token_ttl: timedelta = TOKEN_TTL,
                 max_attempts: int = MAX_ATTEMPTS, lockout: timedelta = LOCKOUT) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._audit = audit
        self.token_ttl = token_ttl
        self.max_attempts = max_attempts
        self.lockout = lockout
        try:
            self._db = Database(Path(db_path))
        except (sqlite3.Error, OSError) as e:
            raise AuthError(f"Ошибка: база пользователей недоступна ({e})") from None
        self._key = self._load_key(Path(key_path))

    # ------------------------------------------------------------ служебное
    @staticmethod
    def _load_key(path: Path) -> bytes:
        try:
            if path.exists():
                key = bytes.fromhex(path.read_text(encoding="ascii").strip())
                if len(key) < KEY_BYTES:
                    raise ValueError("ключ слишком короткий")
                return key
            path.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(KEY_BYTES)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(key.hex())
            return key
        except (OSError, ValueError) as e:
            raise AuthError(f"Ошибка: ключ подписи токенов недоступен ({e})") from None

    @property
    def database(self) -> Database:
        return self._db

    def close(self) -> None:
        self._db.close()

    def _now(self) -> datetime:
        return self._clock()

    def set_audit(self, audit: Optional[AuditLog]) -> None:
        self._audit = audit

    def _log(self, text: str, *, ok: bool = True, level: str = "info", action: str = "access", obj: str = "") -> None:
        if self._audit is not None:
            self._audit.log("ecp.auth", text, level=level if ok or level != "info" else "warning",
                            status="success" if ok else "failure", action=action, obj=obj)

    def _fail(self, message: str, log_text: str, login: str = "", *, cls=AuthError, level: str = "warning",
              action: str = "access"):
        self._log(log_text, ok=False, level=level, action=action, obj=login)
        return cls(message)

    @staticmethod
    def _short(device_id: Optional[str]) -> str:
        return (device_id or "-")[:16]

    def _guarded(self, fn):
        try:
            return fn()
        except sqlite3.Error as e:
            raise self._fail(f"Ошибка: база пользователей недоступна ({e})", f"Сбой базы пользователей: {e}",
                             level="error") from None

    # ------------------------------------------------------------ ограничение попыток
    def _check_lock(self, login: str, what: str) -> None:
        failed, until = self._db.get_attempts(login)
        if until and _parse(until) > self._now():
            minutes = max(1, int((_parse(until) - self._now()).total_seconds() + 59) // 60)
            raise self._fail(f"Ошибка: слишком много неудачных попыток. Повторите через {minutes} мин.",
                             f"{what}: учётная запись «{login}» заблокирована до {until}", login)

    def _register_failure(self, login: str) -> None:
        failed, until = self._db.get_attempts(login)
        if until and _parse(until) <= self._now():  # блокировка закончилась - счёт с нуля
            failed, until = 0, None
        failed += 1
        until = _iso(self._now() + self.lockout) if failed >= self.max_attempts else None
        self._db.set_attempts(login, 0 if until else failed, until)

    # ------------------------------------------------------------ /register
    def register(self, login: str, password: str, device_id: Optional[str] = None) -> Registration:
        return self._guarded(lambda: self._register(login, password, device_id))

    def _register(self, login: str, password: str, device_id: Optional[str]) -> Registration:
        login = normalize_login(login)
        if device_id is not None and not devmod.is_valid_device_id(device_id):
            raise self._fail("Ошибка: неверный идентификатор устройства", f"Регистрация «{login}»: неверный device_id",
                             login, action="create")
        problems = passwords.policy_problems(password)
        if problems:
            raise self._fail("Ошибка: " + "; ".join(problems), f"Регистрация «{login}» отклонена: слабый пароль",
                             login, action="create")
        salt = passwords.new_salt()
        try:
            user_id = self._db.add_user(login, passwords.hash_password(password, salt), salt, device_id,
                                        _iso(self._now()))
        except sqlite3.IntegrityError:
            raise self._fail("Ошибка: пользователь с таким логином уже существует",
                             f"Регистрация «{login}» отклонена: логин занят", login, action="create") from None
        code = self._issue_reset_code(user_id)
        self._log(f"Зарегистрирован пользователь «{login}», device_id={self._short(device_id)}",
                  action="create", obj=login)
        return Registration(login, code)

    def _issue_reset_code(self, user_id: int) -> str:
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
        salt = passwords.new_salt()
        self._db.set_reset_code(user_id, passwords.hash_password(raw, salt), salt)
        return "-".join(raw[i:i + 4] for i in range(0, 12, 4))

    # ------------------------------------------------------------ /login
    def login(self, login: str, password: str, device_id: str) -> LoginResult:
        return self._guarded(lambda: self._login(login, password, device_id))

    def _login(self, login: str, password: str, device_id: str) -> LoginResult:
        try:
            login = normalize_login(login)
        except AuthError:
            raise AuthError(BAD_CREDENTIALS) from None
        if not devmod.is_valid_device_id(device_id):
            raise self._fail("Ошибка: не удалось определить устройство", f"Вход «{login}»: неверный device_id", login)
        now = self._now()
        self._db.purge_expired(_iso(now))
        self._check_lock(login, "Вход")
        user = self._db.get_user(login)
        if user is None:  # одинаковое время и сообщение для неизвестного логина и неверного пароля
            passwords.hash_password(password, _DUMMY_SALT)
            ok = False
        else:
            ok = passwords.verify_password(password, user.salt, user.password_hash)
        if not ok:
            self._register_failure(login)
            raise self._fail(BAD_CREDENTIALS,
                             f"Неудачный вход «{login}»: неверный логин или пароль, device_id={self._short(device_id)}",
                             login)
        assert user is not None
        if user.device_id is None:
            self._db.set_device(user.id, device_id)
            self._log(f"Устройство привязано к «{login}», device_id={self._short(device_id)}", action="modify", obj=login)
        elif user.device_id != device_id:
            raise self._fail(UNKNOWN_DEVICE,
                             f"Отказ во входе «{login}»: вход с незнакомого устройства, device_id={self._short(device_id)}",
                             login)
        self._db.clear_attempts(login)
        self._db.touch(user.id, _iso(now))
        expires = now + self.token_ttl
        claims = {"sub": user.id, "login": login, "did": device_id, "jti": secrets.token_hex(8),
                  "iat": int(now.timestamp()), "exp": int(expires.timestamp())}
        token = tokens.encode(claims, self._key)
        self._db.add_session(token, user.id, device_id, _iso(now), _iso(expires))
        self._log(f"Успешный вход «{login}», device_id={self._short(device_id)}", obj=login)
        return LoginResult(token, login, _iso(expires))

    # ------------------------------------------------------------ /me
    def me(self, token: str, device_id: Optional[str] = None) -> UserInfo:
        return self._guarded(lambda: self._me(token, device_id))

    def _validate(self, token: str, device_id: Optional[str], purpose: str):
        now = self._now()
        try:
            claims = tokens.decode(token, self._key, int(now.timestamp()))
        except tokens.TokenExpired:
            self._db.delete_session(token)
            raise self._fail("Сессия истекла, выполните вход заново", f"{purpose}: токен просрочен",
                             cls=SessionExpired) from None
        except tokens.TokenError as e:
            raise self._fail("Ошибка: недействительный токен", f"{purpose}: недействительный токен ({e})") from None
        session = self._db.get_session(token)
        if session is None:
            raise self._fail("Сессия завершена, выполните вход заново", f"{purpose}: сессия не найдена",
                             claims.get("login", ""), cls=SessionExpired)
        if _parse(session.expires_at) <= now:
            self._db.delete_session(token)
            raise self._fail("Сессия истекла, выполните вход заново", f"{purpose}: сессия просрочена",
                             claims.get("login", ""), cls=SessionExpired)
        if claims.get("did") != session.device_id or (device_id is not None and device_id != session.device_id):
            raise self._fail(UNKNOWN_DEVICE, f"{purpose}: токен предъявлен с другого устройства",
                             claims.get("login", ""))
        user = self._db.get_user_by_id(session.user_id)
        if user is None:
            raise self._fail("Сессия завершена, выполните вход заново", f"{purpose}: пользователь удалён",
                             cls=SessionExpired)
        return user, session

    def _me(self, token: str, device_id: Optional[str]) -> UserInfo:
        user, session = self._validate(token, device_id, "Проверка сессии")
        self._db.touch(user.id, _iso(self._now()))
        return UserInfo(user.login, user.device_id, user.created_at, _iso(self._now()), session.expires_at)

    # ------------------------------------------------------------ /logout
    def logout(self, token: str) -> None:
        self._guarded(lambda: self._logout(token))

    def _logout(self, token: str) -> None:
        try:
            claims = tokens.decode(token, self._key, int(self._now().timestamp()), verify_exp=False)
        except tokens.TokenError:
            raise self._fail("Ошибка: недействительный токен", "Выход: недействительный токен") from None
        self._db.delete_session(token)
        self._log(f"Выход «{claims.get('login', '')}»", obj=str(claims.get("login", "")))

    # ------------------------------------------------------------ сброс привязки устройства
    def reset_device(self, login: str, password: str, reset_code: str) -> str:
        """Снимает привязку к устройству по одноразовому коду. Возвращает новый код сброса."""
        return self._guarded(lambda: self._reset_device(login, password, reset_code))

    def _reset_device(self, login: str, password: str, reset_code: str) -> str:
        try:
            login = normalize_login(login)
        except AuthError:
            raise AuthError(BAD_CREDENTIALS) from None
        self._check_lock(login, "Сброс привязки")
        user = self._db.get_user(login)
        stored = self._db.get_reset_code(user.id) if user else None
        raw = re.sub(r"[\s\-]", "", reset_code or "").upper()
        ok_password = bool(user) and passwords.verify_password(password, user.salt, user.password_hash)
        ok_code = bool(stored) and passwords.verify_password(raw, stored[1], stored[0])
        if not (ok_password and ok_code):
            self._register_failure(login)
            raise self._fail("Ошибка: неверный логин, пароль или код сброса",
                             f"Неудачный сброс привязки устройства «{login}»", login, action="modify")
        assert user is not None
        self._db.clear_attempts(login)
        self._db.set_device(user.id, None)
        self._db.delete_user_sessions(user.id)
        new_code = self._issue_reset_code(user.id)
        self._log(f"Привязка устройства «{login}» сброшена по одноразовому коду", action="modify", obj=login)
        return new_code
