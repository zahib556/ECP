"""Регистрация, вход, выход, /me, привязка к устройству, ограничение попыток, сброс привязки."""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from ecp import audit
from ecp.auth import AuthError, AuthService, SessionExpired
from ecp.auth import passwords

DEV1 = "a1" * 32
DEV2 = "b2" * 32
PW = "Hunter2-secure"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def log(tmp_path):
    return audit.AuditLog(tmp_path / "audit.log", user="os-user", host_ip="10.0.0.9")


@pytest.fixture()
def svc(tmp_path, clock, log):
    service = AuthService(tmp_path / "users.db", tmp_path / "auth.key", audit=log, clock=clock)
    yield service
    service.close()


def events(log):
    return [e for e in audit.read_events(log.path)[0] if e.source_name == "ecp.auth"]


def rows(svc, sql, *args):
    return sqlite3.connect(str(svc._db.path)).execute(sql, args).fetchall()


# ------------------------------------------------------------------ схема и хранение
def test_schema_matches_assignment(svc):
    users = [r[1] for r in rows(svc, "PRAGMA table_info(users)")]
    sessions = [r[1] for r in rows(svc, "PRAGMA table_info(sessions)")]
    assert users == ["id", "login", "password_hash", "salt", "device_id", "created_at", "last_seen"]
    assert sessions == ["token", "user_id", "device_id", "created_at", "expires_at"]


def test_register_stores_hash_and_salt_not_password(svc):
    svc.register("Alice", PW, DEV1)
    login, pw_hash, salt, dev, created, last_seen = rows(
        svc, "SELECT login, password_hash, salt, device_id, created_at, last_seen FROM users")[0]
    assert login == "alice" and dev == DEV1 and last_seen is None and created.startswith("2026-10-23")
    assert PW not in pw_hash and PW not in salt and passwords.verify_password(PW, salt, pw_hash)


def test_same_password_different_users_different_salt_and_hash(svc):
    svc.register("alice", PW)
    svc.register("bob", PW)
    (h1, s1), (h2, s2) = rows(svc, "SELECT password_hash, salt FROM users ORDER BY id")
    assert s1 != s2 and h1 != h2


def test_register_validation(svc):
    with pytest.raises(AuthError, match="логин"):
        svc.register("a b", PW)
    with pytest.raises(AuthError, match="пароль"):
        svc.register("alice", "short")
    with pytest.raises(AuthError, match="устройства"):
        svc.register("alice", PW, "not-a-device-id")
    assert rows(svc, "SELECT COUNT(*) FROM users")[0][0] == 0


def test_register_duplicate_login_case_insensitive(svc):
    svc.register("alice", PW)
    with pytest.raises(AuthError, match="уже существует"):
        svc.register("ALICE", PW)


def test_register_returns_one_time_code_stored_hashed(svc):
    reg = svc.register("alice", PW)
    assert len(reg.reset_code.replace("-", "")) == 12
    code_hash = rows(svc, "SELECT code_hash FROM reset_codes")[0][0]
    assert reg.reset_code.replace("-", "") not in code_hash


# ------------------------------------------------------------------ вход
def test_login_success_issues_session(svc):
    svc.register("alice", PW)
    res = svc.login("Alice", PW, DEV1)
    assert res.login == "alice" and res.token.count(".") == 2
    assert rows(svc, "SELECT user_id, device_id FROM sessions") == [(1, DEV1)]
    assert rows(svc, "SELECT last_seen FROM users")[0][0] is not None


def test_login_wrong_password_and_unknown_user_same_message(svc):
    svc.register("alice", PW)
    with pytest.raises(AuthError) as bad_pw:
        svc.login("alice", "Wrong-pass-1", DEV1)
    with pytest.raises(AuthError) as no_user:
        svc.login("nobody", PW, DEV1)
    assert str(bad_pw.value) == str(no_user.value) == "Ошибка: неверный логин или пароль"
    assert rows(svc, "SELECT COUNT(*) FROM sessions")[0][0] == 0


def test_login_requires_valid_device_id(svc):
    svc.register("alice", PW)
    with pytest.raises(AuthError, match="устройство"):
        svc.login("alice", PW, "")


# ------------------------------------------------------------------ привязка к устройству
def test_first_login_binds_device_when_null(svc):
    svc.register("alice", PW)  # без device_id
    assert rows(svc, "SELECT device_id FROM users")[0][0] is None
    svc.login("alice", PW, DEV1)
    assert rows(svc, "SELECT device_id FROM users")[0][0] == DEV1


def test_same_device_allowed_other_device_refused(svc):
    svc.register("alice", PW, DEV1)
    svc.login("alice", PW, DEV1)
    with pytest.raises(AuthError, match="Вход с незнакомого устройства|вход с незнакомого устройства"):
        svc.login("alice", PW, DEV2)
    assert rows(svc, "SELECT device_id FROM users")[0][0] == DEV1  # привязка не изменилась


def test_unknown_device_refused_only_after_correct_password(svc):
    svc.register("alice", PW, DEV1)
    with pytest.raises(AuthError, match="логин или пароль"):
        svc.login("alice", "Wrong-pass-1", DEV2)  # с чужого устройства и неверным паролем - обычная ошибка


# ------------------------------------------------------------------ /me и /logout
def test_me_returns_user(svc):
    svc.register("alice", PW)
    token = svc.login("alice", PW, DEV1).token
    info = svc.me(token, DEV1)
    assert info.login == "alice" and info.device_id == DEV1


def test_me_rejects_garbage_and_foreign_tokens(svc):
    with pytest.raises(AuthError):
        svc.me("garbage")
    with pytest.raises(AuthError):
        svc.me("")


def test_token_is_bound_to_device(svc):
    svc.register("alice", PW)
    token = svc.login("alice", PW, DEV1).token
    with pytest.raises(AuthError, match="незнакомого устройства"):
        svc.me(token, DEV2)


def test_token_expires_after_30_minutes(svc, clock):
    svc.register("alice", PW)
    token = svc.login("alice", PW, DEV1).token
    clock.advance(minutes=29)
    assert svc.me(token, DEV1).login == "alice"
    clock.advance(minutes=2)
    with pytest.raises(SessionExpired):
        svc.me(token, DEV1)
    assert rows(svc, "SELECT COUNT(*) FROM sessions")[0][0] == 0


def test_logout_invalidates_token(svc):
    svc.register("alice", PW)
    token = svc.login("alice", PW, DEV1).token
    svc.logout(token)
    with pytest.raises(SessionExpired):
        svc.me(token, DEV1)
    with pytest.raises(AuthError):
        svc.logout("garbage")


def test_token_from_another_service_key_rejected(svc, tmp_path, clock):
    svc.register("alice", PW)
    token = svc.login("alice", PW, DEV1).token
    other = AuthService(tmp_path / "users.db", tmp_path / "other.key", clock=clock)
    try:
        with pytest.raises(AuthError, match="недействительный"):
            other.me(token, DEV1)
    finally:
        other.close()


def test_key_persists_between_runs(tmp_path, clock):
    first = AuthService(tmp_path / "users.db", tmp_path / "auth.key", clock=clock)
    first.register("alice", PW)
    token = first.login("alice", PW, DEV1).token
    first.close()
    second = AuthService(tmp_path / "users.db", tmp_path / "auth.key", clock=clock)
    try:
        assert second.me(token, DEV1).login == "alice"
    finally:
        second.close()


def test_corrupt_key_file_reported(tmp_path):
    (tmp_path / "auth.key").write_text("zz", encoding="ascii")
    with pytest.raises(AuthError, match="ключ"):
        AuthService(tmp_path / "users.db", tmp_path / "auth.key")


def test_database_failure_is_reported_not_raised(svc):
    svc._db.close()
    with pytest.raises(AuthError, match="база"):
        svc.login("alice", PW, DEV1)


# ------------------------------------------------------------------ ограничение попыток входа
def test_lockout_after_five_failures_then_unlock(svc, clock):
    svc.register("alice", PW)
    for _ in range(5):
        with pytest.raises(AuthError, match="логин или пароль"):
            svc.login("alice", "Wrong-pass-1", DEV1)
    with pytest.raises(AuthError, match="слишком много"):
        svc.login("alice", PW, DEV1)  # даже верный пароль не принимается
    clock.advance(minutes=6)
    assert svc.login("alice", PW, DEV1).login == "alice"


def test_successful_login_resets_counter(svc):
    svc.register("alice", PW)
    for _ in range(4):
        with pytest.raises(AuthError):
            svc.login("alice", "Wrong-pass-1", DEV1)
    svc.login("alice", PW, DEV1)
    for _ in range(4):
        with pytest.raises(AuthError, match="логин или пароль"):
            svc.login("alice", "Wrong-pass-1", DEV1)
    assert svc.login("alice", PW, DEV1)  # не заблокирован: счёт начался заново


def test_lockout_applies_to_unknown_logins_too(svc):
    for _ in range(5):
        with pytest.raises(AuthError):
            svc.login("ghost", PW, DEV1)
    with pytest.raises(AuthError, match="слишком много"):
        svc.login("ghost", PW, DEV1)


# ------------------------------------------------------------------ сброс привязки
def test_reset_device_with_one_time_code(svc):
    reg = svc.register("alice", PW, DEV1)
    token = svc.login("alice", PW, DEV1).token
    new_code = svc.reset_device("alice", PW, reg.reset_code.lower())  # регистр и дефисы не важны
    assert new_code != reg.reset_code
    assert rows(svc, "SELECT device_id FROM users")[0][0] is None
    with pytest.raises(SessionExpired):
        svc.me(token, DEV1)  # старые сессии закрыты
    assert svc.login("alice", PW, DEV2).login == "alice"  # новое устройство привязалось
    with pytest.raises(AuthError):
        svc.reset_device("alice", PW, reg.reset_code)  # старый код больше не действует


def test_reset_device_wrong_code_or_password(svc):
    reg = svc.register("alice", PW, DEV1)
    with pytest.raises(AuthError, match="код сброса"):
        svc.reset_device("alice", PW, "AAAA-AAAA-AAAA")
    with pytest.raises(AuthError, match="код сброса"):
        svc.reset_device("alice", "Wrong-pass-1", reg.reset_code)
    assert rows(svc, "SELECT device_id FROM users")[0][0] == DEV1


def test_reset_attempts_are_rate_limited(svc):
    reg = svc.register("alice", PW, DEV1)
    for _ in range(5):
        with pytest.raises(AuthError):
            svc.reset_device("alice", PW, "AAAA-AAAA-AAAA")
    with pytest.raises(AuthError, match="слишком много"):
        svc.reset_device("alice", PW, reg.reset_code)


# ------------------------------------------------------------------ журнал входов
def test_login_events_in_audit_log(svc, log):
    svc.register("alice", PW, DEV1)
    with pytest.raises(AuthError):
        svc.login("alice", "Wrong-pass-1", DEV1)
    token = svc.login("alice", PW, DEV1).token
    with pytest.raises(AuthError):
        svc.login("alice", PW, DEV2)
    svc.logout(token)
    evs = events(log)
    texts = [(e.status, e.description) for e in evs]
    assert ("failure", f"Неудачный вход «alice»: неверный логин или пароль, device_id={DEV1[:16]}") in texts
    assert any(s == "success" and d.startswith("Успешный вход «alice»") and DEV1[:16] in d for s, d in texts)
    assert any(s == "failure" and "незнакомого устройства" in d and DEV2[:16] in d for s, d in texts)
    assert any(d == "Выход «alice»" for _, d in texts)
    assert all(e.source_ip == "127.0.0.1" and e.event_datetime for e in evs)


def test_secrets_never_reach_audit_log(svc, log):
    reg = svc.register("alice", PW, DEV1)
    token = svc.login("alice", PW, DEV1).token
    with pytest.raises(AuthError):
        svc.login("alice", "Wrong-pass-1", DEV1)
    svc.reset_device("alice", PW, reg.reset_code)
    text = log.path.read_text(encoding="utf-8")
    for secret in (PW, "Wrong-pass-1", token, token.split(".")[1], reg.reset_code, reg.reset_code.replace("-", "")):
        assert secret not in text
    assert DEV1 not in text  # в журнале только короткий префикс device_id
