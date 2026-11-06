"""Интеграция: операции приложения доступны только после входа (контекст + защита операций)."""
import copy
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from ecp import audit, service
from ecp.auth import AuthError, SessionExpired
from ecp.context import AppContext

DEV1 = "a1" * 32
DEV2 = "b2" * 32
PW = "Hunter2-secure"


class Clock:
    def __init__(self):
        self.now = datetime.now(timezone.utc)

    def __call__(self):
        return self.now


def start(tmp_path, device=DEV1, require_auth=True):
    return AppContext.start(tmp_path / "cfg" / "config.ini", require_auth=require_auth, device_id=device,
                            user="os-user", host_ip="10.0.0.9")


@pytest.fixture()
def ctx(tmp_path):
    context = start(tmp_path)
    yield context
    context.shutdown()


def logged_in(ctx, login="alice"):
    ctx.register(login, PW, PW)
    ctx.login(login, PW)
    return ctx


def touch_operation():
    """Любая защищённая операция сервисного слоя (все они проходят через service._op)."""
    with service._op("ecp.test", "проверка доступа", "access"):
        return "выполнено"


def events(ctx, **kw):
    return [e for e in audit.read_events(ctx.audit.path)[0] if all(getattr(e, k) == v for k, v in kw.items())]


# ------------------------------------------------------------------ защита операций
def test_auth_is_off_by_default(tmp_path):
    context = start(tmp_path, require_auth=False)
    try:
        assert not context.auth_required and service._access_guard is None
        assert touch_operation() == "выполнено"
    finally:
        context.shutdown()


def test_operations_blocked_before_login(ctx):
    assert ctx.auth_required and not ctx.logged_in
    with pytest.raises(AuthError, match="требуется вход"):
        touch_operation()
    denied = events(ctx, source_name="ecp.auth", status="failure")
    assert denied and denied[-1].description == "Отказ в доступе: вход не выполнен"


def test_keygen_blocked_before_login_creates_nothing(ctx, tmp_path):
    with pytest.raises(AuthError):
        service.generate_keys(tmp_path / "keys")
    assert not (tmp_path / "keys").exists()


def test_operations_allowed_after_login_and_blocked_after_logout(ctx):
    logged_in(ctx)
    assert touch_operation() == "выполнено"
    ctx.logout()
    assert not ctx.logged_in and ctx.session.token is None
    with pytest.raises(AuthError, match="требуется вход"):
        touch_operation()


def test_real_core_keygen_and_sign_after_login(ctx, tmp_path):
    logged_in(ctx)
    keys = service.generate_keys(tmp_path / "keys")
    message = tmp_path / "doc.txt"
    message.write_bytes(b"hello")
    result = service.sign_file(message, keys.private_path, tmp_path / "doc.sig")
    assert service.verify_files(message, tmp_path / "doc.sig", keys.public_path).ok
    assert result.signature_path.exists()
    ctx.logout()
    with pytest.raises(AuthError):
        service.sign_file(message, keys.private_path, tmp_path / "doc2.sig")
    assert not (tmp_path / "doc2.sig").exists()


def test_config_operations_protected(ctx, tmp_path):
    new = copy.deepcopy(ctx.config)
    new.logging.max_file_size = "50MB"
    for call in (lambda: ctx.save_config(new), ctx.reset_config, lambda: ctx.export_config(tmp_path / "x.ini"),
                 lambda: ctx.import_config(tmp_path / "x.ini")):
        with pytest.raises(AuthError, match="требуется вход"):
            call()
    assert ctx.config.logging.max_file_size != "50MB"
    logged_in(ctx)
    assert ctx.save_config(new) is True and ctx.config.logging.max_file_size == "50MB"


# ------------------------------------------------------------------ вход через контекст
def test_register_requires_matching_confirmation(ctx):
    with pytest.raises(AuthError, match="подтверждение"):
        ctx.register("alice", PW, PW + "x")
    code = ctx.register("alice", PW, PW)
    assert len(code.replace("-", "")) == 12


def test_failed_login_keeps_session_closed(ctx):
    ctx.register("alice", PW, PW)
    with pytest.raises(AuthError, match="логин или пароль"):
        ctx.login("alice", "Wrong-pass-1")
    assert not ctx.logged_in and ctx.audit.user == "os-user"


def test_login_from_unknown_device_refused(tmp_path):
    first = start(tmp_path, DEV1)
    first.register("alice", PW, PW)
    first.login("alice", PW)
    first.shutdown()
    second = start(tmp_path, DEV2)
    try:
        with pytest.raises(AuthError, match="незнакомого устройства"):
            second.login("alice", PW)
        assert not second.logged_in
        with pytest.raises(AuthError):
            touch_operation()
    finally:
        second.shutdown()


def test_audit_user_follows_login(ctx):
    logged_in(ctx)
    touch_operation()
    assert events(ctx, source_name="ecp.test")[-1].user_account == "alice"
    ctx.logout()
    assert ctx.audit.user == "os-user"


def test_reset_device_through_context(tmp_path):
    first = start(tmp_path, DEV1)
    code = first.register("alice", PW, PW)
    first.login("alice", PW)
    first.shutdown()
    second = start(tmp_path, DEV2)
    try:
        with pytest.raises(AuthError):
            second.login("alice", PW)
        second.reset_device("alice", PW, code)
        assert second.login("alice", PW) == "alice"
        assert touch_operation() == "выполнено"
    finally:
        second.shutdown()


# ------------------------------------------------------------------ истечение сессии
def test_expired_session_returns_to_login(ctx):
    clock = Clock()
    ctx.auth._clock = clock
    lost = []
    ctx.on_session_lost = lost.append
    logged_in(ctx)
    clock.now += timedelta(minutes=31)
    with pytest.raises(SessionExpired):
        touch_operation()
    assert not ctx.logged_in and ctx.audit.user == "os-user"
    assert len(lost) == 1 and "истекла" in lost[0]
    clock.now += timedelta(minutes=0)
    ctx.login("alice", PW)  # повторный вход после истечения
    assert touch_operation() == "выполнено"


def test_session_valid_inside_ttl(ctx):
    clock = Clock()
    ctx.auth._clock = clock
    logged_in(ctx)
    clock.now += timedelta(minutes=29)
    assert touch_operation() == "выполнено"


# ------------------------------------------------------------------ токен только в памяти
def test_token_not_written_to_files_or_log(ctx, tmp_path):
    logged_in(ctx)
    token = ctx.session.token
    assert token and token not in repr(ctx.session)
    touch_operation()
    ctx.logout()
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.name != "users.db":  # users.db хранит сессии на стороне сервиса
            assert token.encode() not in path.read_bytes(), path


# ------------------------------------------------------------------ завершение работы
def test_shutdown_ends_session_and_removes_guard(tmp_path):
    context = start(tmp_path)
    logged_in(context)
    db = context.state_path.with_name("users.db")
    context.shutdown()
    assert service._access_guard is None
    assert sqlite3.connect(str(db)).execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert touch_operation() == "выполнено"  # после закрытия контекста защита не «залипает» для других тестов


def test_start_fails_cleanly_when_user_database_unavailable(tmp_path):
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "users.db").mkdir()  # вместо файла базы - каталог
    with pytest.raises(AuthError, match="база"):
        start(tmp_path)
    assert service._access_guard is None and service.get_audit() is None
