"""События безопасности при реальной работе с файлами и ключами (настоящее криптоядро)."""
import pytest

from ecp import audit, service
from ecp.context import AppContext
from ecp.errors import EcpError


@pytest.fixture()
def ctx(tmp_path):
    context = AppContext.start(tmp_path / "cfg" / "config.ini", user="tester", host_ip="10.0.0.9")
    yield context
    context.shutdown()


def evs(ctx):
    return audit.read_events(ctx.audit.path)[0]


def find(ctx, **kw):
    return [e for e in evs(ctx) if all(getattr(e, k) == v for k, v in kw.items())]


def test_keygen_events(ctx, tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    assert len(find(ctx, source_name="ecp.keys", status="success", action="create")) == 1
    created = find(ctx, source_name="ecp.files", action="create", status="success")
    assert {e.object for e in created} == {str(keys.private_path), str(keys.public_path)}
    for e in find(ctx, source_name="ecp.keys"):
        assert e.operation_start <= e.operation_end
    # секреты в журнал не попадают
    assert keys.private_key.hex() not in ctx.audit.path.read_text(encoding="utf-8").lower()


def test_overwrite_is_logged_as_modify(ctx, tmp_path):
    service.generate_keys(tmp_path / "keys")
    service.generate_keys(tmp_path / "keys", overwrite=True)
    assert len(find(ctx, source_name="ecp.files", action="modify", status="success")) == 2


def test_keygen_refusal_is_failure(ctx, tmp_path):
    service.generate_keys(tmp_path / "keys")
    with pytest.raises(EcpError):
        service.generate_keys(tmp_path / "keys")
    failed = find(ctx, source_name="ecp.keys", status="failure")
    assert len(failed) == 1 and failed[0].level == "error" and "уже есть" in failed[0].description


def test_sign_and_verify_events(ctx, tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    msg = tmp_path / "doc.txt"
    msg.write_bytes(b"hello")
    sig = tmp_path / "doc.sig"
    service.sign_file(msg, keys.private_path, sig)
    assert len(find(ctx, source_name="ecp.sign", status="success", action="create")) == 1
    reads = find(ctx, source_name="ecp.files", action="access", status="success")
    assert {e.object for e in reads} >= {str(msg), str(keys.private_path)}

    assert service.verify_files(msg, sig, keys.public_path).ok
    ok = find(ctx, source_name="ecp.verify", status="success")
    assert len(ok) == 1 and "ДА" in ok[0].description

    msg.write_bytes(b"changed")
    assert not service.verify_files(msg, sig, keys.public_path).ok
    bad = find(ctx, source_name="ecp.verify", status="failure")
    assert len(bad) == 1 and bad[0].level == "warning" and "НЕТ" in bad[0].description


def test_missing_file_logged(ctx, tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    with pytest.raises(EcpError):
        service.sign_file(tmp_path / "нет.txt", keys.private_path, tmp_path / "s.sig")
    failed = find(ctx, source_name="ecp.files", status="failure", action="access")
    assert len(failed) == 1 and failed[0].level == "error"
    assert len(find(ctx, source_name="ecp.sign", status="failure")) == 1


def test_cades_events(ctx, tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    msg = tmp_path / "doc.txt"
    msg.write_bytes(b"hello")
    out = tmp_path / "doc.p7s"
    service.sign_cades_file(msg, keys.private_path, out, "Иванов И.И.")
    service.verify_cades_file(msg, out)
    assert len(find(ctx, source_name="ecp.cades", status="success")) == 2


def test_cancel_logged(ctx):
    service.audit_cancel("ecp.sign", "Отмена: файл подписи не выбран", obj="x.sig")
    cancelled = find(ctx, status="cancelled")
    assert len(cancelled) == 1 and cancelled[0].action == "create"


def test_selftest_logged(ctx):
    results = service.self_test()
    ok = all(r.ok for r in results)
    if ok:
        assert find(ctx, source_name="ecp.selftest", status="success", level="info")
    else:
        assert find(ctx, source_name="ecp.selftest", status="failure", level="critical")


def test_build_info_in_development_mode_or_release():
    info = service.build_info()
    assert info.version == service.version()
    assert info.status in ("absent", "ok", "failed")
    if info.status == "absent":
        assert info.build_date == "" and info.authentic is None
