"""Обновление в приложении: update_audit, журнал, защита входом, процесс установки, сборщик релиза."""
import importlib.util
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ecp import audit
from ecp.auth import AuthError
from ecp.context import AppContext
from ecp.errors import EcpError
from ecp.update import FileSource, installer, release

_spec = importlib.util.spec_from_file_location("build_update", Path(__file__).parent.parent / "tools" / "build_update.py")
build_update = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_update)

DEV = "a1" * 32
PW = "Hunter2-secure"
INSTALLED = {"PySide6": "6.7.0", "cryptography": "42.0.5"}


def keypair():
    key = ed25519.Ed25519PrivateKey.generate()
    return (key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def start(tmp_path, require_auth=False):
    return AppContext.start(tmp_path / "cfg" / "config.ini", require_auth=require_auth, device_id=DEV,
                            user="os-user", host_ip="10.0.0.9")


@pytest.fixture()
def ctx(tmp_path):
    context = start(tmp_path)
    yield context
    context.shutdown()


def rows(ctx, sql="SELECT status, from_version, to_version, user_id, device_id, ip, ts FROM update_audit ORDER BY id"):
    return sqlite3.connect(str(ctx.state_path.with_name("users.db"))).execute(sql).fetchall()


def make_env(tmp_path):
    private, public = keypair()
    app = tmp_path / "install" / "ecp"
    app.mkdir(parents=True)
    (app / "__main__.py").write_text("old", encoding="utf-8")
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "__main__.py").write_text("new", encoding="utf-8")
    manifest = build_update.build_package(payload, tmp_path / "release", "1.3.0", "0.4.0", private, os_name="windows",
                                          arch="x64", installed=INSTALLED)
    return private, public, app, manifest


def make_updater(ctx, tmp_path, public, app):
    return ctx.make_updater(app_dir=app, current_version="1.2.0", public_key=public, os_name="windows", arch="x64",
                            entry_files=("__main__.py",))


# ------------------------------------------------------------------ update_audit и журнал
def test_update_audit_row_and_journal_event(ctx):
    ctx.record_update("installed", "1.2.0", "1.3.0")
    ctx.record_update("rolled_back", "1.2.0", "1.4.0", "сбой запуска")
    ctx.record_update("sbom_mismatch", "1.2.0", "1.5.0", "хэш SBOM")
    got = rows(ctx)
    assert [r[0] for r in got] == ["installed", "rolled_back", "sbom_mismatch"]
    status, frm, to, user_id, device, ip, ts = got[0]
    assert (frm, to, user_id, device, ip) == ("1.2.0", "1.3.0", None, DEV, "127.0.0.1") and ts.endswith("Z")
    evs = [e for e in audit.read_events(ctx.audit.path)[0] if e.source_name == "ecp.update"]
    assert [(e.level, e.status) for e in evs] == [("info", "success"), ("warning", "failure"), ("error", "failure")]
    assert "сбой запуска" in evs[1].description and "1.2.0 -> 1.3.0" in evs[0].description


def test_update_audit_schema_matches_assignment(ctx):
    ctx.record_update("verified", "1.0.0", "1.1.0")
    cols = [r[1] for r in rows(ctx, "PRAGMA table_info(update_audit)")]
    assert cols == ["id", "user_id", "device_id", "from_version", "to_version", "status", "ip", "ts"]


def test_invalid_status_rejected(ctx):
    with pytest.raises(ValueError):
        ctx.record_update("hacked", "1.0.0", "1.1.0")


def test_audit_row_has_user_id_when_logged_in(tmp_path):
    context = start(tmp_path, require_auth=True)
    try:
        context.register("alice", PW, PW)
        context.login("alice", PW)
        context.record_update("installed", "1.2.0", "1.3.0")
        uid = rows(context, "SELECT id FROM users WHERE login='alice'")[0][0]
        assert rows(context)[0][3] == uid
    finally:
        context.shutdown()


# ------------------------------------------------------------------ результат отдельного процесса
def test_ingest_result_file(ctx):
    ctx.update_result_path.write_text(json.dumps(
        {"status": "rolled_back", "from_version": "1.2.0", "to_version": "1.3.0", "error": "не стартует"}), encoding="utf-8")
    ctx.ingest_update_result()
    assert rows(ctx)[0][:3] == ("rolled_back", "1.2.0", "1.3.0")
    assert not ctx.update_result_path.exists()  # запись вносится один раз
    ctx.ingest_update_result()
    assert len(rows(ctx)) == 1


def test_ingest_ignores_corrupt_or_forged_results(ctx):
    for text in ("не json", json.dumps({"status": "pwned"}), json.dumps(["x"])):
        ctx.update_result_path.write_text(text, encoding="utf-8")
        ctx.ingest_update_result()
        assert not ctx.update_result_path.exists()
    assert ctx.update_db.list_update_audit() == []  # поддельные результаты в журнал обновлений не попали
    warn = [e for e in audit.read_events(ctx.audit.path)[0] if e.level == "warning" and e.source_name == "ecp.update"]
    assert len(warn) == 3


def test_result_is_ingested_on_next_start(tmp_path):
    first = start(tmp_path)
    path = first.update_result_path
    first.shutdown()
    path.write_text(json.dumps({"status": "installed", "from_version": "1.2.0", "to_version": "1.3.0"}), encoding="utf-8")
    second = start(tmp_path)
    try:
        assert rows(second)[0][0] == "installed"
    finally:
        second.shutdown()


# ------------------------------------------------------------------ полный путь через контекст
def test_full_offline_update_through_context(ctx, tmp_path):
    _, public, app, manifest = make_env(tmp_path)
    updater = make_updater(ctx, tmp_path, public, app)
    prepared = updater.prepare(updater.check(FileSource(manifest)))
    assert updater.install(prepared).status == "installed"
    assert (app / "__main__.py").read_text(encoding="utf-8") == "new"
    assert [r[0] for r in rows(ctx)] == ["verified", "installed"]


def test_failed_check_is_recorded_in_update_audit(ctx, tmp_path):
    _, public, app, manifest = make_env(tmp_path)
    manifest.write_text(manifest.read_text(encoding="utf-8").replace('"1.3.0"', '"9.9.9"', 1), encoding="utf-8")
    updater = make_updater(ctx, tmp_path, public, app)
    with pytest.raises(EcpError):
        updater.check(FileSource(manifest))
    assert [r[0] for r in rows(ctx)] == ["failed"]


# ------------------------------------------------------------------ защита входом
def test_updates_require_login(tmp_path):
    context = start(tmp_path, require_auth=True)
    try:
        _, public, app, manifest = make_env(tmp_path)
        updater = make_updater(context, tmp_path, public, app)
        with pytest.raises(AuthError, match="требуется вход"):
            updater.check(FileSource(manifest))
        assert (app / "__main__.py").read_text(encoding="utf-8") == "old"
        context.register("alice", PW, PW)
        context.login("alice", PW)
        prepared = updater.prepare(updater.check(FileSource(manifest)))
        context.logout()
        with pytest.raises(AuthError, match="требуется вход"):
            updater.install(prepared)  # после выхода замена файлов невозможна
        assert (app / "__main__.py").read_text(encoding="utf-8") == "old"
    finally:
        context.shutdown()


# ------------------------------------------------------------------ отдельный процесс установки
def run_helper(tmp_path, health_code, marker):
    app, staging, backup = tmp_path / "app", tmp_path / "app.staging", tmp_path / "app.backup"
    app.mkdir()
    (app / "v.txt").write_text("old")
    staging.mkdir()
    (staging / "v.txt").write_text("new")
    result = tmp_path / "result.json"
    health = [sys.executable, "-c", f"import sys; sys.exit({health_code})"]
    launch = [sys.executable, "-c", f"open(r'{marker}', 'w').write('started')"]
    code = subprocess.run([sys.executable, installer.__file__, "--app", str(app), "--staging", str(staging),
                           "--backup", str(backup), "--result", str(result), "--from", "1.2.0", "--to", "1.3.0",
                           "--health", json.dumps(health), "--launch", json.dumps(launch)], timeout=60).returncode
    for _ in range(50):  # перезапуск приложения идёт асинхронно
        if marker.exists():
            break
        time.sleep(0.1)
    return code, app, backup, json.loads(result.read_text(encoding="utf-8"))


def test_installer_process_success(tmp_path):
    marker = tmp_path / "started.flag"
    code, app, backup, res = run_helper(tmp_path, 0, marker)
    assert code == 0 and res["status"] == "installed" and res["to_version"] == "1.3.0"
    assert (app / "v.txt").read_text() == "new" and (backup / "v.txt").read_text() == "old"
    assert marker.read_text() == "started"  # приложение перезапущено


def test_installer_process_rolls_back_when_new_version_fails_to_start(tmp_path):
    marker = tmp_path / "started.flag"
    code, app, backup, res = run_helper(tmp_path, 3, marker)
    assert code == 1 and res["status"] == "rolled_back" and "проверку запуска" in res["error"]
    assert (app / "v.txt").read_text() == "old" and not backup.exists()
    assert marker.read_text() == "started"  # после отката запускается прежняя версия


def test_launch_installer_end_to_end_then_ingest(ctx, tmp_path):
    _, public, app, manifest = make_env(tmp_path)
    updater = make_updater(ctx, tmp_path, public, app)
    prepared = updater.prepare(updater.check(FileSource(manifest)))
    marker = tmp_path / "started.flag"
    updater.launch_installer(prepared, 0, ctx.update_result_path, [sys.executable, "-c", "pass"],
                             [sys.executable, "-c", f"open(r'{marker}', 'w').write('x')"])
    for _ in range(100):
        if ctx.update_result_path.exists() and marker.exists():
            break
        time.sleep(0.1)
    assert (app / "__main__.py").read_text(encoding="utf-8") == "new"
    ctx.ingest_update_result()
    assert [r[0] for r in rows(ctx)] == ["verified", "installed"]


# ------------------------------------------------------------------ сборщик релиза
def test_keygen_embeds_public_key_and_refuses_overwrite(tmp_path):
    pub_file = tmp_path / "pubkey.py"
    pub_file.write_text('UPDATE_PUBLIC_KEY_B64 = ""\n', encoding="utf-8")
    key_path = tmp_path / "keys" / "update_signing.key"
    public = build_update.keygen(key_path, pub_file)
    import base64
    assert f'"{base64.b64encode(public).decode()}"' in pub_file.read_text(encoding="utf-8")
    assert len(build_update.load_private_key(key_path)) == 32
    with pytest.raises(EcpError, match="уже существует"):
        build_update.keygen(key_path, pub_file)


def test_built_release_verifies_with_generated_key(tmp_path):
    private, public, app, manifest = make_env(tmp_path)
    parsed = release.verify_manifest(manifest.read_bytes(), (manifest.parent / "manifest.sig").read_bytes(), public)
    package = manifest.parent / parsed.package_url
    assert parsed.package_size == package.stat().st_size and parsed.os == "windows"
    other = keypair()[1]
    with pytest.raises(EcpError):
        release.verify_manifest(manifest.read_bytes(), None, other)


def test_build_package_rejects_bad_input(tmp_path):
    private, _ = keypair()
    with pytest.raises(EcpError, match="пуст"):
        build_update.build_package(tmp_path / "nothing", tmp_path / "out", "1.0.0", "1.0.0", private, installed=INSTALLED)
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "a.txt").write_text("x")
    with pytest.raises(ValueError):
        build_update.build_package(tmp_path / "p", tmp_path / "out", "1.0", "1.0.0", private, installed=INSTALLED)


def test_cli_package_and_errors(tmp_path):
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "a.txt").write_text("x")
    assert build_update.main(["package", "--version", "1.0.0", "--min-supported", "1.0.0", "--source", str(payload),
                              "--out", str(tmp_path / "o"), "--key", str(tmp_path / "missing.key")]) == 1
