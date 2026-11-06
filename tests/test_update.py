"""Обновление ПО (вариант Б, offline): подпись, SHA-256, SBOM, staging, атомарная замена, откат."""
import base64
import hashlib
import importlib.util
import json
import os
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ecp.errors import EcpError
from ecp.update import FileSource, Updater, UpdateError, installer, release, sbom, staging, versions
from ecp.update.updater import current_arch, current_os

_spec = importlib.util.spec_from_file_location("build_update", Path(__file__).parent.parent / "tools" / "build_update.py")
build_update = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_update)

INSTALLED = {"PySide6": "6.7.0", "cryptography": "42.0.5"}


def new_key():
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw, pub


@pytest.fixture()
def world(tmp_path):
    private, public = new_key()
    app = tmp_path / "install" / "ecp"
    app.mkdir(parents=True)
    (app / "__main__.py").write_text("old", encoding="utf-8")
    (app / "data.txt").write_text("old-data", encoding="utf-8")
    payload = tmp_path / "payload"
    (payload / "sub").mkdir(parents=True)
    (payload / "__main__.py").write_text("new", encoding="utf-8")
    (payload / "sub" / "new.txt").write_text("new-data", encoding="utf-8")
    events = []
    updater = Updater(app, "1.2.0", public, recorder=lambda *a: events.append(a), os_name="windows", arch="x64",
                      entry_files=("__main__.py",))
    return SimpleNamespace(tmp=tmp_path, private=private, public=public, app=app, payload=payload, events=events,
                           updater=updater, out=tmp_path / "release")


def build(w, version="1.3.0", min_supported="1.0.0", **kw):
    return build_update.build_package(w.payload, w.out, version, min_supported, kw.pop("private", w.private),
                                      os_name="windows", arch="x64", installed=INSTALLED, **kw)


def craft(w, entries, sbom_bytes=None, sbom_declared=None, version="1.3.0", min_supported="1.0.0", mutate=None):
    """Произвольный подписанный пакет: entries - {имя: байты | ZipInfo-кортеж}, SBOM можно испортить."""
    good = sbom.generate("ecp", version, installed=INSTALLED)
    body = sbom_bytes if sbom_bytes is not None else good
    w.out.mkdir(parents=True, exist_ok=True)
    package = w.out / "package.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            if isinstance(data, tuple):
                z.writestr(data[0], data[1])
            else:
                z.writestr(name, data)
        if body is not False:
            z.writestr("sbom.json", body)
    manifest = {
        "version": version, "min_supported": min_supported, "release_date": "2026-10-23T10:00:00Z",
        "os": "windows", "arch": "x64", "package_url": "package.zip", "package_size": package.stat().st_size,
        "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        "sbom": {"format": "CycloneDX-1.5", "url": "sbom.json", "sha256": sbom.sha256_hex(sbom_declared or good)},
        "critical": False,
    }
    if mutate:
        mutate(manifest)
    manifest["signature"] = release.sign_manifest(manifest, w.private)
    path = w.out / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    (w.out / "manifest.sig").write_text(manifest["signature"], encoding="ascii")
    return path


def run_prepare(w, manifest_path):
    plan = w.updater.check(FileSource(manifest_path))
    return w.updater.prepare(plan)


def statuses(w):
    return [e[0] for e in w.events]


def untouched(w):
    assert (w.app / "__main__.py").read_text(encoding="utf-8") == "old"
    assert not w.updater.staging_dir.exists()


# ------------------------------------------------------------------ успешное обновление
def test_update_success(world):
    path = build(world)
    prepared = run_prepare(world, path)
    assert (prepared.staging / "sub" / "new.txt").read_text(encoding="utf-8") == "new-data"
    assert (world.app / "__main__.py").read_text(encoding="utf-8") == "old"  # до замены ничего не тронуто
    result = world.updater.install(prepared, health_check=lambda app: (app / "__main__.py").read_text() == "new")
    assert result.status == "installed"
    assert (world.app / "__main__.py").read_text(encoding="utf-8") == "new"
    assert (world.app / "sbom.json").is_file() and not (world.app / "manifest.json").exists()
    assert (world.updater.backup_dir / "data.txt").read_text(encoding="utf-8") == "old-data"  # прежняя версия в backup
    assert not world.updater.staging_dir.exists()
    assert statuses(world) == ["verified", "installed"]
    assert world.events[-1][1:3] == ("1.2.0", "1.3.0")


def test_second_update_replaces_old_backup(world):
    run = lambda v: world.updater.install(run_prepare(world, build(world, version=v)))
    assert run("1.3.0").status == "installed"
    world.updater.current_version = "1.3.0"
    assert run("1.4.0").status == "installed"
    assert (world.app / "__main__.py").read_text(encoding="utf-8") == "new"


# ------------------------------------------------------------------ подпись манифеста
def test_tampered_manifest_rejected(world):
    path = build(world)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["version"] = "9.9.9"
    path.write_text(json.dumps(data), encoding="utf-8")
    (path.parent / "manifest.sig").unlink()
    with pytest.raises(UpdateError, match="подпись"):
        world.updater.check(FileSource(path))
    assert statuses(world) == ["failed"]
    untouched(world)


def test_attacker_swaps_package_and_hash_but_cannot_resign(world):
    path = build(world)
    data = json.loads(path.read_text(encoding="utf-8"))
    evil = path.parent / "evil.zip"
    evil.write_bytes(b"PK-evil")
    data.update(package_url="evil.zip", package_size=evil.stat().st_size,
                package_sha256=hashlib.sha256(evil.read_bytes()).hexdigest())
    path.write_text(json.dumps(data), encoding="utf-8")  # подпись осталась прежней
    with pytest.raises(UpdateError, match="подпись"):
        world.updater.check(FileSource(path))


def test_signature_by_foreign_key_rejected(world):
    other_private, _ = new_key()
    path = build(world, private=other_private)
    with pytest.raises(UpdateError, match="подпись"):
        world.updater.check(FileSource(path))


def test_unsigned_manifest_and_sig_mismatch_rejected(world):
    path = build(world)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["signature"]
    path.write_text(json.dumps(data), encoding="utf-8")
    (path.parent / "manifest.sig").unlink()
    with pytest.raises(UpdateError, match="не подписан"):
        world.updater.check(FileSource(path))
    path = build(world)
    (path.parent / "manifest.sig").write_text(base64.b64encode(b"x" * 64).decode(), encoding="ascii")
    with pytest.raises(UpdateError, match="не совпадает"):
        world.updater.check(FileSource(path))


def test_signature_only_in_sig_file_is_accepted(world):
    path = build(world)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["signature"]
    path.write_text(json.dumps(data), encoding="utf-8")
    assert world.updater.check(FileSource(path)).manifest.version == "1.3.0"


def test_no_embedded_public_key_blocks_updates(world):
    updater = Updater(world.app, "1.2.0", None, os_name="windows", arch="x64")
    with pytest.raises(UpdateError, match="ключ проверки обновлений не задан"):
        updater.check(FileSource(build(world)))


# ------------------------------------------------------------------ SHA-256 пакета
def test_replaced_package_rejected_by_sha256(world):
    path = build(world)
    package = path.parent / "ecp-1.3.0-windows-x64.zip"
    raw = bytearray(package.read_bytes())
    raw[len(raw) // 2] ^= 0xFF  # тот же размер, другое содержимое
    package.write_bytes(bytes(raw))
    with pytest.raises(UpdateError, match="SHA-256 пакета"):
        run_prepare(world, path)
    assert statuses(world) == ["verified", "failed"]
    untouched(world)


def test_package_size_mismatch_rejected(world):
    path = build(world)
    (path.parent / "ecp-1.3.0-windows-x64.zip").write_bytes(b"short")
    with pytest.raises(UpdateError, match="размер пакета"):
        run_prepare(world, path)
    untouched(world)


def test_missing_package_rejected(world):
    path = build(world)
    (path.parent / "ecp-1.3.0-windows-x64.zip").unlink()
    with pytest.raises(UpdateError, match="пакет обновления не найден"):
        run_prepare(world, path)


def test_package_url_cannot_escape_manifest_folder(world):
    path = craft(world, {"__main__.py": b"new"}, mutate=lambda m: m.update(package_url="../../etc/passwd"))
    # путь из манифеста обрезается до имени файла, берётся package.zip рядом с манифестом
    assert FileSource(path).open_package(release.validate(json.loads(path.read_text()))).name == "package.zip"


# ------------------------------------------------------------------ SBOM
def test_sbom_problems_block_install_with_sbom_mismatch_status(world):
    good = sbom.generate("ecp", "1.3.0", installed=INSTALLED)
    bom = json.loads(good)
    cases = {
        "битый JSON": b"{not json",
        "не CycloneDX": json.dumps({"bomFormat": "SPDX"}).encode(),
        "нет обязательной зависимости": json.dumps({**bom, "components": bom["components"][:1]}).encode(),
        "версия приложения": json.dumps({**bom, "metadata": {"component": {"version": "0.0.1"}}}).encode(),
        "дубликат": json.dumps({**bom, "components": bom["components"] + bom["components"][:1]}).encode(),
        "purl": json.dumps({**bom, "components": [dict(bom["components"][0], purl="pkg:pypi/other@1")] + bom["components"][1:]}).encode(),
        "без версии": json.dumps({**bom, "components": [{"name": "PySide6"}] + bom["components"][1:]}).encode(),
    }
    for name, bad in cases.items():
        world.events.clear()
        path = craft(world, {"__main__.py": b"new"}, sbom_bytes=bad, sbom_declared=bad)
        with pytest.raises(UpdateError) as err:
            run_prepare(world, path)
        assert err.value.status == "sbom_mismatch", name
        assert statuses(world) == ["verified", "sbom_mismatch"], name
        untouched(world)


def test_sbom_hash_mismatch_with_manifest(world):
    tampered = sbom.generate("ecp", "1.3.0", installed={"PySide6": "6.7.1", "cryptography": "42.0.5"})
    path = craft(world, {"__main__.py": b"new"}, sbom_bytes=tampered)  # в манифесте хэш настоящего SBOM
    with pytest.raises(UpdateError, match="SHA-256 SBOM") as err:
        run_prepare(world, path)
    assert err.value.status == "sbom_mismatch"
    untouched(world)


def test_package_without_sbom_rejected(world):
    path = craft(world, {"__main__.py": b"new"}, sbom_bytes=False)
    with pytest.raises(UpdateError, match="нет sbom.json") as err:
        run_prepare(world, path)
    assert err.value.status == "sbom_mismatch"


def test_sbom_name_normalization_and_roundtrip():
    data = sbom.generate("ecp", "1.0.0", ["PySide6", "cryptography"], INSTALLED)
    found = sbom.check(data, sbom.sha256_hex(data), "1.0.0", required=("pyside6", "Cryptography"))
    assert found == {"pyside6": "6.7.0", "cryptography": "42.0.5"}
    with pytest.raises(EcpError, match="не установлен"):
        sbom.generate("ecp", "1.0.0", ["no-such-package-xyz"])


# ------------------------------------------------------------------ откат при сбое установки
def test_failed_health_check_rolls_back(world):
    prepared = run_prepare(world, build(world))
    result = world.updater.install(prepared, health_check=lambda app: False)
    assert result.status == "rolled_back" and "проверку запуска" in result.error
    untouched(world)
    assert (world.app / "data.txt").read_text(encoding="utf-8") == "old-data"
    assert not world.updater.backup_dir.exists()
    assert not (world.app.parent / "ecp.broken").exists()
    assert statuses(world)[-1] == "rolled_back"


def test_crash_during_second_rename_rolls_back(world):
    prepared = run_prepare(world, build(world))
    real, calls = os.replace, []

    def flaky(src, dst):
        calls.append((src, dst))
        if len(calls) == 2:  # staging -> app
            raise OSError("обрыв питания")
        return real(src, dst)
    installer.os.replace = flaky
    try:
        result = world.updater.install(prepared)
    finally:
        installer.os.replace = real
    assert result.status == "rolled_back" and "обрыв питания" in result.error
    assert (world.app / "__main__.py").read_text(encoding="utf-8") == "old"


def test_busy_app_dir_leaves_everything_untouched(world):
    prepared = run_prepare(world, build(world))
    real = os.replace

    def locked(src, dst):
        raise PermissionError("файл занят процессом")
    installer.os.replace = locked
    try:
        result = world.updater.install(prepared)
    finally:
        installer.os.replace = real
    assert result.status == "failed" and "заняты" in result.error
    assert (world.app / "__main__.py").read_text(encoding="utf-8") == "old"
    assert not world.updater.backup_dir.exists()


def test_failed_rollback_reports_manual_recovery(world):
    prepared = run_prepare(world, build(world))
    real, calls = os.replace, []

    def broken(src, dst):
        calls.append(1)
        if len(calls) >= 2:
            raise OSError("диск недоступен")
        return real(src, dst)
    installer.os.replace = broken
    try:
        result = world.updater.install(prepared)
    finally:
        installer.os.replace = real
    assert result.status == "failed" and "вручную" in result.error
    assert (world.updater.backup_dir / "__main__.py").read_text(encoding="utf-8") == "old"  # данные целы


# ------------------------------------------------------------------ совместимость
def test_min_supported_above_current_blocks_update(world):
    path = build(world, min_supported="1.2.5")
    with pytest.raises(UpdateError, match="ручная установка"):
        world.updater.check(FileSource(path))
    assert statuses(world) == ["failed"]


def test_min_supported_equal_to_current_is_allowed(world):
    assert world.updater.check(FileSource(build(world, min_supported="1.2.0"))).manifest.version == "1.3.0"


def test_downgrade_and_same_version_forbidden(world):
    for version in ("1.2.0", "1.1.0"):
        with pytest.raises(UpdateError, match="понижение версии запрещено"):
            world.updater.check(FileSource(build(world, version=version, min_supported="1.0.0")))


def test_wrong_os_or_arch_blocked(world):
    path = build_update.build_package(world.payload, world.out, "1.3.0", "1.0.0", world.private, os_name="linux",
                                      arch="x64", installed=INSTALLED)
    with pytest.raises(UpdateError, match="linux/x64"):
        world.updater.check(FileSource(path))


def test_missing_entry_file_rejected(world):
    (world.payload / "__main__.py").unlink()
    with pytest.raises(UpdateError, match="обязательного файла"):
        run_prepare(world, build(world))
    untouched(world)


# ------------------------------------------------------------------ безопасная распаковка
def test_unsafe_archives_rejected(world):
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    bad = {
        "zip slip": {"../evil.txt": b"x"},
        "абсолютный путь": {"/etc/evil": b"x"},
        "обратные слеши": {"..\\..\\evil.txt": b"x"},
        "диск Windows": {"C:/evil.txt": b"x"},
        "символьная ссылка": {"link": (link, b"/etc/passwd")},
        "повтор имени в другом регистре": {"A.txt": b"1", "a.TXT": b"2"},
    }
    for name, entries in bad.items():
        world.events.clear()
        path = craft(world, entries)
        with pytest.raises(UpdateError, match="Ошибка"):
            run_prepare(world, path)
        assert not (world.tmp / "evil.txt").exists() and not (world.tmp / "install" / "evil.txt").exists(), name
        untouched(world)


def test_zip_bomb_by_declared_size_and_by_real_size(tmp_path):
    big = tmp_path / "big.zip"
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.bin", b"\0" * 5_000_000)
    with pytest.raises(EcpError, match="превышает допустимый"):
        staging.extract(big, tmp_path / "s1", limit=1_000_000)
    assert staging.extract(big, tmp_path / "s2") == 1


def test_manifest_files_in_package_are_not_installed_but_integrity_manifest_is(world):
    path = craft(world, {"__main__.py": b"new", "manifest.json": b"{}", "manifest.sig": b"x", "MANIFEST.json": b"{\"files\":{}}"})
    prepared = run_prepare(world, path)
    names = sorted(p.name for p in prepared.staging.iterdir())
    assert "manifest.json" not in names and "manifest.sig" not in names  # служебные файлы пропущены
    assert "MANIFEST.json" in names  # манифест целостности программы (другой регистр) сохранён
    assert (prepared.staging / "MANIFEST.json").read_text() == '{"files":{}}'
    assert not (prepared.staging / "manifest.sig").exists()


def test_not_a_zip_rejected(world):
    path = craft(world, {"__main__.py": b"x"})
    junk = b"this is not a zip"
    (path.parent / "package.zip").write_bytes(junk)
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(package_size=len(junk), package_sha256=hashlib.sha256(junk).hexdigest())
    data["signature"] = release.sign_manifest(data, world.private)
    path.write_text(json.dumps(data), encoding="utf-8")
    (path.parent / "manifest.sig").unlink()
    with pytest.raises(UpdateError, match="ZIP"):
        run_prepare(world, path)
    untouched(world)


# ------------------------------------------------------------------ формат манифеста
def test_manifest_field_validation():
    good = {"version": "1.3.0", "min_supported": "1.2.0", "release_date": "2026-10-23T10:00:00Z", "os": "windows",
            "arch": "x64", "package_url": "/updates/download/1.3.0", "package_size": 48213345,
            "package_sha256": "a" * 64, "sbom": {"format": "CycloneDX-1.5", "url": "/u", "sha256": "c" * 64},
            "critical": False}
    assert release.validate(good).package_size == 48213345
    changes = {"version": "1.3", "min_supported": "2.0.0", "release_date": "23.10.2026", "os": "plan9", "arch": "mips",
               "package_size": 0, "package_sha256": "XYZ", "critical": "no", "sbom": {"format": "SPDX", "sha256": "c" * 64}}
    for field, value in changes.items():
        with pytest.raises(release.ManifestError):
            release.validate(dict(good, **{field: value}))
    with pytest.raises(release.ManifestError):
        release.validate({k: v for k, v in good.items() if k != "version"})
    with pytest.raises(release.ManifestError):
        release.validate(dict(good, package_size=True))


def test_manifest_json_strictness():
    with pytest.raises(release.ManifestError, match="повторяющееся"):
        release.load_json(b'{"version":"1.0.0","version":"9.0.0"}')
    with pytest.raises(release.ManifestError):
        release.load_json(b"[]")
    with pytest.raises(release.ManifestError, match="слишком большой"):
        release.load_json(b" " * (release.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(release.ManifestError):
        release.load_json("не json".encode())


def test_versions():
    assert versions.parse("1.10.0") > versions.parse("1.9.9")
    assert not versions.is_valid("1.0") and not versions.is_valid("01.0.0") and not versions.is_valid(None)
    with pytest.raises(ValueError):
        versions.parse("abc")


def test_current_platform_names_are_valid():
    assert current_os() in release.OS_NAMES and current_arch() in release.ARCHES
