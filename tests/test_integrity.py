"""Целостность и подлинность ПО: подписанный манифест (СТБ 34.101.31 + СТБ 34.101.45)."""
import re
from datetime import datetime

import pytest

import ecp
from ecp import manifest, version
from ecp.cryptoif import default_crypto
from ecp.errors import EcpError


@pytest.fixture()
def pkg(tmp_path):
    base = tmp_path / "pkg"
    (base / "sub").mkdir(parents=True)
    (base / "__pycache__").mkdir()
    (base / "a.py").write_text("print('a')\n", encoding="utf-8")
    (base / "sub" / "b.py").write_text("print('b')\n", encoding="utf-8")
    (base / "core.pyd").write_bytes(b"\x00\x01\x02binary")
    (base / "notes.txt").write_text("не входит", encoding="utf-8")
    (base / "__pycache__" / "x.py").write_text("кэш", encoding="utf-8")
    return base


@pytest.fixture()
def released(pkg, tmp_path):
    keypair = ecp.generate_keypair()
    manifest.init_developer_key(tmp_path / "keys", base=pkg, keypair=keypair)
    manifest.release(keypair[0], base=pkg, now=datetime(2026, 10, 14, 14, 32, 0))
    return pkg


def test_compute_selects_program_files(pkg):
    files = manifest.compute(pkg)
    assert sorted(files) == ["a.py", "core.pyd", "sub/b.py"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in files.values())


def test_absent_manifest_is_development_mode(pkg):
    assert manifest.check(pkg).status == "absent"


def test_release_and_check_ok(released):
    rep = manifest.check(released)
    assert rep.status == "ok" and rep.authentic is True
    assert rep.version == version.VERSION
    assert rep.build_date == "2026-10-14 14:32:00"
    assert re.fullmatch(r"[0-9a-f]{64}", rep.fingerprint)
    assert {f.name for f in rep.files} == {"a.py", "core.pyd", "sub/b.py", "developer.pub"}
    assert all(f.ok for f in rep.files)


def test_build_date_format():
    text = manifest.build_manifest(now=datetime(2026, 1, 5, 9, 3, 7), base=None).decode("utf-8")
    assert '"build_date": "2026-01-05 09:03:07"' in text


def test_modified_file_detected_but_still_authentic(released):
    (released / "a.py").write_text("print('hacked')\n", encoding="utf-8")
    rep = manifest.check(released)
    assert rep.status == "failed" and rep.authentic is True
    bad = [f for f in rep.files if not f.ok]
    assert [(f.name, f.detail) for f in bad] == [("a.py", "хэш не совпал")]


def test_added_and_removed_files_detected(released):
    (released / "evil.py").write_text("x", encoding="utf-8")
    (released / "sub" / "b.py").unlink()
    rep = manifest.check(released)
    details = {f.name: f.detail for f in rep.files if not f.ok}
    assert details == {"evil.py": "файл не входит в эталон", "sub/b.py": "файл отсутствует"}
    assert rep.status == "failed"


def test_tampered_manifest_breaks_signature(released):
    path = released / manifest.MANIFEST_NAME
    path.write_bytes(path.read_bytes().replace(version.VERSION.encode(), b"9.9.9"))
    rep = manifest.check(released)
    assert rep.authentic is False and rep.status == "failed"
    assert any("ЭЦП манифеста неверна" in p for p in rep.auth_problems)


def test_wrong_signature(released):
    (released / manifest.SIGNATURE_NAME).write_bytes(b"\x01" * 48)
    rep = manifest.check(released)
    assert rep.authentic is False and rep.status == "failed"


def test_manifest_signed_by_other_key_is_rejected(released, tmp_path):
    other = ecp.generate_keypair()
    data = (released / manifest.MANIFEST_NAME).read_bytes()
    (released / manifest.SIGNATURE_NAME).write_bytes(ecp.sign(other[0], data))
    assert manifest.check(released).authentic is False


def test_missing_key_or_signature(released):
    (released / manifest.SIGNATURE_NAME).unlink()
    rep = manifest.check(released)
    assert rep.status == "failed" and rep.authentic is False
    assert any("MANIFEST.sig" in p for p in rep.auth_problems)
    (released / manifest.PUBKEY_NAME).unlink()
    rep = manifest.check(released)
    assert any("developer.pub" in p for p in rep.auth_problems)


def test_broken_manifest_json(released):
    (released / manifest.MANIFEST_NAME).write_bytes(b"{not json")
    rep = manifest.check(released)
    assert rep.status == "failed" and "манифест повреждён" in rep.problems


def test_release_requires_matching_key(pkg, tmp_path):
    keypair = ecp.generate_keypair()
    manifest.init_developer_key(tmp_path / "keys", base=pkg, keypair=keypair)
    with pytest.raises(EcpError, match="не соответствует"):
        manifest.release(ecp.generate_keypair()[0], base=pkg)


def test_release_requires_public_key(pkg):
    with pytest.raises(EcpError, match="developer.pub"):
        manifest.release(ecp.generate_keypair()[0], base=pkg)


def test_developer_key_is_not_overwritten(pkg, tmp_path):
    manifest.init_developer_key(tmp_path / "keys", base=pkg, keypair=ecp.generate_keypair())
    with pytest.raises(EcpError, match="уже существуют"):
        manifest.init_developer_key(tmp_path / "keys", base=pkg, keypair=ecp.generate_keypair())


def test_real_package_is_listed():
    files = manifest.compute()
    assert "service.py" in files and "manifest.py" in files and "gui/app.py" in files


def test_version_format():
    assert version.is_semver(version.VERSION)
    assert version.is_semver("1.12.0")
    for bad in ("1.2", "1.2.3.4", "01.2.3", "v1.2.3", "1.2.x", ""):
        assert not version.is_semver(bad)
