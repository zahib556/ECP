"""ПЗ-6, часть 3.2. Функциональные НЕГАТИВНЫЕ тесты: пустые, неверные, недопустимые данные -> отказ, а не падение.

Related to #N2.
"""
import zipfile
from datetime import timezone

import pytest

from ecp import asn1, config, x509
from ecp.auth import AuthError, AuthService, passwords, tokens
from ecp.auth.device import is_valid_device_id
from ecp.errors import EcpError
from ecp.update import release, sbom, staging, versions
from helpers import DEV, fake_cert, make_zip, manifest

PW = "Hunter2-secure"


# ------------------------------------------------------------------ ASN.1 / X.509
@pytest.mark.parametrize("bad", [
    b"", b"\x30", b"\x30\x05\x01", b"\x30\x80\x00\x00", b"\x1f\x01\x00", b"\x30\x85\x01\x01\x01\x01\x01",
    b"\x02\x01\x00\x00",
])
def test_asn1_rejects_malformed_der(bad):
    with pytest.raises(asn1.Asn1Error):
        asn1.parse(bad)


@pytest.mark.parametrize("dotted", ["", "1", "3.1", "1.40", "a.b", "1..2", "1.2.-3", "-1.2"])
def test_asn1_oid_rejects_invalid_identifiers(dotted):
    with pytest.raises(asn1.Asn1Error):
        asn1.oid(dotted)


@pytest.mark.parametrize("text", [b"261024123045", b"261324123045Z", b"261024253045Z", b"26102412304Z", b"abcdefghijkl"])
def test_asn1_utc_time_rejects_wrong_values(text):
    with pytest.raises(asn1.Asn1Error):
        asn1.parse(asn1.tlv(asn1.UTC_TIME, text)).as_time()


def test_asn1_wrong_type_access():
    with pytest.raises(asn1.Asn1Error):
        asn1.parse(asn1.utf8_string("x")).as_int()
    with pytest.raises(asn1.Asn1Error):
        asn1.parse(asn1.integer(1)).children()


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x30\x00", fake_cert()[:-1], fake_cert()[:20], b"\x30\x03\x02\x01\x01"])
def test_x509_rejects_garbage(data):
    with pytest.raises(EcpError):
        x509.parse_certificate(data)


def test_x509_rejects_wrong_key_length():
    with pytest.raises(EcpError, match="64 байта"):
        x509.parse_certificate(fake_cert(key=bytes(63)))


# ------------------------------------------------------------------ версии
@pytest.mark.parametrize("text", ["", "1", "1.0", "1.0.0.0", "01.0.0", "1.0.0-rc1", "v1.0.0", " 1.0.0", "1.0.0 ", "1.0.0\n",
                                  "1.0.\u0663", "1.-1.0", "a.b.c", None, 100, b"1.0.0"])
def test_versions_rejects_invalid(text):
    assert versions.is_valid(text) is False
    with pytest.raises(ValueError):
        versions.parse(text)


# ------------------------------------------------------------------ пароли и токены
def test_password_policy_rejects_weak_passwords():
    assert passwords.policy_problems("")                  # пусто
    assert passwords.policy_problems("short1")            # короче 8
    assert passwords.policy_problems("password")          # из списка популярных
    assert passwords.policy_problems("aaaaaaaaaa")        # <= 3 разных символа
    assert passwords.policy_problems("onlyletters")       # один класс символов


@pytest.mark.parametrize("stored", ["", "x", "a$b", "a$b$c$d", "md5$300000$00", "pbkdf2_sha256$100$00",
                                    "pbkdf2_sha256$abc$00", "pbkdf2_sha256$200000$é"])
def test_verify_password_returns_false_on_malformed_record(stored):
    assert passwords.verify_password(PW, "00" * 16, stored) is False


def test_hash_password_rejects_low_iteration_count():
    with pytest.raises(ValueError):
        passwords.hash_password(PW, "00" * 16, 199_999)


KEY = b"k" * 32


@pytest.mark.parametrize("token", ["", "abc", "a.b", "a.b.c.d", None, 123, "é.é.é", "x" * 5000])
def test_token_rejects_malformed(token):
    with pytest.raises(tokens.TokenError):
        tokens.decode(token, KEY, now=0)


def test_token_wrong_key_expired_and_tampered():
    token = tokens.encode({"exp": 100}, KEY)
    with pytest.raises(tokens.TokenError):
        tokens.decode(token, b"x" * 32, now=0)
    with pytest.raises(tokens.TokenExpired):
        tokens.decode(token, KEY, now=100)
    head, payload, sig = token.split(".")
    with pytest.raises(tokens.TokenError):
        tokens.decode(f"{head}.{payload[:-1]}A.{sig}", KEY, now=0)


# ------------------------------------------------------------------ конфигурация
@pytest.mark.parametrize("text", ["", None, "d", "30", "30x", "-5d", "1.5d", "0d", "0h", "3651d", "99999999999d"])
def test_parse_period_rejects(text):
    with pytest.raises(ValueError):
        config.parse_period(text)


@pytest.mark.parametrize("text", ["", None, "MB", "100", "100TB", "-1MB", "0KB", "10241MB", "11GB"])
def test_parse_size_rejects(text):
    with pytest.raises(ValueError):
        config.parse_size(text)


@pytest.mark.parametrize("section, name, value", [
    ("logging", "log_format", "XML"), ("logging", "log_path", ""), ("logging", "log_path", "dir/"),
    ("logging", "unknown", "1"), ("crypto", "hashing", "md5"), ("crypto", "encryption", "aes"),
    ("other", "x", "y"),
])
def test_check_param_reports_error(section, name, value):
    assert config.check_param(section, name, value)


def test_broken_config_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "config.ini"
    path.write_bytes(b"\xff\xfe\x00garbage[[[")
    result = config.load(path)
    assert result.problems and config.validate(result.config) == []
    with pytest.raises(EcpError):
        config.read_strict(path)


# ------------------------------------------------------------------ манифест, SBOM, пакет
@pytest.mark.parametrize("change", [
    {"version": "1.3"}, {"version": 1}, {"min_supported": "2.0.0"}, {"release_date": "2026-10-23"},
    {"release_date": "2026-02-30T10:00:00Z"}, {"os": "amiga"}, {"arch": "mips"}, {"package_size": 0},
    {"package_size": -1}, {"package_size": True}, {"package_size": "1024"}, {"package_sha256": "A" * 64},
    {"package_sha256": "a" * 63}, {"package_sha256": "a" * 64 + "\n"}, {"critical": "yes"}, {"package_url": 5},
    {"sbom": {"format": "SPDX-2.3", "url": "s", "sha256": "b" * 64}}, {"sbom": "x"}, {"sbom": {}},
])
def test_manifest_rejects_invalid_field(change):
    with pytest.raises(release.ManifestError):
        release.validate(manifest(**change))


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b"{", b'{"a":1,"a":2}', b"\xff\xfe"])
def test_manifest_json_rejects(raw):
    with pytest.raises(release.ManifestError):
        release.load_json(raw)


def test_manifest_json_rejects_oversized():
    # размер строим внутри теста: длинное значение в parametrize попадает в id теста и ломает Windows
    with pytest.raises(release.ManifestError):
        release.load_json(b"x" * (release.MAX_MANIFEST_BYTES + 1))


def test_manifest_without_signature_is_refused():
    import json
    with pytest.raises(release.SignatureError):
        release.verify_manifest(json.dumps(manifest()).encode(), None, bytes(32))


def _bom(**over):
    import json
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"version": "1.3.0"}},
           "components": [{"name": "PySide6", "version": "6.7.0"}, {"name": "cryptography", "version": "42.0.0"}]}
    bom.update(over)
    return json.dumps(bom).encode()


@pytest.mark.parametrize("data", [
    b"not json", b"[]", _bom(bomFormat="SPDX"), _bom(specVersion="1.4"), _bom(metadata=None),
    _bom(metadata={"component": [1]}), _bom(metadata={"component": {"version": "9.9.9"}}),
    _bom(components="x"), _bom(components=[{"name": "PySide6", "version": "6"}]),
    _bom(components=[{"name": "PySide6", "version": "6"}, {"name": "pyside6", "version": "6"},
                     {"name": "cryptography", "version": "1"}]),
    _bom(components=[{"name": "PySide6"}, {"name": "cryptography", "version": "1"}]),
    _bom(components=[{"name": "PySide6", "version": "6", "purl": "pkg:pypi/other@6"},
                     {"name": "cryptography", "version": "1"}]),
])
def test_sbom_rejects_invalid(data):
    with pytest.raises(sbom.SbomMismatch):
        sbom.check(data, sbom.sha256_hex(data), "1.3.0")


def test_sbom_hash_mismatch():
    data = _bom()
    with pytest.raises(sbom.SbomMismatch, match="SHA-256"):
        sbom.check(data, "0" * 64, "1.3.0")


@pytest.mark.parametrize("name", ["../evil.py", "/abs.py", "C:/win.py", "a/../../b.py", "a\\..\\..\\b.py"])
def test_package_rejects_zip_slip_and_absolute_paths(tmp_path, name):
    pkg = tmp_path / "p.zip"
    make_zip({name: "x"}, pkg)
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "out")
    assert not (tmp_path / "evil.py").exists()


def test_package_rejects_non_zip_empty_duplicates_and_corrupt_crc(tmp_path):
    pkg = tmp_path / "p.zip"
    pkg.write_bytes(b"not a zip")
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "o1")
    make_zip({"manifest.json": "{}"}, pkg)                       # только служебные файлы
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "o2")
    make_zip({"a/File.py": "1", "a/file.py": "2"}, pkg)          # одинаковые имена с точностью до регистра
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "o3")
    data = bytearray(make_zip({"a.py": "x" * 100}, compression=zipfile.ZIP_STORED))
    data[data.index(b"x" * 100) + 5] ^= 0xFF                      # порча данных -> неверная CRC-32
    pkg.write_bytes(bytes(data))
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "o4")


# ------------------------------------------------------------------ идентификатор устройства и вход
@pytest.mark.parametrize("value", [None, "", "abc", "A" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n", "g" * 64, 5])
def test_device_id_rejects_invalid(value):
    assert is_valid_device_id(value) is False


@pytest.fixture()
def svc(tmp_path):
    service = AuthService(tmp_path / "users.db", tmp_path / "auth.key")
    yield service
    service.close()


@pytest.mark.parametrize("login", ["", "  ", "ab", "a" * 33, "иван", "a b c", "a@b.ru", "name;drop", None])
def test_register_rejects_bad_login(svc, login):
    with pytest.raises(AuthError):
        svc.register(login, PW, DEV)


@pytest.mark.parametrize("password", ["", "short1", "password", "aaaaaaaaaaaa", "x" * 129 + "1"])
def test_register_rejects_bad_password(svc, password):
    with pytest.raises(AuthError):
        svc.register("student", password, DEV)


def test_register_rejects_bad_device_and_duplicate(svc):
    with pytest.raises(AuthError):
        svc.register("student", PW, "not-a-device")
    svc.register("student", PW, DEV)
    with pytest.raises(AuthError, match="уже существует"):
        svc.register("STUDENT", PW, DEV)


@pytest.mark.parametrize("login, password, device", [
    ("student", "wrong-Pass1", DEV), ("nobody", PW, DEV), ("", PW, DEV), ("student", "", DEV),
    (None, PW, DEV), ("student", PW, "bad"), ("student", PW, "b2" * 32),
])
def test_login_rejects(svc, login, password, device):
    svc.register("student", PW, DEV)
    with pytest.raises(AuthError):
        svc.login(login, password, device)


@pytest.mark.parametrize("token", ["", "x.y.z", None, "a" * 10])
def test_me_and_logout_reject_garbage_token(svc, token):
    with pytest.raises(AuthError):
        svc.me(token, DEV)
    with pytest.raises(AuthError):
        svc.logout(token)
