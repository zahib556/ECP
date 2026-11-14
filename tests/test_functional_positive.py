"""ПЗ-6, часть 3.1. Функциональные ПОЗИТИВНЫЕ тесты: корректные входные данные -> корректный результат.

Криптоядро (Rust) не требуется: проверяются чистые Python-модули. Related to #N1.
"""
from datetime import datetime, timedelta, timezone

import pytest

from ecp import asn1, audit, config, logview, x509
from ecp.auth import AuthService, passwords, tokens
from ecp.update import release, sbom, staging, versions
from helpers import DEV, fake_cert, make_zip, manifest

PW = "Hunter2-secure"


# ------------------------------------------------------------------ ASN.1
def test_asn1_sequence_roundtrip():
    der = asn1.seq(asn1.oid("1.2.840.113549.1.1.1"), asn1.integer(65537), asn1.utf8_string("Привет"))
    oid, num, text = asn1.parse(der).children()
    assert (oid.as_oid(), num.as_int(), text.content.decode()) == ("1.2.840.113549.1.1.1", 65537, "Привет")


def test_asn1_time_roundtrip():
    dt = datetime(2026, 10, 24, 12, 30, 45, tzinfo=timezone.utc)
    assert asn1.parse(asn1.time_choice(dt)).as_time() == dt
    assert asn1.parse(asn1.generalized_time(dt)).as_time() == dt


# ------------------------------------------------------------------ X.509
def test_x509_parse_certificate_fields():
    cert = x509.parse_certificate(fake_cert("Иванов И. И."))
    assert cert.subject_cn == "Иванов И. И."
    assert cert.serial == 123456789
    assert cert.public_key == bytes(range(64))
    assert cert.sig_alg == x509.OID_BIGN_WITH_HBELT
    assert cert.key_purposes == [x509.OID_KP_TIME_STAMPING]
    assert cert.not_before < cert.not_after


# ------------------------------------------------------------------ версии
@pytest.mark.parametrize("text, expected", [("0.0.0", (0, 0, 0)), ("1.2.3", (1, 2, 3)), ("10.20.30", (10, 20, 30))])
def test_versions_parse(text, expected):
    assert versions.parse(text) == expected
    assert versions.is_valid(text)


def test_versions_compare_numerically_not_as_strings():
    assert versions.parse("1.10.0") > versions.parse("1.9.0")


# ------------------------------------------------------------------ пароли и токены
def test_password_hash_and_verify():
    salt = passwords.new_salt()
    stored = passwords.hash_password(PW, salt)
    assert stored.startswith("pbkdf2_sha256$310000$")
    assert passwords.verify_password(PW, salt, stored) is True


def test_password_policy_accepts_good_password_and_rates_it():
    assert passwords.policy_problems(PW) == []
    score, label = passwords.strength("Zx9#mK2$pLq7!vR4")
    assert score == 4 and label == "надёжный"


def test_token_encode_decode():
    key = b"k" * 32
    token = tokens.encode({"sub": 7, "exp": 2_000_000_000}, key)
    assert tokens.decode(token, key, now=1_900_000_000) == {"sub": 7, "exp": 2_000_000_000}


# ------------------------------------------------------------------ конфигурация
def test_config_parsers_accept_valid_values():
    assert config.parse_period("30d") == timedelta(days=30)
    assert config.parse_period("12h") == timedelta(hours=12)
    assert config.parse_size("100MB") == 100 * 1024 ** 2
    assert config.format_size(config.parse_size("2GB")) == "2GB"


def test_config_default_file_is_created_and_valid(tmp_path):
    result = config.load(tmp_path / "config.ini")
    assert result.created and result.problems == []
    assert config.validate(result.config) == []


# ------------------------------------------------------------------ обновление ПО
def test_manifest_valid_is_accepted():
    m = release.validate(manifest())
    assert (m.version, m.os, m.arch, m.package_size, m.critical) == ("1.3.0", "windows", "x64", 1024, False)


def test_manifest_canonical_form_ignores_signature_and_key_order():
    a = release.canonical_bytes({"b": 1, "a": 2, "signature": "x"})
    b = release.canonical_bytes({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_sbom_generated_is_accepted():
    data = sbom.generate("ecp", "1.3.0", installed={"PySide6": "6.7.0", "cryptography": "42.0.0"})
    found = sbom.check(data, sbom.sha256_hex(data), "1.3.0")
    assert found == {"pyside6": "6.7.0", "cryptography": "42.0.0"}


def test_package_extracts_and_skips_service_files(tmp_path):
    pkg = tmp_path / "p.zip"
    make_zip({"ecp/main.py": "print(1)", "manifest.json": "{}", "manifest.sig": "x"}, pkg)
    assert staging.extract(pkg, tmp_path / "out") == 1
    assert (tmp_path / "out" / "ecp" / "main.py").read_text() == "print(1)"
    assert not (tmp_path / "out" / "manifest.json").exists()


# ------------------------------------------------------------------ журнал
def test_audit_line_roundtrip_in_all_formats():
    ev = audit.AuditEvent(event_datetime="2026-10-24 10:00:00.000", source_name="ecp.sign", description="файл a=b|c",
                          level="warning", status="success", action="create", object="a.txt")
    for fmt in ("JSON", "CSV", "CEF"):
        back = audit.parse_line(audit.format_line(ev, fmt))
        assert back is not None and back.description == ev.description and back.level == "warning", fmt


def test_logview_alert_for_three_failed_verifications_in_a_row():
    def ev(status):
        return audit.AuditEvent(event_datetime="2026-10-24 10:00:00.000", source_name="ecp.verify", status=status)
    summary = logview.analyze([ev("failure")] * 3)
    assert any("Серия неуспешных проверок" in a for a in summary.alerts)


# ------------------------------------------------------------------ аутентификация
def test_auth_register_login_me_logout(tmp_path):
    svc = AuthService(tmp_path / "users.db", tmp_path / "auth.key")
    reg = svc.register("Student_01", PW, DEV)
    assert reg.login == "student_01" and len(reg.reset_code) == 14
    session = svc.login("STUDENT_01", PW, DEV)          # логин нечувствителен к регистру
    assert svc.me(session.token, DEV).login == "student_01"
    svc.logout(session.token)
    svc.close()
