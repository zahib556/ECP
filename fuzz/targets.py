"""Цели фаззинга: функции проекта, принимающие внешние данные (парсеры и валидаторы).

Каждая цель - функция data: bytes -> None. Исключения из списка `allowed` считаются штатным отказом
на плохие данные; любое другое исключение, AssertionError свойства или зависание - дефект.
Только стандартная библиотека + сам проект (криптоядро не нужно).
"""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Tuple, Type

from ecp import asn1, audit, config, x509
from ecp.auth import device, passwords, tokens
from ecp.errors import EcpError
from ecp.update import release, sbom, staging, versions

KEY = bytes(range(32))
NOW = 1_800_000_000


@dataclass
class Target:
    name: str
    func: Callable[[bytes], None]
    allowed: Tuple[Type[BaseException], ...]
    seeds: List[bytes]
    tokens: List[bytes]  # словарь «интересных» фрагментов для мутатора


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------------ ASN.1
def _walk(node: asn1.Node, depth: int = 0) -> None:
    """Обходит дерево и вызывает все as_*: любой из них может получить произвольное содержимое."""
    for conv in (node.as_int, node.as_oid, node.as_bit_string, node.as_octets, node.as_bool, node.as_time):
        try:
            conv()
        except asn1.Asn1Error:
            pass
    if node.constructed and depth < 6:
        for child in node.children():
            _walk(child, depth + 1)


def fuzz_asn1_parse(data: bytes) -> None:
    for node in asn1.parse_all(data):
        _walk(node)


def fuzz_asn1_oid(data: bytes) -> None:
    """Свойство: если oid() принял строку, decode_oid() возвращает ту же строку."""
    arcs = [str(b - 128 if i % 3 else b * 7) for i, b in enumerate(data[:12])]
    dotted = ".".join(arcs)
    encoded = asn1.oid(dotted)
    assert asn1.decode_oid(asn1.parse(encoded).content) == dotted, f"oid({dotted!r}) не обратим"


def fuzz_asn1_roundtrip(data: bytes) -> None:
    """Свойство: integer / octet_string / utf8 / время кодируются и читаются без потерь."""
    n = int.from_bytes(data[:40], "big")
    assert asn1.parse(asn1.integer(n)).as_int() == n
    assert asn1.parse(asn1.octet_string(data)).as_octets() == data
    assert asn1.parse(asn1.tlv(0x04, data)).content == data
    year = 1000 + int.from_bytes(data[:2], "big") % 9000
    month, day = 1 + (data[2] if len(data) > 2 else 0) % 12, 1 + (data[3] if len(data) > 3 else 0) % 28
    dt = datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
    assert asn1.parse(asn1.time_choice(dt)).as_time() == dt


# ------------------------------------------------------------------ X.509
def _fake_cert(cn: str = "Тестовый владелец") -> bytes:
    name = x509.name_from_cn(cn)
    now = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    ext = asn1.seq(asn1.seq(asn1.oid(x509.OID_EXT_KEY_USAGE), asn1.boolean(True),
                            asn1.octet_string(asn1.seq(asn1.oid(x509.OID_KP_TIME_STAMPING)))))
    tbs = asn1.seq(
        asn1.explicit(0, asn1.integer(2)), asn1.integer(123456789),
        x509.algorithm_identifier(x509.OID_BIGN_WITH_HBELT), name,
        asn1.seq(asn1.time_choice(now), asn1.time_choice(datetime(2036, 10, 24, tzinfo=timezone.utc))),
        name, x509.public_key_info(bytes(range(64))), asn1.explicit(3, ext))
    return asn1.seq(tbs, x509.algorithm_identifier(x509.OID_BIGN_WITH_HBELT), asn1.bit_string(bytes(48)))


def fuzz_x509(data: bytes) -> None:
    x509.parse_certificate(data)


# ------------------------------------------------------------------ журнал
def _sample_event() -> audit.AuditEvent:
    return audit.AuditEvent(event_datetime="2026-10-24 10:00:00.000", source_name="ecp.sign", user_account="user",
                            source_ip="10.0.0.1", host_ip="10.0.0.2", description="Подписан файл a=b|c",
                            level="info", status="success", action="create", object="a.txt")


def fuzz_audit_line(data: bytes) -> None:
    audit.parse_line(_text(data))


# ------------------------------------------------------------------ конфигурация
def fuzz_config(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.ini"
        path.write_bytes(data)
        result = config.load(path)
        assert not config.validate(result.config), "load() вернул недопустимую конфигурацию"
        try:
            config.read_strict(path)
        except EcpError:
            pass


# ------------------------------------------------------------------ обновление
_MANIFEST = {
    "version": "1.3.0", "min_supported": "0.5.0", "release_date": "2026-10-23T10:00:00Z", "os": "windows",
    "arch": "x64", "package_url": "ecp-1.3.0-windows-x64.zip", "package_size": 1024,
    "package_sha256": "a" * 64, "sbom": {"format": "CycloneDX-1.5", "url": "sbom.json", "sha256": "b" * 64},
    "critical": False,
}


def fuzz_manifest(data: bytes) -> None:
    release.validate(release.load_json(data))


def _sbom_bytes() -> bytes:
    return sbom.generate("ecp", "1.3.0", installed={"PySide6": "6.7.0", "cryptography": "42.0.0"})


def fuzz_sbom(data: bytes) -> None:
    sbom.check(data, hashlib.sha256(data).hexdigest(), "1.3.0")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ecp/main.py", "print('hi')\n" * 20)
        zf.writestr("ecp/sub/data.bin", bytes(range(256)))
        zf.writestr("sbom.json", "{}")
    return buf.getvalue()


def fuzz_package(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "pkg.zip"
        pkg.write_bytes(data)
        staging.extract(pkg, Path(tmp) / "out", limit=1 << 20)


# ------------------------------------------------------------------ аутентификация
def fuzz_token(data: bytes) -> None:
    tokens.decode(_text(data), KEY, NOW)


def fuzz_semver(data: bytes) -> None:
    text = _text(data)
    ok = versions.is_valid(text)
    try:
        parsed = versions.parse(text)
    except ValueError:
        assert not ok
        return
    assert ok
    assert text == "%d.%d.%d" % parsed, f"{text!r} принята как версия, но не равна {parsed}"


def fuzz_hex_ids(data: bytes) -> None:
    text = _text(data)
    if device.is_valid_device_id(text):
        assert len(text) == 64 and text == text.lower() and text.isascii() and "\n" not in text


def fuzz_password_policy(data: bytes) -> None:
    pw = _text(data)
    passwords.policy_problems(pw)
    score, label = passwords.strength(pw)
    assert 0 <= score <= 4 and label == passwords.STRENGTH_LABELS[score]


def _all() -> List[Target]:
    ev = _sample_event()
    good_token = tokens.encode({"sub": 1, "login": "alice", "did": "a" * 64, "exp": NOW + 600}, KEY).encode()
    cfg_seed = config._render(config.default_config(Path("/tmp/ecp"))).encode("utf-8")
    sbom_seed = _sbom_bytes()
    return [
        Target("asn1_parse", fuzz_asn1_parse, (asn1.Asn1Error,),
               [_fake_cert(), asn1.seq(asn1.oid("1.2.840.113549.1.1.1"), asn1.null(), asn1.integer(65537),
                                       asn1.set_of([asn1.utf8_string("x")]), asn1.boolean(True))],
               [b"\x30", b"\x06", b"\x17", b"\x18", b"\x80", b"\x84\xff\xff\xff\xff", b"\x00", b"\xff", b"Z"]),
        Target("asn1_oid", fuzz_asn1_oid, (asn1.Asn1Error, ValueError), [b"\x01\x02\x03", bytes(range(1, 9))],
               [b"\x00", b"\x7f", b"\x80", b"\xff"]),
        Target("asn1_roundtrip", fuzz_asn1_roundtrip, (), [bytes(range(48)), b"\x00" * 12, b"\xff" * 40],
               [b"\x00", b"\xff", b"\x80"]),
        Target("x509", fuzz_x509, (EcpError,), [_fake_cert()], [b"\x30", b"\xa3", b"\xa0", b"\x03", b"\x06", b"\x81"]),
        Target("audit_line", fuzz_audit_line, (),
               [audit.to_json(ev).encode(), audit.to_csv(ev).encode(), audit.to_cef(ev).encode(), b"CEF:0|a|b|c|d|e|3|"],
               [b"|", b"\\", b"=", b" rt=", b" msg=", b'"', b"{", b"}", b"\\n", b"CEF:", b"9" * 30]),
        Target("config", fuzz_config, (), [cfg_seed],
               [b"[logging]", b"[crypto]", b"\n", b"=", b"%", b"\r\n", b"\x00", b"30d", b"100MB", b"JSON", b"\xff"]),
        Target("manifest", fuzz_manifest, (release.ManifestError,), [json.dumps(_MANIFEST).encode()],
               [b"null", b"[", b"{", b'""', b"true", b"1e999", b"-1", b'"\\u0000"', b"\n", b"0", b"99999999999999999999"]),
        Target("sbom", fuzz_sbom, (sbom.SbomMismatch,), [sbom_seed],
               [b"null", b"[", b"{}", b'"', b"[]", b"1", b"true", b'"component"', b'"components"', b'"metadata"']),
        Target("package_zip", fuzz_package, (staging.PackageError,), [_zip_bytes()],
               [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"../", b"..\\", b"/", b"C:", b"\x00", b"\xff\xff\xff\xff"]),
        Target("token", fuzz_token, (tokens.TokenError,), [good_token],
               [b".", b"..", b"=", b"-", b"_", b"eyJ", b"e30", b"bnVsbA", b"W10", b"\xff"]),
        Target("semver", fuzz_semver, (), [b"1.2.3", b"0.0.0", b"10.20.30"],
               [b".", b"0", b"9", b"\n", b"\r", b" ", b"\xd9\xa3", b"-", b"+", b"\x00"]),
        Target("ids", fuzz_hex_ids, (), [b"a" * 64, b"0123456789abcdef" * 4], [b"\n", b"\r", b"f", b"g", b"\x00", b" "]),
        Target("password_policy", fuzz_password_policy, (), [b"Hunter2-secure", b"password", "Пароль-123".encode()],
               [b"\x00", b" ", b"\xf0\x9f\x98\x80", b"a" * 129, b"1", b"_"]),
    ]


TARGETS = {t.name: t for t in _all()}
