"""Сертификат открытого ключа X.509 с ключом bign-curve256v1 (СТБ 34.101.19, СТБ 34.101.45, прил. Д).

Выпускается самоподписанный сертификат: он нужен атрибуту SigningCertificate в расширенной ЭЦП.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from . import asn1
from .cryptoif import Crypto
from .errors import EcpError

OID_BIGN_WITH_HBELT = "1.2.112.0.2.0.34.101.45.12"
OID_BIGN_PUBKEY = "1.2.112.0.2.0.34.101.45.2.1"
OID_BIGN_CURVE256V1 = "1.2.112.0.2.0.34.101.45.3.1"
OID_BELT_HASH = "1.2.112.0.2.0.34.101.31.81"
OID_COMMON_NAME = "2.5.4.3"
OID_SUBJECT_KEY_ID = "2.5.29.14"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

PUBLIC_KEY_LEN = 64
SIGNATURE_LEN = 48


def algorithm_identifier(oid_str: str, params: Optional[bytes] = None) -> bytes:
    return asn1.seq(asn1.oid(oid_str), params) if params else asn1.seq(asn1.oid(oid_str))


def name_from_cn(common_name: str) -> bytes:
    return asn1.seq(asn1.set_of([asn1.seq(asn1.oid(OID_COMMON_NAME), asn1.utf8_string(common_name))]))


def public_key_info(q: bytes) -> bytes:
    return asn1.seq(
        algorithm_identifier(OID_BIGN_PUBKEY, asn1.oid(OID_BIGN_CURVE256V1)),
        asn1.bit_string(q),
    )


def build_self_signed(
    private_key: bytes,
    common_name: str,
    crypto: Crypto,
    now: Optional[datetime] = None,
    years: int = 10,
    time_stamping: bool = False,
) -> bytes:
    """Самоподписанный сертификат: подпись bign-with-hbelt от DER-кода tbsCertificate.

    time_stamping=True - сертификат службы штампов времени: критическое расширение
    ExtKeyUsage с единственным назначением id-kp-timeStamping (СТБ 34.101.82, п. 7.2).
    """
    if not common_name.strip():
        raise EcpError("Ошибка: не задано имя владельца сертификата")
    q = crypto.derive_public_key(private_key)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    not_after = now + timedelta(days=365 * years)
    serial = (int.from_bytes(os.urandom(16), "big") >> 1) or 1
    name = name_from_cn(common_name.strip())
    ski = asn1.seq(asn1.oid(OID_SUBJECT_KEY_ID), asn1.octet_string(asn1.octet_string(crypto.hash(q)[:20])))
    key_usage = asn1.seq(
        asn1.oid(OID_KEY_USAGE),
        asn1.boolean(True),
        asn1.octet_string(asn1.bit_string(b"\xc0", 6)),  # digitalSignature, nonRepudiation
    )
    extra_extensions = []
    if time_stamping:
        extra_extensions.append(asn1.seq(
            asn1.oid(OID_EXT_KEY_USAGE),
            asn1.boolean(True),  # критическое
            asn1.octet_string(asn1.seq(asn1.oid(OID_KP_TIME_STAMPING))),
        ))
    tbs = asn1.seq(
        asn1.explicit(0, asn1.integer(2)),  # version v3
        asn1.integer(serial),
        algorithm_identifier(OID_BIGN_WITH_HBELT),
        name,
        asn1.seq(asn1.time_choice(now), asn1.time_choice(not_after)),
        name,
        public_key_info(q),
        asn1.explicit(3, asn1.seq(ski, key_usage, *extra_extensions)),
    )
    signature = crypto.sign(private_key, tbs)
    return asn1.seq(tbs, algorithm_identifier(OID_BIGN_WITH_HBELT), asn1.bit_string(signature))


@dataclass
class CertInfo:
    der: bytes
    tbs: bytes
    serial: int
    serial_der: bytes
    issuer_der: bytes
    subject_der: bytes
    subject_cn: str
    not_before: datetime
    not_after: datetime
    public_key: bytes
    sig_alg: str
    signature: bytes
    key_purposes: List[str] = field(default_factory=list)


def _common_name(name_der: bytes) -> str:
    try:
        for rdn in asn1.parse(name_der).children():
            for atv in rdn.children():
                parts = atv.children()
                if parts[0].as_oid() == OID_COMMON_NAME:
                    return parts[1].content.decode("utf-8", errors="replace")
    except (asn1.Asn1Error, IndexError):
        pass
    return ""


def parse_certificate(der: bytes) -> CertInfo:
    try:
        root = asn1.parse(der).expect(asn1.SEQUENCE, "Certificate")
        tbs, alg, sig = root.children()
        items = tbs.expect(asn1.SEQUENCE, "TBSCertificate").children()
        i = 1 if items[0].tag == 0xA0 else 0
        serial, _inner_alg, issuer, validity, subject, spki = items[i:i + 6]
        times = validity.children()
        key_alg, key_bits = spki.children()
        if key_alg.children()[0].as_oid() != OID_BIGN_PUBKEY:
            raise EcpError("Ошибка: сертификат содержит ключ неподдерживаемого типа (ожидается bign-pubkey)")
        unused, key = key_bits.as_bit_string()
        if unused != 0 or len(key) != PUBLIC_KEY_LEN:
            raise EcpError("Ошибка: неверный формат открытого ключа в сертификате (ожидается 64 байта)")
        sig_unused, sig_value = sig.as_bit_string()
        purposes: List[str] = []
        ext_node = next((n for n in items[i + 6:] if n.tag == 0xA3), None)
        if ext_node is not None:
            for ext in ext_node.children()[0].children():
                parts = ext.children()
                if parts[0].as_oid() == OID_EXT_KEY_USAGE:
                    purposes = [p.as_oid() for p in asn1.parse(parts[-1].as_octets()).children()]
        return CertInfo(
            der=der,
            tbs=tbs.raw,
            serial=serial.as_int(),
            serial_der=serial.raw,
            issuer_der=issuer.raw,
            subject_der=subject.raw,
            subject_cn=_common_name(subject.raw),
            not_before=times[0].as_time(),
            not_after=times[1].as_time(),
            public_key=key,
            sig_alg=alg.children()[0].as_oid(),
            signature=sig_value if sig_unused == 0 else b"",
            key_purposes=purposes,
        )
    except (asn1.Asn1Error, ValueError, IndexError):
        raise EcpError("Ошибка: неверная структура сертификата") from None


def verify_certificate_signature(cert: CertInfo, issuer_public_key: bytes, crypto: Crypto) -> bool:
    """Проверка подписи сертификата (для самоподписанного - его собственным ключом)."""
    if cert.sig_alg != OID_BIGN_WITH_HBELT or len(cert.signature) != SIGNATURE_LEN:
        return False
    try:
        return bool(crypto.verify(issuer_public_key, cert.tbs, cert.signature))
    except ValueError:
        return False
