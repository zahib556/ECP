"""Расширенная ЭЦП формата CAdES, профиль B-B (СТБ 34.101.80, разд. 7, 9) поверх
подписанных данных CMS (СТБ 34.101.23, разд. 8, 15).

Состав подписанных атрибутов: ContentType, MessageDigest, SigningTime, SigningCertificateV2.
Хэширование - belt-hash, ЭЦП - bign-with-hbelt (СТБ 34.101.45).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional

from . import asn1, x509
from .cryptoif import Crypto
from .errors import EcpError

OID_ID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
TIMESTAMP_ORDER_TOLERANCE = timedelta(seconds=60)


def _attribute(oid_str: str, value: bytes) -> bytes:
    return asn1.seq(asn1.oid(oid_str), asn1.set_of([value]))


def _signing_certificate_v2(cert: x509.CertInfo, crypto: Crypto) -> bytes:
    """Атрибут SigningCertificateV2: ссылка на сертификат (belt-hash от его DER-кода)."""
    cert_id = asn1.seq(  # ESSCertIDv2
        x509.algorithm_identifier(x509.OID_BELT_HASH),
        asn1.octet_string(crypto.hash(cert.der)),
        asn1.seq(asn1.seq(asn1.explicit(4, cert.issuer_der)), cert.serial_der),  # IssuerSerial
    )
    return asn1.seq(asn1.seq(cert_id))


def build_signed_data(
    content_type: str,
    content: bytes,
    private_key: bytes,
    cert_der: bytes,
    crypto: Crypto,
    *,
    attach: bool,
    include_cert: bool = True,
    signing_time: Optional[datetime] = None,
    include_signing_time: bool = True,
    timestamp_provider: Optional[Callable[[bytes], bytes]] = None,
) -> bytes:
    """Подписанные данные CMS (СТБ 34.101.23, разд. 8) с одной подписью.

    timestamp_provider(imprint) -> TimeStampToken: если задан, в неподписываемые атрибуты
    добавляется SignatureTimeStamp по хэшу значения подписи (профиль CAdES-B-T).
    """
    cert = x509.parse_certificate(cert_der)
    if crypto.derive_public_key(private_key) != cert.public_key:
        raise EcpError("Ошибка: сертификат не соответствует личному ключу")

    attributes = [
        _attribute(OID_CONTENT_TYPE, asn1.oid(content_type)),
        _attribute(OID_MESSAGE_DIGEST, asn1.octet_string(crypto.hash(content))),
    ]
    if include_signing_time:
        now = (signing_time or datetime.now(timezone.utc)).replace(microsecond=0)
        attributes.append(_attribute(OID_SIGNING_TIME, asn1.time_choice(now)))
    attributes.append(_attribute(OID_SIGNING_CERT_V2, _signing_certificate_v2(cert, crypto)))
    signed_attrs = asn1.set_of(attributes)  # DER; именно этот код подписывается (СТБ 34.101.23, 8.5)
    signature = crypto.sign(private_key, signed_attrs)

    signer_fields = [
        asn1.integer(1),
        asn1.seq(cert.issuer_der, cert.serial_der),  # issuerAndSerialNumber
        x509.algorithm_identifier(x509.OID_BELT_HASH),
        b"\xa0" + signed_attrs[1:],  # [0] IMPLICIT: тег SET заменяется на [0]
        x509.algorithm_identifier(x509.OID_BIGN_WITH_HBELT),
        asn1.octet_string(signature),
    ]
    if timestamp_provider is not None:
        token = timestamp_provider(crypto.hash(signature))
        unsigned = asn1.set_of([_attribute(OID_SIGNATURE_TIMESTAMP, token)])
        signer_fields.append(b"\xa1" + unsigned[1:])  # unsignedAttrs [1] IMPLICIT
    signer_info = asn1.seq(*signer_fields)

    encap = asn1.seq(asn1.oid(content_type), *([asn1.explicit(0, asn1.octet_string(content))] if attach else []))
    parts = [
        asn1.integer(1 if content_type == OID_ID_DATA else 3),
        asn1.set_of([x509.algorithm_identifier(x509.OID_BELT_HASH)]),
        encap,
    ]
    if include_cert:
        parts.append(asn1.tlv(0xA0, cert_der))  # certificates [0] IMPLICIT
    parts.append(asn1.set_of([signer_info]))
    return asn1.seq(asn1.oid(OID_SIGNED_DATA), asn1.explicit(0, asn1.seq(*parts)))


def build_cades_bb(
    message: bytes,
    private_key: bytes,
    cert_der: bytes,
    crypto: Crypto,
    signing_time: Optional[datetime] = None,
    attach: bool = False,
    timestamp_provider: Optional[Callable[[bytes], bytes]] = None,
) -> bytes:
    """CAdES-B-B; с timestamp_provider - CAdES-B-T. attach=False - отделённая подпись."""
    return build_signed_data(
        OID_ID_DATA, message, private_key, cert_der, crypto,
        attach=attach, signing_time=signing_time, timestamp_provider=timestamp_provider,
    )


def parse_attributes(attrs: asn1.Node) -> dict:
    """Атрибуты CMS: {OID: [значения]}."""
    result = {}
    for a in attrs.children():
        items = a.children()
        result[items[0].as_oid()] = items[1].children()
    return result


# ------------------------------------------------------------------ проверка
@dataclass
class CadesCheck:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class CadesResult:
    ok: bool
    checks: List[CadesCheck] = field(default_factory=list)
    signer: str = ""
    signing_time: Optional[datetime] = None
    public_key: bytes = b""
    detached: bool = True
    digest: bytes = b""
    timestamped: bool = False
    timestamp: Optional[object] = None  # tsp.TspResult
    notes: List[str] = field(default_factory=list)


def verify_cades(
    cms: bytes,
    message: Optional[bytes],
    crypto: Crypto,
    trusted_key: Optional[bytes] = None,
    trusted_tsa_key: Optional[bytes] = None,
) -> CadesResult:
    """Проверка CAdES-B-B и B-T. message=None допустим только для обертывающей подписи."""
    result = CadesResult(ok=False)

    def check(name: str, ok: bool, detail: str = "") -> bool:
        result.checks.append(CadesCheck(name, ok, detail))
        return ok

    try:
        root = asn1.parse(cms).expect(asn1.SEQUENCE, "ContentInfo")
        content_type, content = root.children()
        if content_type.as_oid() != OID_SIGNED_DATA:
            raise EcpError("Ошибка: контейнер не является подписанными данными (id-signedData)")
        signed_data = content.expect(0xA0, "content").children()[0].expect(asn1.SEQUENCE, "SignedData")
        parts = signed_data.children()
        version, digest_algs, encap = parts[0], parts[1], parts[2]
        certs_node = next((p for p in parts[3:] if p.tag == 0xA0), None)
        signer_infos = parts[-1].expect(asn1.SET, "signerInfos").children()
        version.as_int()
        if len(signer_infos) != 1:
            raise EcpError("Ошибка: поддерживается ровно одна подпись в контейнере")
        encap_parts = encap.expect(asn1.SEQUENCE, "encapContentInfo").children()
        e_content_type = encap_parts[0].as_oid()
        attached = encap_parts[1].children()[0].as_octets() if len(encap_parts) > 1 else None
        si = signer_infos[0].expect(asn1.SEQUENCE, "SignerInfo").children()
        sid, digest_alg, signed_attrs, sig_alg, sig_value = si[1], si[2], si[3], si[4], si[5]
        sig_value_bytes = sig_value.as_octets()
        signed_attrs.expect(0xA0, "signedAttrs")
        unsigned_attrs = next((n for n in si[6:] if n.tag == 0xA1), None)
    except asn1.Asn1Error as e:
        raise EcpError(f"Ошибка: неверная структура CMS ({e})") from None
    except (ValueError, IndexError, StopIteration):
        raise EcpError("Ошибка: неверная структура CMS") from None

    result.detached = attached is None
    data = attached if attached is not None else message
    if data is None:
        raise EcpError("Ошибка: подпись отделённая, выберите файл сообщения")
    if attached is not None and message is not None and attached != message:
        check("Сообщение совпадает с вложенным в подпись", False)
    result.digest = crypto.hash(data)

    check("Структура CMS (СТБ 34.101.23)", True)
    algs_ok = (
        digest_alg.children()[0].as_oid() == x509.OID_BELT_HASH
        and sig_alg.children()[0].as_oid() == x509.OID_BIGN_WITH_HBELT
        and [a.children()[0].as_oid() for a in digest_algs.children()] == [x509.OID_BELT_HASH]
    )
    if not check("Алгоритмы: belt-hash и bign-with-hbelt", algs_ok):
        result.ok = False
        return result

    # --- сертификат подписанта
    cert: Optional[x509.CertInfo] = None
    try:
        sid_items = sid.children()
        if certs_node is not None:
            for c in certs_node.children():
                info = x509.parse_certificate(c.raw)
                if info.issuer_der == sid_items[0].raw and info.serial_der == sid_items[1].raw:
                    cert = info
                    break
    except (asn1.Asn1Error, IndexError, EcpError):
        cert = None
    if not check("Сертификат подписанта найден в контейнере", cert is not None):
        return result
    assert cert is not None
    result.signer = cert.subject_cn
    result.public_key = cert.public_key

    try:
        crypto.check_public_key(cert.public_key)
        key_ok = True
    except EcpError:
        key_ok = False
    if not check("Открытый ключ сертификата допустим (п. 6.2.3)", key_ok):
        return result
    if trusted_key is not None:
        check("Ключ совпадает с указанным открытым ключом", trusted_key == cert.public_key)

    # --- атрибуты
    attrs = {}
    try:
        for a in signed_attrs.children():
            a_items = a.children()
            attrs[a_items[0].as_oid()] = a_items[1].children()
    except (asn1.Asn1Error, IndexError):
        raise EcpError("Ошибка: неверная структура подписываемых атрибутов") from None

    def single(oid_str: str) -> Optional[asn1.Node]:
        values = attrs.get(oid_str)
        return values[0] if values and len(values) == 1 else None

    ct = single(OID_CONTENT_TYPE)
    check("Атрибут ContentType совпадает с eContentType",
          ct is not None and ct.as_oid() == e_content_type)
    md = single(OID_MESSAGE_DIGEST)
    check("Атрибут MessageDigest = belt-hash(сообщение)",
          md is not None and md.content == result.digest)
    st = single(OID_SIGNING_TIME)
    try:
        result.signing_time = st.as_time() if st is not None else None
    except asn1.Asn1Error:
        result.signing_time = None
    check("Атрибут SigningTime", result.signing_time is not None)

    scv2 = single(OID_SIGNING_CERT_V2)
    cert_ref_ok = False
    try:
        if scv2 is not None:
            first = scv2.children()[0].children()[0].children()
            hash_alg_ok = first[0].children()[0].as_oid() == x509.OID_BELT_HASH
            cert_ref_ok = hash_alg_ok and first[1].as_octets() == crypto.hash(cert.der)
    except (asn1.Asn1Error, IndexError):
        cert_ref_ok = False
    check("Атрибут SigningCertificate: хэш сертификата", cert_ref_ok)

    if result.signing_time is not None:
        check("Сертификат действует на момент подписания",
              cert.not_before <= result.signing_time <= cert.not_after)

    # --- ЭЦП атрибутов: подписывается код SET OF, полученный заменой тега [0] на SET
    to_verify = b"\x31" + signed_attrs.raw[1:]
    try:
        sig_ok = len(sig_value_bytes) == 48 and crypto.verify(cert.public_key, to_verify, sig_value_bytes)
    except ValueError:
        sig_ok = False
    check("ЭЦП подписываемых атрибутов (bign-with-hbelt)", sig_ok)

    # --- штамп времени подписи (профиль B-T, СТБ 34.101.80, СТБ 34.101.82)
    if unsigned_attrs is not None:
        _check_signature_timestamp(unsigned_attrs, sig_value_bytes, result, crypto, trusted_tsa_key, check)

    result.ok = all(c.ok for c in result.checks)
    return result


def _check_signature_timestamp(unsigned_attrs, signature: bytes, result: CadesResult, crypto: Crypto,
                               trusted_tsa_key: Optional[bytes], check) -> None:
    from . import tsp  # локальный импорт: tsp использует сборку CMS из этого модуля

    try:
        values = parse_attributes(unsigned_attrs).get(OID_SIGNATURE_TIMESTAMP)
        token = values[0].raw if values else None
    except (asn1.Asn1Error, IndexError):
        check("Атрибут SignatureTimeStamp: структура", False)
        return
    if token is None:
        return
    result.timestamped = True
    try:
        ts = tsp.verify_token(token, crypto.hash(signature), None, crypto, trusted_key=trusted_tsa_key)
    except EcpError as e:
        check("Штамп времени: структура", False, str(e))
        return
    result.timestamp = ts
    for c in ts.checks:
        check("Штамп времени: " + c.name, c.ok, c.detail)
    if ts.gen_time is not None and result.signing_time is not None:
        check("Время подписания не позднее времени штампа (допуск 60 с)",
              result.signing_time <= ts.gen_time + TIMESTAMP_ORDER_TOLERANCE)
    if trusted_tsa_key is None:
        result.notes.append("Служба штампов времени не проверена на доверие: её ключ взят из самого штампа.")
