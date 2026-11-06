"""Протокол постановки штампа времени (СТБ 34.101.82-2019, RFC 3161 + RFC 5816).

Запрос TimeStampReq, ответ TimeStampResp со штампом TimeStampToken (CMS SignedData, подписанный
службой штампов времени), локальная служба для демонстрации и проверка ответа клиентом (разд. 6).
Хэширование - belt-hash, подпись - bign-with-hbelt.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional, Tuple

from . import asn1, cades, x509
from .cades import CadesCheck
from .cryptoif import Crypto
from .errors import EcpError

OID_TSTINFO = cades.OID_TSTINFO
DEMO_POLICY = "2.999.82.1"  # 2.999 - ветвь для примеров (X.660): политика демонстрационной службы
HASH_LEN = 32

GRANTED, GRANTED_WITH_MODS, REJECTION, WAITING = 0, 1, 2, 3
STATUS_TEXT = {
    0: "штамп предоставлен", 1: "штамп предоставлен с изменениями", 2: "запрос отклонён",
    3: "запрос ожидает обработки", 4: "предупреждение об отзыве сертификата службы",
    5: "сертификат службы отозван",
}

FAIL_BAD_ALG, FAIL_BAD_REQUEST, FAIL_BAD_DATA_FORMAT = 0, 2, 5
FAIL_TIME_NOT_AVAILABLE, FAIL_UNACCEPTED_POLICY, FAIL_UNACCEPTED_EXTENSION = 14, 15, 16
FAIL_ADD_INFO_NOT_AVAILABLE, FAIL_SYSTEM_FAILURE = 17, 25
FAIL_TEXT = {
    FAIL_BAD_ALG: "badAlg: неподдерживаемый алгоритм хэширования",
    FAIL_BAD_REQUEST: "badRequest: транзакция не разрешена",
    FAIL_BAD_DATA_FORMAT: "badDataFormat: некорректный формат запроса",
    FAIL_TIME_NOT_AVAILABLE: "timeNotAvailable: источник времени недоступен",
    FAIL_UNACCEPTED_POLICY: "unacceptedPolicy: политика не поддерживается",
    FAIL_UNACCEPTED_EXTENSION: "unacceptedExtension: расширение не поддерживается",
    FAIL_ADD_INFO_NOT_AVAILABLE: "addInfoNotAvailable: дополнительная информация недоступна",
    FAIL_SYSTEM_FAILURE: "systemFailure: сбой системы",
}


# ------------------------------------------------------------------ запрос
def new_nonce() -> int:
    """Случайное значение nonce с 64 битами энтропии (рекомендация п. 7.1)."""
    return int.from_bytes(os.urandom(8), "big") or 1


def build_request(
    imprint: bytes,
    nonce: Optional[int] = None,
    cert_req: bool = True,
    policy: Optional[str] = None,
    hash_oid: str = x509.OID_BELT_HASH,
) -> bytes:
    """TimeStampReq в отличительных правилах кодирования (certReq = FALSE по умолчанию не кодируется)."""
    parts = [asn1.integer(1), asn1.seq(x509.algorithm_identifier(hash_oid), asn1.octet_string(imprint))]
    if policy:
        parts.append(asn1.oid(policy))
    if nonce is not None:
        parts.append(asn1.integer(nonce))
    if cert_req:
        parts.append(asn1.boolean(True))
    return asn1.seq(*parts)


@dataclass
class TimeStampRequest:
    version: int
    hash_oid: str
    imprint: bytes
    policy: Optional[str]
    nonce: Optional[int]
    cert_req: bool
    has_extensions: bool
    der: bytes


def parse_request(der: bytes) -> TimeStampRequest:
    try:
        items = asn1.parse(der).expect(asn1.SEQUENCE, "TimeStampReq").children()
        version = items[0].as_int()
        mi = items[1].expect(asn1.SEQUENCE, "MessageImprint").children()
        req = TimeStampRequest(
            version=version, hash_oid=mi[0].children()[0].as_oid(), imprint=mi[1].as_octets(),
            policy=None, nonce=None, cert_req=False, has_extensions=False, der=der,
        )
        for node in items[2:]:
            if node.tag == asn1.OID:
                req.policy = node.as_oid()
            elif node.tag == asn1.INTEGER:
                req.nonce = node.as_int()
            elif node.tag == asn1.BOOLEAN:
                req.cert_req = node.as_bool()
            elif node.tag == 0xA0:
                req.has_extensions = True
            else:
                raise asn1.Asn1Error("неизвестный компонент запроса")
        return req
    except (asn1.Asn1Error, IndexError, ValueError):
        raise EcpError("Ошибка: неверный формат запроса штампа времени") from None


# ------------------------------------------------------------------ ответ
def _fail_info(bit: int) -> bytes:
    """PKIFailureInfo: именованный список битов (бит 0 - старший бит первого октета)."""
    data = bytearray(bit // 8 + 1)
    data[bit // 8] |= 0x80 >> (bit % 8)
    return asn1.bit_string(bytes(data), 7 - bit % 8)


def parse_response_status(der: bytes) -> Tuple[int, str, Optional[int], Optional[bytes]]:
    """(status, statusString, failInfo-бит, токен) из TimeStampResp."""
    try:
        items = asn1.parse(der).expect(asn1.SEQUENCE, "TimeStampResp").children()
        info = items[0].expect(asn1.SEQUENCE, "PKIStatusInfo").children()
        status = info[0].as_int()
        text, fail = "", None
        for node in info[1:]:
            if node.tag == asn1.SEQUENCE:  # PKIFreeText
                text = "; ".join(n.content.decode("utf-8", errors="replace") for n in node.children())
            elif node.tag == asn1.BIT_STRING:
                unused, data = node.as_bit_string()
                for i in range(len(data) * 8 - unused):
                    if data[i // 8] & (0x80 >> (i % 8)):
                        fail = i
                        break
        token = items[1].raw if len(items) > 1 else None
        return status, text, fail, token
    except (asn1.Asn1Error, IndexError, ValueError):
        raise EcpError("Ошибка: неверный формат ответа службы штампов времени") from None


class TimeStampAuthority:
    """Локальная служба штампов времени (СШВ). Принимает запрос, возвращает ответ."""

    def __init__(self, private_key: bytes, cert_der: bytes, crypto: Crypto,
                 policy: str = DEMO_POLICY, clock: Optional[Callable[[], datetime]] = None,
                 accuracy_seconds: int = 1) -> None:
        self.private_key = private_key
        self.cert_der = cert_der
        self.cert = x509.parse_certificate(cert_der)
        self.crypto = crypto
        self.policy = policy
        self.accuracy_seconds = accuracy_seconds
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if crypto.derive_public_key(private_key) != self.cert.public_key:
            raise EcpError("Ошибка: сертификат службы штампов времени не соответствует её ключу")
        if x509.OID_KP_TIME_STAMPING not in self.cert.key_purposes:
            raise EcpError("Ошибка: сертификат службы не предназначен для штампов времени (id-kp-timeStamping)")

    @property
    def public_key(self) -> bytes:
        return self.cert.public_key

    def _reject(self, fail_bit: int, text: Optional[str] = None) -> bytes:
        info = asn1.seq(
            asn1.integer(REJECTION),
            asn1.seq(asn1.utf8_string(text or FAIL_TEXT[fail_bit])),  # PKIFreeText
            _fail_info(fail_bit),
        )
        return asn1.seq(info)

    def respond(self, request_der: bytes) -> bytes:
        """TimeStampResp на запрос TimeStampReq (разд. 6, 7)."""
        try:
            req = parse_request(request_der)
        except EcpError:
            return self._reject(FAIL_BAD_DATA_FORMAT)
        if req.version != 1:
            return self._reject(FAIL_BAD_DATA_FORMAT, "badDataFormat: версия запроса должна быть равна 1")
        if req.hash_oid != x509.OID_BELT_HASH:
            return self._reject(FAIL_BAD_ALG)
        if len(req.imprint) != HASH_LEN:
            return self._reject(FAIL_BAD_DATA_FORMAT, "badDataFormat: длина хэш-значения не соответствует belt-hash")
        if req.has_extensions:
            return self._reject(FAIL_UNACCEPTED_EXTENSION)
        if req.policy is not None and req.policy != self.policy:
            return self._reject(FAIL_UNACCEPTED_POLICY)
        try:
            now = self._clock()
            serial = (int.from_bytes(os.urandom(16), "big") >> 1) or 1  # 127 бит, уникальность вероятностная
            tst = [
                asn1.integer(1),
                asn1.oid(self.policy),
                asn1.seq(x509.algorithm_identifier(req.hash_oid), asn1.octet_string(req.imprint)),
                asn1.integer(serial),
                asn1.generalized_time(now),
                asn1.seq(asn1.integer(self.accuracy_seconds)),  # accuracy
            ]
            if req.nonce is not None:
                tst.append(asn1.integer(req.nonce))
            tst.append(asn1.explicit(0, asn1.explicit(4, self.cert.subject_der)))  # tsa: directoryName
            tst_info = asn1.seq(*tst)
            token = cades.build_signed_data(
                OID_TSTINFO, tst_info, self.private_key, self.cert_der, self.crypto,
                attach=True, include_cert=req.cert_req, include_signing_time=False,
            )
        except (EcpError, ValueError):
            return self._reject(FAIL_SYSTEM_FAILURE)
        return asn1.seq(asn1.seq(asn1.integer(GRANTED)), token)


# ------------------------------------------------------------------ проверка ответа клиентом
@dataclass
class TspResult:
    ok: bool = False
    checks: List[CadesCheck] = field(default_factory=list)
    gen_time: Optional[datetime] = None
    serial: int = 0
    policy: str = ""
    accuracy: float = 0.0
    nonce: Optional[int] = None
    imprint: bytes = b""
    tsa_name: str = ""
    token: bytes = b""


def verify_token(
    token: bytes,
    imprint: bytes,
    nonce: Optional[int],
    crypto: Crypto,
    trusted_key: Optional[bytes] = None,
    now: Optional[datetime] = None,
    max_skew: timedelta = timedelta(minutes=5),
) -> TspResult:
    """Проверка TimeStampToken: структура, messageImprint, nonce, подпись службы, сертификат, время."""
    result = TspResult(token=token)

    def check(name: str, ok: bool, detail: str = "") -> bool:
        result.checks.append(CadesCheck(name, ok, detail))
        return ok

    try:
        root = asn1.parse(token).expect(asn1.SEQUENCE, "TimeStampToken")
        content_type, content = root.children()
        if content_type.as_oid() != cades.OID_SIGNED_DATA:
            raise EcpError("Ошибка: штамп времени не является подписанными данными CMS")
        sd = content.expect(0xA0, "content").children()[0].expect(asn1.SEQUENCE, "SignedData").children()
        encap = sd[2].expect(asn1.SEQUENCE, "encapContentInfo").children()
        e_type = encap[0].as_oid()
        tst_der = encap[1].children()[0].as_octets()
        certs_node = next((p for p in sd[3:] if p.tag == 0xA0), None)
        signer_infos = sd[-1].expect(asn1.SET, "signerInfos").children()
        if len(signer_infos) != 1:
            raise EcpError("Ошибка: штамп времени должен содержать ровно одну подпись службы")
        si = signer_infos[0].children()
        sid, digest_alg, signed_attrs, sig_alg, sig_value = si[1], si[2], si[3], si[4], si[5]
        signed_attrs.expect(0xA0, "signedAttrs")

        tst = asn1.parse(tst_der).expect(asn1.SEQUENCE, "TSTInfo").children()
        version = tst[0].as_int()
        result.policy = tst[1].as_oid()
        mi = tst[2].children()
        mi_alg, mi_hash = mi[0].children()[0].as_oid(), mi[1].as_octets()
        result.serial = tst[3].as_int()
        result.gen_time = tst[4].as_time()
        tsa_name_der = None
        for node in tst[5:]:
            if node.tag == asn1.SEQUENCE:  # Accuracy
                seconds = 0.0
                for part in node.children():
                    value = part.as_int() if part.tag == asn1.INTEGER else int.from_bytes(part.content, "big")
                    seconds += value if part.tag == asn1.INTEGER else value / (1000 if part.tag == 0x80 else 1_000_000)
                result.accuracy = seconds
            elif node.tag == asn1.INTEGER:
                result.nonce = node.as_int()
            elif node.tag == 0xA0:
                tsa_name_der = node.children()[0].children()[0].raw
    except asn1.Asn1Error as e:
        raise EcpError(f"Ошибка: неверная структура штампа времени ({e})") from None
    except (ValueError, IndexError):
        raise EcpError("Ошибка: неверная структура штампа времени") from None

    result.imprint = mi_hash
    check("Структура штампа времени (СТБ 34.101.82)", version == 1 and e_type == OID_TSTINFO)
    check("messageImprint: алгоритм belt-hash", mi_alg == x509.OID_BELT_HASH)
    check("messageImprint совпадает с хэшем данных", mi_hash == imprint)
    if nonce is not None:
        check("nonce совпадает с запросом", result.nonce == nonce)

    # --- сертификат службы
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
    tsa_key = cert.public_key if cert is not None else trusted_key
    if cert is None:
        check("Сертификат службы в штампе", trusted_key is not None,
              "" if trusted_key is not None else "нет в штампе (certReq не был установлен) и нет доверенного ключа")
    if tsa_key is None:
        return result
    try:
        crypto.check_public_key(tsa_key)
        key_ok = True
    except EcpError:
        key_ok = False
    if not check("Открытый ключ службы допустим (п. 6.2.3)", key_ok):
        return result
    if trusted_key is not None:
        check("Ключ службы совпадает с доверенным", tsa_key == trusted_key)

    if cert is not None:
        result.tsa_name = cert.subject_cn
        check("Сертификат службы: назначение id-kp-timeStamping", x509.OID_KP_TIME_STAMPING in cert.key_purposes)
        check("Сертификат действует на момент штампа", cert.not_before <= result.gen_time <= cert.not_after)
        if tsa_name_der is not None:
            check("Имя службы в штампе совпадает с субъектом сертификата", tsa_name_der == cert.subject_der)

    # --- подпись службы
    try:
        attrs = cades.parse_attributes(signed_attrs)
    except (asn1.Asn1Error, IndexError):
        raise EcpError("Ошибка: неверная структура подписываемых атрибутов штампа") from None

    def single(oid_str: str) -> Optional[asn1.Node]:
        values = attrs.get(oid_str)
        return values[0] if values and len(values) == 1 else None

    algs_ok = (digest_alg.children()[0].as_oid() == x509.OID_BELT_HASH
               and sig_alg.children()[0].as_oid() == x509.OID_BIGN_WITH_HBELT)
    check("Алгоритмы подписи службы: belt-hash и bign-with-hbelt", algs_ok)
    ct = single(cades.OID_CONTENT_TYPE)
    check("Атрибут ContentType = id-ct-TSTInfo", ct is not None and ct.as_oid() == OID_TSTINFO)
    md = single(cades.OID_MESSAGE_DIGEST)
    check("Атрибут MessageDigest = belt-hash(TSTInfo)", md is not None and md.content == crypto.hash(tst_der))
    if cert is not None:
        scv2 = single(cades.OID_SIGNING_CERT_V2)
        ref_ok = False
        try:
            if scv2 is not None:
                first = scv2.children()[0].children()[0].children()
                ref_ok = (first[0].children()[0].as_oid() == x509.OID_BELT_HASH
                          and first[1].as_octets() == crypto.hash(cert.der))
        except (asn1.Asn1Error, IndexError):
            ref_ok = False
        check("Атрибут SigningCertificate: ссылка на сертификат службы", ref_ok)
    try:
        sig_bytes = sig_value.as_octets()
        sig_ok = len(sig_bytes) == 48 and crypto.verify(tsa_key, b"\x31" + signed_attrs.raw[1:], sig_bytes)
    except (ValueError, asn1.Asn1Error):
        sig_ok = False
    check("ЭЦП службы штампов времени (bign-with-hbelt)", sig_ok)

    if now is not None:
        delta = abs((result.gen_time - now).total_seconds())
        check("Время штампа близко к локальному времени", delta <= max_skew.total_seconds() + result.accuracy,
              f"расхождение {delta:.0f} с")

    result.ok = all(c.ok for c in result.checks)
    return result


def verify_response(
    response: bytes,
    imprint: bytes,
    nonce: Optional[int],
    crypto: Crypto,
    trusted_key: Optional[bytes] = None,
    now: Optional[datetime] = None,
) -> TspResult:
    """Проверка TimeStampResp. Отказ службы - EcpError с причиной."""
    status, text, fail, token = parse_response_status(response)
    if status not in (GRANTED, GRANTED_WITH_MODS):
        reason = "; ".join(x for x in (text, FAIL_TEXT.get(fail, "") if fail is not None else "") if x)
        raise EcpError(f"Ошибка: служба штампов времени: {STATUS_TEXT.get(status, f'статус {status}')}"
                       + (f" ({reason})" if reason else ""))
    if token is None:
        raise EcpError("Ошибка: ответ службы со статусом «предоставлен» не содержит штампа времени")
    return verify_token(token, imprint, nonce, crypto, trusted_key=trusted_key, now=now)


def make_provider(authority: TimeStampAuthority, crypto: Crypto,
                  nonce_source: Callable[[], int] = new_nonce) -> Callable[[bytes], bytes]:
    """Клиент протокола для CAdES-B-T: запрос -> служба -> ответ -> проверка -> токен."""
    def provider(imprint: bytes) -> bytes:
        nonce = nonce_source()
        response = authority.respond(build_request(imprint, nonce=nonce, cert_req=True))
        result = verify_response(response, imprint, nonce, crypto, trusted_key=authority.public_key,
                                 now=datetime.now(timezone.utc))
        if not result.ok:
            failed = "; ".join(c.name for c in result.checks if not c.ok)
            raise EcpError(f"Ошибка: штамп времени не прошёл проверку: {failed}")
        return result.token
    return provider
