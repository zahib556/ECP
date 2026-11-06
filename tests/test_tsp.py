"""Протокол штампа времени (СТБ 34.101.82) и расширенная подпись CAdES-B-T."""
from datetime import datetime, timedelta, timezone

import pytest

import ecp
from ecp import asn1, cades, tsp, x509
from ecp.cryptoif import default_crypto
from ecp.errors import EcpError

DATA = "Документ для штампа времени".encode("utf-8")


@pytest.fixture(scope="module")
def crypto():
    return default_crypto()


@pytest.fixture(scope="module")
def tsa_keys():
    return ecp.generate_keypair()


@pytest.fixture(scope="module")
def tsa(tsa_keys, crypto):
    cert = x509.build_self_signed(tsa_keys[0], "Тестовая СШВ", crypto, time_stamping=True)
    return tsp.TimeStampAuthority(tsa_keys[0], cert, crypto)


def imprint_of(data=DATA):
    return ecp.belt_hash(data)


# ---------------- запрос ----------------
def test_request_roundtrip():
    imprint = imprint_of()
    der = tsp.build_request(imprint, nonce=123456789, cert_req=True, policy="2.999.1")
    req = tsp.parse_request(der)
    assert (req.version, req.hash_oid, req.imprint) == (1, x509.OID_BELT_HASH, imprint)
    assert (req.nonce, req.cert_req, req.policy, req.has_extensions) == (123456789, True, "2.999.1", False)


def test_request_defaults_are_not_encoded():
    der = tsp.build_request(imprint_of(), cert_req=False)
    req = tsp.parse_request(der)
    assert req.nonce is None and req.policy is None and req.cert_req is False
    assert asn1.BOOLEAN not in [n.tag for n in asn1.parse(der).children()]  # DEFAULT FALSE - в DER опускается


def test_nonce_has_64_bits_of_entropy():
    values = {tsp.new_nonce() for _ in range(50)}
    assert len(values) == 50 and all(0 < v < 2 ** 64 for v in values)


@pytest.mark.parametrize("bad", [b"", b"\x30\x00", b"\x30\x03\x02\x01\x01", b"\x01\x02\x03", b"\x30\x80"])
def test_parse_request_rejects_garbage(bad):
    with pytest.raises(EcpError, match="формат запроса"):
        tsp.parse_request(bad)


# ---------------- ответ службы ----------------
def test_granted_response_is_verified(tsa, crypto):
    nonce = tsp.new_nonce()
    resp = tsa.respond(tsp.build_request(imprint_of(), nonce=nonce))
    status, text, fail, token = tsp.parse_response_status(resp)
    assert status == tsp.GRANTED and fail is None and token
    result = tsp.verify_response(resp, imprint_of(), nonce, crypto, trusted_key=tsa.public_key,
                                 now=datetime.now(timezone.utc))
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    assert result.policy == tsp.DEMO_POLICY and result.nonce == nonce
    assert result.accuracy == 1.0 and result.tsa_name == "Тестовая СШВ"
    assert result.serial > 0 and result.imprint == imprint_of()
    assert abs((result.gen_time - datetime.now(timezone.utc)).total_seconds()) < 10


def test_serial_numbers_are_unique(tsa):
    serials = set()
    for _ in range(20):
        resp = tsa.respond(tsp.build_request(imprint_of()))
        token = tsp.parse_response_status(resp)[3]
        serials.add(tsp.verify_token(token, imprint_of(), None, default_crypto(), trusted_key=tsa.public_key).serial)
    assert len(serials) == 20


def test_wrong_imprint_and_nonce_detected(tsa, crypto):
    nonce = 4242
    resp = tsa.respond(tsp.build_request(imprint_of(), nonce=nonce))
    bad_imprint = tsp.verify_response(resp, imprint_of(b"other"), nonce, crypto, trusted_key=tsa.public_key)
    assert not bad_imprint.ok and any("messageImprint совпадает" in c.name and not c.ok for c in bad_imprint.checks)
    bad_nonce = tsp.verify_response(resp, imprint_of(), nonce + 1, crypto, trusted_key=tsa.public_key)
    assert not bad_nonce.ok and any("nonce" in c.name and not c.ok for c in bad_nonce.checks)


def test_unsupported_hash_algorithm_is_rejected(tsa, crypto):
    req = tsp.build_request(bytes(32), hash_oid="2.16.840.1.101.3.4.2.1")  # SHA-256
    status, text, fail, token = tsp.parse_response_status(tsa.respond(req))
    assert (status, fail, token) == (tsp.REJECTION, tsp.FAIL_BAD_ALG, None)
    with pytest.raises(EcpError, match="badAlg"):
        tsp.verify_response(tsa.respond(req), bytes(32), None, crypto)


def test_wrong_imprint_length_is_bad_data_format(tsa):
    status, _, fail, _ = tsp.parse_response_status(tsa.respond(tsp.build_request(b"\x01" * 20)))
    assert (status, fail) == (tsp.REJECTION, tsp.FAIL_BAD_DATA_FORMAT)


def test_garbage_request_is_rejected(tsa):
    status, _, fail, token = tsp.parse_response_status(tsa.respond(b"not a request"))
    assert (status, fail, token) == (tsp.REJECTION, tsp.FAIL_BAD_DATA_FORMAT, None)


def test_policy_handling(tsa, crypto):
    ok = tsa.respond(tsp.build_request(imprint_of(), policy=tsp.DEMO_POLICY))
    assert tsp.parse_response_status(ok)[0] == tsp.GRANTED
    bad = tsa.respond(tsp.build_request(imprint_of(), policy="2.999.7"))
    assert tsp.parse_response_status(bad)[2] == tsp.FAIL_UNACCEPTED_POLICY


def test_extensions_are_not_accepted(tsa):
    der = tsp.build_request(imprint_of())
    with_ext = asn1.seq(*[n.raw for n in asn1.parse(der).children()],
                        asn1.tlv(0xA0, asn1.seq(asn1.seq(asn1.oid("2.999.5"), asn1.octet_string(b"x")))))
    assert tsp.parse_response_status(tsa.respond(with_ext))[2] == tsp.FAIL_UNACCEPTED_EXTENSION


def test_fail_info_bit_encoding():
    assert tsp._fail_info(0) == bytes.fromhex("03020780")      # badAlg: бит 0, 7 неиспользуемых
    assert tsp._fail_info(5) == bytes.fromhex("03020204")      # badDataFormat: бит 5, 2 неиспользуемых
    node = asn1.parse(tsp._fail_info(25))
    unused, data = node.as_bit_string()
    assert (unused, len(data)) == (6, 4) and data[3] == 0x40


# ---------------- сертификат службы ----------------
def test_certificate_without_time_stamping_purpose_is_refused(tsa_keys, crypto):
    cert = x509.build_self_signed(tsa_keys[0], "Обычный ключ", crypto)  # без id-kp-timeStamping
    with pytest.raises(EcpError, match="не предназначен"):
        tsp.TimeStampAuthority(tsa_keys[0], cert, crypto)


def test_time_stamping_certificate_fields(tsa):
    info = tsa.cert
    assert info.key_purposes == [x509.OID_KP_TIME_STAMPING] and info.subject_cn == "Тестовая СШВ"


def test_cert_req_false_needs_trusted_key(tsa, crypto):
    resp = tsa.respond(tsp.build_request(imprint_of(), cert_req=False))
    token = tsp.parse_response_status(resp)[3]
    assert asn1.parse(token).children()[1].children()[0].children()  # токен разобран
    no_key = tsp.verify_token(token, imprint_of(), None, crypto)
    assert not no_key.ok and any("Сертификат службы" in c.name and not c.ok for c in no_key.checks)
    with_key = tsp.verify_token(token, imprint_of(), None, crypto, trusted_key=tsa.public_key)
    assert with_key.ok, [(c.name, c.detail) for c in with_key.checks if not c.ok]


def test_cert_req_true_embeds_certificate(tsa, crypto):
    token = tsp.parse_response_status(tsa.respond(tsp.build_request(imprint_of(), cert_req=True)))[3]
    assert tsp.verify_token(token, imprint_of(), None, crypto).ok  # ключ берётся из штампа


def test_wrong_trusted_key_rejected(tsa, crypto):
    token = tsp.parse_response_status(tsa.respond(tsp.build_request(imprint_of())))[3]
    other = ecp.generate_keypair()[1]
    result = tsp.verify_token(token, imprint_of(), None, crypto, trusted_key=other)
    assert not result.ok and any("доверенным" in c.name and not c.ok for c in result.checks)


def test_tampered_token_detected(tsa, crypto):
    token = bytearray(tsp.parse_response_status(tsa.respond(tsp.build_request(imprint_of())))[3])
    i = bytes(token).index(asn1.oid(tsp.DEMO_POLICY)) + 12
    token[i] ^= 0x01  # меняем байт внутри TSTInfo
    try:
        result = tsp.verify_token(bytes(token), imprint_of(), None, crypto)
    except EcpError:
        return  # структура разрушена - тоже обнаружено
    assert not result.ok


def test_stale_time_is_detected(tsa_keys, crypto):
    cert = x509.build_self_signed(tsa_keys[0], "СШВ с отставшими часами", crypto, time_stamping=True)
    old = tsp.TimeStampAuthority(tsa_keys[0], cert, crypto,
                                 clock=lambda: datetime.now(timezone.utc) - timedelta(days=1))
    resp = old.respond(tsp.build_request(imprint_of()))
    result = tsp.verify_response(resp, imprint_of(), None, crypto, now=datetime.now(timezone.utc))
    assert not result.ok and any("Время штампа" in c.name and not c.ok for c in result.checks)


def test_generalized_time_with_fraction():
    node = asn1.parse(asn1.tlv(asn1.GENERALIZED_TIME, b"20170325132100.3Z"))
    assert node.as_time() == datetime(2017, 3, 25, 13, 21, 0, tzinfo=timezone.utc)


# ---------------- CAdES-B-T ----------------
@pytest.fixture(scope="module")
def signer(crypto):
    d, q = ecp.generate_keypair()
    return d, q, x509.build_self_signed(d, "Подписант", crypto)


def test_cades_bt_roundtrip(signer, tsa, crypto):
    d, q, cert = signer
    cms = cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=tsp.make_provider(tsa, crypto))
    result = cades.verify_cades(cms, DATA, crypto, trusted_tsa_key=tsa.public_key)
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    assert result.timestamped and result.timestamp.tsa_name == "Тестовая СШВ"
    assert any(c.name.startswith("Штамп времени:") for c in result.checks)
    assert result.notes == []


def test_cades_bt_without_trusted_key_adds_note(signer, tsa, crypto):
    d, q, cert = signer
    cms = cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=tsp.make_provider(tsa, crypto))
    result = cades.verify_cades(cms, DATA, crypto)
    assert result.ok and any("не проверена на доверие" in n for n in result.notes)


def test_cades_bt_wrong_tsa_key(signer, tsa, crypto):
    d, q, cert = signer
    cms = cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=tsp.make_provider(tsa, crypto))
    result = cades.verify_cades(cms, DATA, crypto, trusted_tsa_key=ecp.generate_keypair()[1])
    assert not result.ok


def test_cades_bb_has_no_timestamp(signer, crypto):
    d, q, cert = signer
    result = cades.verify_cades(cades.build_cades_bb(DATA, d, cert, crypto), DATA, crypto)
    assert result.ok and not result.timestamped and result.timestamp is None


def test_cades_bt_attached_and_modified_data(signer, tsa, crypto):
    d, q, cert = signer
    provider = tsp.make_provider(tsa, crypto)
    cms = cades.build_cades_bb(DATA, d, cert, crypto, attach=True, timestamp_provider=provider)
    assert cades.verify_cades(cms, None, crypto, trusted_tsa_key=tsa.public_key).ok
    assert not cades.verify_cades(cms, DATA + b"!", crypto).ok


def test_cades_bt_tampered_signature_breaks_both(signer, tsa, crypto):
    d, q, cert = signer
    cms = bytearray(cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=tsp.make_provider(tsa, crypto)))
    oid_bytes = asn1.oid(cades.OID_SIGNING_TIME)
    cms[cms.index(oid_bytes) + len(oid_bytes) + 9] ^= 0x01  # время подписания в подписываемых атрибутах
    result = cades.verify_cades(bytes(cms), DATA, crypto, trusted_tsa_key=tsa.public_key)
    assert not result.ok


def test_signing_time_after_stamp_is_detected(signer, tsa_keys, crypto):
    d, q, cert = signer
    cert_tsa = x509.build_self_signed(tsa_keys[0], "СШВ в прошлом", crypto, time_stamping=True)
    past = tsp.TimeStampAuthority(tsa_keys[0], cert_tsa, crypto,
                                  clock=lambda: datetime.now(timezone.utc) - timedelta(hours=1))
    # провайдер проверяет время сам, поэтому собираем токен вручную
    def provider(imprint):
        resp = past.respond(tsp.build_request(imprint, nonce=7))
        return tsp.parse_response_status(resp)[3]
    cms = cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=provider)
    result = cades.verify_cades(cms, DATA, crypto, trusted_tsa_key=past.public_key)
    assert not result.ok
    assert any("не позднее времени штампа" in c.name and not c.ok for c in result.checks)


def test_provider_refuses_stale_stamp(signer, tsa_keys, crypto):
    d, q, cert = signer
    cert_tsa = x509.build_self_signed(tsa_keys[0], "СШВ в прошлом", crypto, time_stamping=True)
    past = tsp.TimeStampAuthority(tsa_keys[0], cert_tsa, crypto,
                                  clock=lambda: datetime.now(timezone.utc) - timedelta(days=2))
    with pytest.raises(EcpError, match="не прошёл проверку"):
        cades.build_cades_bb(DATA, d, cert, crypto, timestamp_provider=tsp.make_provider(past, crypto))
