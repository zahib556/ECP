"""Сертификат X.509 и расширенная ЭЦП CAdES-B-B на настоящем криптоядре."""
from datetime import datetime, timezone

import pytest

import ecp
from ecp import asn1, cades, service, x509
from ecp.cryptoif import default_crypto
from ecp.errors import EcpError

MSG = "Тестовое сообщение для расширенной подписи".encode("utf-8")


@pytest.fixture(scope="module")
def crypto():
    return default_crypto()


@pytest.fixture(scope="module")
def keypair():
    return ecp.generate_keypair()


@pytest.fixture(scope="module")
def cert(keypair, crypto):
    return x509.build_self_signed(keypair[0], "Иванов И.И.", crypto)


def test_certificate_fields(cert, keypair, crypto):
    info = x509.parse_certificate(cert)
    assert info.subject_cn == "Иванов И.И."
    assert info.issuer_der == info.subject_der
    assert info.public_key == keypair[1]
    assert info.sig_alg == x509.OID_BIGN_WITH_HBELT
    assert info.not_before < info.not_after
    assert x509.verify_certificate_signature(info, info.public_key, crypto) is True


def test_certificate_signature_detects_tampering(cert, crypto):
    info = x509.parse_certificate(cert)
    broken = bytearray(cert)
    broken[len(broken) // 2] ^= 0x01
    try:
        bad = x509.parse_certificate(bytes(broken))
    except EcpError:
        return  # структура разрушена - тоже обнаружено
    assert x509.verify_certificate_signature(bad, info.public_key, crypto) is False


def test_certificate_requires_name(keypair, crypto):
    with pytest.raises(EcpError, match="имя владельца"):
        x509.build_self_signed(keypair[0], "  ", crypto)


def test_cades_detached_roundtrip(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    result = cades.verify_cades(cms, MSG, crypto)
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    assert result.detached is True
    assert result.signer == "Иванов И.И."
    assert result.public_key == keypair[1]
    assert result.digest == ecp.belt_hash(MSG)


def test_cades_attached_roundtrip(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto, attach=True)
    result = cades.verify_cades(cms, None, crypto)
    assert result.ok and result.detached is False


def test_cades_detached_needs_message(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    with pytest.raises(EcpError, match="отделённая"):
        cades.verify_cades(cms, None, crypto)


def test_cades_signing_time_is_kept(cert, keypair, crypto):
    when = datetime(2026, 5, 17, 10, 30, 15, tzinfo=timezone.utc)
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto, signing_time=when)
    assert cades.verify_cades(cms, MSG, crypto).signing_time == when


def test_cades_modified_message(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    result = cades.verify_cades(cms, MSG + b"!", crypto)
    assert not result.ok
    assert any("MessageDigest" in c.name and not c.ok for c in result.checks)


def test_cades_modified_signed_attributes(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    # портим время подписания (атрибут signingTime): ЭЦП подписываемых атрибутов перестаёт сходиться
    oid_bytes = asn1.oid(cades.OID_SIGNING_TIME)
    start = cms.index(oid_bytes) + len(oid_bytes) + 4  # SET (2 байта) + UTCTime (2 байта)
    i = start + 5  # единицы дня в записи YYMMDDhhmmssZ
    broken = bytearray(cms)
    broken[i] = ord("0") if broken[i] != ord("0") else ord("1")
    result = cades.verify_cades(bytes(broken), MSG, crypto)
    assert not result.ok
    assert any("ЭЦП" in c.name and not c.ok for c in result.checks)


def test_cades_wrong_trusted_key(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    other_public = ecp.generate_keypair()[1]
    assert cades.verify_cades(cms, MSG, crypto, trusted_key=keypair[1]).ok
    result = cades.verify_cades(cms, MSG, crypto, trusted_key=other_public)
    assert not result.ok


def test_cades_certificate_must_match_key(cert, crypto):
    other_d = ecp.generate_keypair()[0]
    with pytest.raises(EcpError, match="не соответствует"):
        cades.build_cades_bb(MSG, other_d, cert, crypto)


@pytest.mark.parametrize("bad", [b"", b"\x30\x00", b"\x01\x02\x03", b"\x30\x03\x02\x01\x01"])
def test_cades_garbage_input(bad, crypto):
    with pytest.raises(EcpError):
        cades.verify_cades(bad, MSG, crypto)


def test_signed_attributes_are_der_sorted(cert, keypair, crypto):
    cms = cades.build_cades_bb(MSG, keypair[0], cert, crypto)
    signed_data = asn1.parse(cms).children()[1].children()[0]
    signer_info = signed_data.children()[-1].children()[0].children()
    attrs = [n for n in signer_info if n.tag == 0xA0][0].children()
    codes = [a.raw for a in attrs]
    assert codes == sorted(codes)


# ---------------- слой приложения ----------------
def test_service_cades_files(tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    msg = tmp_path / "doc.txt"
    msg.write_bytes(MSG)
    out = tmp_path / "signature.p7s"
    res = service.sign_cades_file(msg, keys.private_path, out, "Петров П.П.")
    assert out.exists() and service.is_cades_data(out.read_bytes())
    assert res.signer == "Петров П.П."
    ok = service.verify_cades_file(msg, out)
    assert ok.ok and ok.signer == "Петров П.П."
    assert service.verify_cades_file(msg, out, keys.public_path).ok
    msg.write_bytes(MSG + b"x")
    assert not service.verify_cades_file(msg, out).ok


def test_is_cades_data_distinguishes_raw_signature():
    assert service.is_cades_data(b"\x30" * 48) is False
    assert service.is_cades_data(b"\x30" + b"\x00" * 300) is True
    assert service.is_cades_data(b"") is False


def test_service_cades_requires_name(tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    msg = tmp_path / "doc.txt"
    msg.write_bytes(MSG)
    with pytest.raises(EcpError, match="имя владельца"):
        service.sign_cades_file(msg, keys.private_path, tmp_path / "s.p7s", "")
