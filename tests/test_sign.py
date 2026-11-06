import pytest

import ecp

MSG = "Тестовое сообщение".encode("utf-8")


def test_keypair_sizes():
    d, q = ecp.generate_keypair()
    assert len(d) == 32
    assert len(q) == 64


def test_keypairs_are_different():
    assert ecp.generate_keypair()[0] != ecp.generate_keypair()[0]


def test_sign_verify_roundtrip():
    d, q = ecp.generate_keypair()
    sig = ecp.sign(d, MSG)
    assert len(sig) == 48
    assert ecp.verify(q, MSG, sig) is True


def test_wrong_message_is_rejected():
    d, q = ecp.generate_keypair()
    sig = ecp.sign(d, MSG)
    assert ecp.verify(q, MSG + b"!", sig) is False


def test_wrong_key_is_rejected():
    d, _ = ecp.generate_keypair()
    _, other_q = ecp.generate_keypair()
    sig = ecp.sign(d, MSG)
    assert ecp.verify(other_q, MSG, sig) is False


def test_corrupted_signature_is_rejected():
    d, q = ecp.generate_keypair()
    sig = bytearray(ecp.sign(d, MSG))
    sig[0] ^= 0x01  # портим S0
    assert ecp.verify(q, MSG, bytes(sig)) is False


def test_empty_message():
    d, q = ecp.generate_keypair()
    assert ecp.verify(q, b"", ecp.sign(d, b"")) is True


def test_bad_private_key_length():
    with pytest.raises(ValueError, match="неверный формат ключа"):
        ecp.sign(b"\x01" * 31, MSG)


def test_bad_public_key_length():
    d, _ = ecp.generate_keypair()
    with pytest.raises(ValueError, match="неверный формат ключа"):
        ecp.verify(b"\x01" * 63, MSG, ecp.sign(d, MSG))


def test_bad_signature_length():
    _, q = ecp.generate_keypair()
    with pytest.raises(ValueError, match="длина подписи"):
        ecp.verify(q, MSG, b"\x00" * 47)
