"""Слой приложения: файлы, ошибки, самотестирование, проверка открытого ключа."""
import pytest

import ecp
from ecp import service
from ecp.curve import check_public_key
from ecp.errors import EcpError

Q_A = bytes.fromhex(
    "BD1A5650179D79E03FCEE49D4C2BD5DDF54CE46D0CF11E4FF87BF7A890857FD0"
    "7AC6A60361E8C8173491686D461B2826190C2EDA5909054A9AB84D2AB9D99A90"
)


@pytest.fixture()
def keys(tmp_path):
    return service.generate_keys(tmp_path / "keys")


def test_generate_keys_files(keys):
    assert keys.private_path.stat().st_size == 32
    assert keys.public_path.stat().st_size == 64
    assert keys.consistent


def test_generate_keys_does_not_overwrite(keys):
    with pytest.raises(EcpError, match="уже есть"):
        service.generate_keys(keys.private_path.parent)
    service.generate_keys(keys.private_path.parent, overwrite=True)


def test_sign_and_verify_files(tmp_path, keys):
    msg = tmp_path / "m.txt"
    msg.write_bytes("Тестовое сообщение".encode("utf-8"))
    sig = tmp_path / "signature.bin"
    result = service.sign_file(msg, keys.private_path, sig)
    assert sig.stat().st_size == 48
    assert result.message_hash == ecp.belt_hash(msg.read_bytes())
    assert service.verify_files(msg, sig, keys.public_path).ok is True


def test_modified_message_is_rejected(tmp_path, keys):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    sig = tmp_path / "s.bin"
    service.sign_file(msg, keys.private_path, sig)
    msg.write_bytes(b"abd")
    assert service.verify_files(msg, sig, keys.public_path).ok is False


def test_demo_corrupted_signature(tmp_path, keys):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    sig = tmp_path / "s.bin"
    service.sign_file(msg, keys.private_path, sig)
    result = service.verify_files(msg, sig, keys.public_path, corrupt=True)
    assert result.ok is False and result.corrupted_demo is True


def test_missing_file(tmp_path, keys):
    with pytest.raises(EcpError, match="не удалось прочитать"):
        service.sign_file(tmp_path / "нет.txt", keys.private_path, tmp_path / "s.bin")


def test_bad_private_key_file(tmp_path):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    bad = tmp_path / "private.key"
    bad.write_bytes(b"\x01" * 31)
    with pytest.raises(EcpError, match="неверный формат ключа"):
        service.sign_file(msg, bad, tmp_path / "s.bin")
    bad.write_bytes(bytes(32))  # d = 0
    with pytest.raises(EcpError, match="диапазона"):
        service.sign_file(msg, bad, tmp_path / "s.bin")


def test_bad_signature_length(tmp_path, keys):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    sig = tmp_path / "s.bin"
    sig.write_bytes(b"\x00" * 47)
    with pytest.raises(EcpError, match="длина подписи"):
        service.verify_files(msg, sig, keys.public_path)


def test_signature_with_s1_not_less_than_q(tmp_path, keys):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    sig = tmp_path / "s.bin"
    sig.write_bytes(b"\x00" * 16 + b"\xff" * 32)  # S1 >= q
    with pytest.raises(EcpError, match="S1"):
        service.verify_files(msg, sig, keys.public_path)


def test_public_key_check():
    check_public_key(Q_A)
    bad = bytearray(Q_A)
    bad[40] ^= 0x01
    with pytest.raises(EcpError, match="не принадлежит"):
        check_public_key(bytes(bad))
    with pytest.raises(EcpError, match="неверный формат"):
        check_public_key(Q_A[:63])


def test_public_key_file_off_curve(tmp_path):
    msg = tmp_path / "m.txt"
    msg.write_bytes(b"abc")
    sig = tmp_path / "s.bin"
    sig.write_bytes(b"\x00" * 48)
    pub = tmp_path / "public.key"
    pub.write_bytes(b"\x01" * 64)
    with pytest.raises(EcpError, match="не принадлежит"):
        service.verify_files(msg, sig, pub)


def test_self_test_passes():
    results = service.self_test()
    failed = [r for r in results if not r.ok and "Целостность" not in r.name and "Подлинность" not in r.name]
    assert not failed, failed


def test_format_hex():
    assert service.format_hex(bytes(range(8))) == "00010203 04050607"
