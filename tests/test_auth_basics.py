"""Пароли (PBKDF2), токены (JWT HS256) и отпечаток устройства: без базы данных."""
import base64
import hashlib
import json

import pytest

from ecp.auth import device, passwords, tokens

KEY = b"k" * 32


# ------------------------------------------------------------------ пароли
def test_hash_has_unique_salt_and_enough_iterations():
    s1, s2 = passwords.new_salt(), passwords.new_salt()
    assert s1 != s2 and len(bytes.fromhex(s1)) == passwords.SALT_BYTES
    h1, h2 = passwords.hash_password("Secret-123", s1), passwords.hash_password("Secret-123", s2)
    assert h1 != h2  # одинаковый пароль, разная соль - разные хэши
    algorithm, iterations, digest = h1.split("$")
    assert algorithm == "pbkdf2_sha256" and int(iterations) >= 200_000 and len(digest) == 64
    assert "Secret-123" not in h1


def test_hash_matches_reference_pbkdf2():
    salt = "00112233445566778899aabbccddeeff"
    expected = hashlib.pbkdf2_hmac("sha256", b"pass", bytes.fromhex(salt), passwords.ITERATIONS).hex()
    assert passwords.hash_password("pass", salt).endswith("$" + expected)


def test_verify_password():
    salt = passwords.new_salt()
    stored = passwords.hash_password("Правильный-1", salt)
    assert passwords.verify_password("Правильный-1", salt, stored)
    assert not passwords.verify_password("Правильный-2", salt, stored)
    assert not passwords.verify_password("Правильный-1", passwords.new_salt(), stored)
    assert not passwords.verify_password("x", salt, "мусор")
    weak = stored.replace(f"${passwords.ITERATIONS}$", "$1000$")  # хэш со слишком малым числом итераций
    assert not passwords.verify_password("Правильный-1", salt, weak)


def test_too_few_iterations_rejected():
    with pytest.raises(ValueError):
        passwords.hash_password("x", passwords.new_salt(), iterations=1000)


def test_strength_scale():
    expected = {"": 0, "abc": 0, "password": 0, "aaaaaaaaaaaaaaaaaaaa": 0, "abcdefgh": 1,
                "Abcdefg1": 2, "Hunter2-ok": 3, "Abcdefg1xyz!": 4, "Tr0ub4dor&3-horse-battery": 4}
    for text, score in expected.items():
        assert passwords.strength(text)[0] == score, text
    assert passwords.strength("Hunter2-ok") == (3, "хороший")
    assert passwords.strength("") == (0, "очень слабый")


def test_policy():
    assert passwords.policy_problems("Hunter2-ok") == []
    assert passwords.policy_problems("short1")  # короткий
    assert passwords.policy_problems("onlyletters")  # одни буквы
    assert passwords.policy_problems("12345678")  # из списка простых
    assert passwords.policy_problems("a" * 200)


# ------------------------------------------------------------------ токены
def test_token_roundtrip():
    token = tokens.encode({"sub": 1, "exp": 2000}, KEY)
    assert token.count(".") == 2
    assert tokens.decode(token, KEY, now=1000)["sub"] == 1


def test_token_expiry():
    token = tokens.encode({"sub": 1, "exp": 2000}, KEY)
    with pytest.raises(tokens.TokenExpired):
        tokens.decode(token, KEY, now=2000)
    assert tokens.decode(token, KEY, now=5000, verify_exp=False)["sub"] == 1


def test_token_tampering_rejected():
    token = tokens.encode({"sub": 1, "exp": 2000}, KEY)
    header, payload, sig = token.split(".")
    forged = base64.urlsafe_b64encode(json.dumps({"sub": 2, "exp": 2000}).encode()).rstrip(b"=").decode()
    for bad in (f"{header}.{forged}.{sig}", token[:-2] + ("AA" if not token.endswith("AA") else "BB")):
        with pytest.raises(tokens.TokenError):
            tokens.decode(bad, KEY, now=1000)
    with pytest.raises(tokens.TokenError):
        tokens.decode(token, b"x" * 32, now=1000)  # чужой ключ


def test_token_alg_none_and_garbage_rejected():
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    unsigned = f"{b64({'alg': 'none'})}.{b64({'sub': 1, 'exp': 9999})}."
    for bad in (unsigned, "abc", "a.b.c", "", "x" * 5000):
        with pytest.raises(tokens.TokenError):
            tokens.decode(bad, KEY, now=1000)
    with pytest.raises(tokens.TokenError):
        tokens.decode(tokens.encode({"sub": 1}, KEY), KEY, now=1000)  # нет exp


# ------------------------------------------------------------------ отпечаток устройства
def test_fingerprint_formula():
    info = device.DeviceInfo("host", "Windows 11", "aabbccddeeff", "guid-1")
    assert device.fingerprint(info) == hashlib.sha256(b"host|Windows 11|aabbccddeeff|guid-1").hexdigest()


def test_fingerprint_changes_with_any_component():
    base = device.DeviceInfo("h", "p", "m", "id")
    ids = {device.fingerprint(base)}
    for changed in (device.DeviceInfo("h2", "p", "m", "id"), device.DeviceInfo("h", "p2", "m", "id"),
                    device.DeviceInfo("h", "p", "m2", "id"), device.DeviceInfo("h", "p", "m", "id2")):
        ids.add(device.fingerprint(changed))
    assert len(ids) == 5


def test_current_device_id_is_stable_and_valid():
    first = device.current_device_id()
    assert first == device.current_device_id() and device.is_valid_device_id(first)
    info = device.collect()
    assert info.hostname and info.platform and len(info.mac) == 12


def test_device_id_validation():
    assert device.is_valid_device_id("a" * 64)
    for bad in (None, "", "a" * 63, "A" * 64, "g" * 64, 5):
        assert not device.is_valid_device_id(bad)
