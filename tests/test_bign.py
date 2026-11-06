"""Проверка по Приложению Г СТБ 34.101.45-2013 (bign-curve256v1, h = belt-hash)."""
import pytest

import ecp


def h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


OID_BELT_HASH = h("06092A7000020022651F51")

D = h("1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269")
Q = h(
    "BD1A5650 179D79E0 3FCEE49D 4C2BD5DD F54CE46D 0CF11E4F F87BF7A8 90857FD0 "
    "7AC6A603 61E8C817 3491686D 461B2826 190C2EDA 5909054A 9AB84D2A B9D99A90"
)

# --- Г.2: выработка подписи (одноразовый ключ задан явно) ---
G2_X = h("B194BAC8 0A08F53B 366D008E 58")
G2_H = h("ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75")
G2_K = h("4C0E74B2 CD5811AD 21F23DE7 E0FA742C 3ED6EC48 3C461CE1 5C33A77A A308B7D2")
G2_S = h(
    "E36B7F03 77AE4C52 4027C387 FADF1B20 CE72F153 0B71F2B5 FD3A8C58 4FE2E1AE "
    "D20082E3 0C8AF650 11F4FB54 649DFD3D"
)

# --- Г.3: проверка подписи ---
G3_X = h(
    "B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D "
    "5BE3D612 17B96181 FE6786AD 716B890B"
)
G3_S = h(
    "47A63C8B 9C936E94 B5FAB3D9 CBD78366 290F3210 E163EEC8 DB4E921E 8479D413 "
    "8F112CC2 3E6DCE65 EC5FF21D F4231C28"
)

# --- Г.6, Г.7: одноразовый личный ключ (п. 6.3.3) ---
G6_THETA = h("D61E3A91 0550E3BC AD5BF4F5 26FB8DAA DEA9C132 E0BAEE03 169DF4DF 9BD6C20C")
G6_K = h("829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E")
G7_H = h("9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A")
G7_T = h("BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF")
G7_THETA = h("AE443163 32A85C3B 9F6B31EE EADFF088 D30FE507 021AC86A 3EC8E087 4ED33648")
G7_K = h("7ADC8713 283EBFA5 47A2AD9C DFB245AE 0F7B968D F0F91CB7 85D1F932 A3583107")


def test_g1_public_key():
    assert ecp.derive_public_key(D) == Q


def test_g2_hash_of_message():
    assert ecp.belt_hash(G2_X) == G2_H


def test_g3_verify_standard_signature():
    assert ecp.verify(Q, G3_X, G3_S) is True


def test_g2_verify_standard_signature():
    assert ecp.verify(Q, G2_X, G2_S) is True


def test_g3_tampered_message_rejected():
    assert ecp.verify(Q, G3_X + b"\x00", G3_S) is False


def test_g3_tampered_signature_rejected():
    bad = bytearray(G3_S)
    bad[20] ^= 0x01
    assert ecp.verify(Q, G3_X, bytes(bad)) is False


def test_g2_sign_with_explicit_k():
    assert ecp.sign_hash_with_k(D, G2_K, G2_H) == G2_S


def test_g6_theta():
    assert ecp.belt_hash(OID_BELT_HASH + D) == G6_THETA


def test_g6_gen_k_empty_t():
    assert ecp.gen_k(D, G2_H) == G6_K


def test_g7_theta():
    assert ecp.belt_hash(OID_BELT_HASH + D + G7_T) == G7_THETA


def test_g7_gen_k_with_t():
    assert ecp.gen_k(D, G7_H, G7_T) == G7_K


def test_sign_is_deterministic_and_valid():
    s1 = ecp.sign(D, G2_X)
    assert s1 == ecp.sign(D, G2_X)
    assert len(s1) == 48
    assert ecp.verify(Q, G2_X, s1) is True


def test_sign_uses_gen_k_per_standard():
    """sign() = sign_hash_with_k(d, gen_k(d, H), H), H = belt-hash(X)."""
    k = ecp.gen_k(D, G2_H)
    assert ecp.sign(D, G2_X) == ecp.sign_hash_with_k(D, k, G2_H)


def test_sign_hash_with_k_rejects_bad_k():
    with pytest.raises(ValueError):
        ecp.sign_hash_with_k(D, bytes(32), G2_H)  # k = 0
    with pytest.raises(ValueError):
        ecp.sign_hash_with_k(D, b"\xff" * 32, G2_H)  # k >= q
