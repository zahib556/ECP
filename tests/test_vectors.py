"""Проверка по официальным тестовым примерам стандартов.

СТБ 34.101.31-2020, табл. А.23 (belt-hash)
СТБ 34.101.47-2017, табл. В.1 (hmac-hbelt), В.2 (brng-ctr-hbelt)
СТБ 34.101.66-2014, табл. Б.1-Б.2 (пары ключей bign-curve256v1)
"""
import pytest

import ecp


def h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


# ---------- belt-hash ----------
BELT_HASH = [
    (
        "B194BAC8 0A08F53B 366D008E 58",
        "ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75",
    ),
    (
        "B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D",
        "749E4C36 53AECE5E 48DB4761 227742EB 6DBE13F4 A80F7BEF F1A9CF8D 10EE7786",
    ),
    (
        "B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D "
        "5BE3D612 17B96181 FE6786AD 716B890B",
        "9D02EE44 6FB6A29F E5C982D4 B13AF9D3 E90861BC 4CEF27CF 306BFB0B 174A154A",
    ),
]


@pytest.mark.parametrize("x,y", BELT_HASH)
def test_belt_hash(x, y):
    assert ecp.belt_hash(h(x)) == h(y)


# ---------- hmac-hbelt (три ветки: ключ короче, равен и длиннее блока 32 байта) ----------
HMAC_X = "BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF8C A58450BF 66D2E88A"
HMAC_K32 = "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6"
HMAC = [
    (
        "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03",
        "D4828E63 12B08BB8 3C9FA653 5A463554 9E411FD1 1C0D8289 359A1130 E930676B",
    ),
    (
        HMAC_K32,
        "41FFE864 5AEC0612 E952D2CD F8DD508F 3E4A1D9B 53F6A1DB 293B19FE 76B1879F",
    ),
    (
        HMAC_K32 + " 92BD9B1C E5D14101 5445",
        "7D01B84D 2315C332 277B3653 D7EC6470 7EBA7CDF F7FF7007 7B1DECBD 68F2A144",
    ),
]


@pytest.mark.parametrize("k,y", HMAC)
def test_hmac_hbelt(k, y):
    assert ecp.hmac_hbelt(h(k), h(HMAC_X)) == h(y)


# ---------- brng-ctr-hbelt ----------
BRNG_K = HMAC_K32
BRNG_S = HMAC_X
BRNG_X = (
    "B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D "
    "5BE3D612 17B96181 FE6786AD 716B890B 5CB0C0FF 33C356B8 35C405AE D8E07F99 "
    "E12BDC1A E28257EC 703FCCF0 95EE8DF1 C1AB7638 9FE678CA F7C6F860 D5BB9C4F"
)
BRNG_Y = (
    "1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269 "
    "4C0E74B2 CD5811AD 21F23DE7 E0FA742C 3ED6EC48 3C461CE1 5C33A77A A308B7D2 "
    "0F51D913 47617C20 BD4AB07A EF4F26A1 AD1362A8 F9A3D42F BE1B8E6F 1C88AAD5"
)


def test_brng_ctr_standard_vector():
    out = ecp.brng_ctr(h(BRNG_K), h(BRNG_S), 3, h(BRNG_X))
    assert out == h(BRNG_Y)


def test_brng_ctr_default_additional_is_zero():
    key, iv = bytes(range(32)), bytes(range(32, 64))
    assert ecp.brng_ctr(key, iv, 2) == ecp.brng_ctr(key, iv, 2, bytes(64))


def test_brng_ctr_rejects_bad_input():
    with pytest.raises(ValueError):
        ecp.brng_ctr(b"\x00" * 31, b"\x00" * 32, 1)
    with pytest.raises(ValueError):
        ecp.brng_ctr(b"\x00" * 32, b"\x00" * 32, 0)
    with pytest.raises(ValueError):
        ecp.brng_ctr(b"\x00" * 32, b"\x00" * 32, 2, b"\x00" * 10)


# ---------- ключи bign-curve256v1 (формат байт как в стандарте) ----------
KEYS = [
    # (d, Q): стороны A и B из СТБ 34.101.66, табл. Б.1
    (
        "1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269",
        "BD1A5650 179D79E0 3FCEE49D 4C2BD5DD F54CE46D 0CF11E4F F87BF7A8 90857FD0 "
        "7AC6A603 61E8C817 3491686D 461B2826 190C2EDA 5909054A 9AB84D2A B9D99A90",
    ),
    (
        "4C0E74B2 CD5811AD 21F23DE7 E0FA742C 3ED6EC48 3C461CE1 5C33A77A A308B7D2",
        "CCEEF1A3 13A40664 9D15DA0A 851D486A 695B641B 20611776 252FFDCE 39C71060 "
        "7C9EA1F3 3C23D20D FCB8485A 88BE6523 A28ECC32 15B47FA2 89D6C9BE 1CE837C0",
    ),
    # одноразовые ключи (u, V) из табл. Б.2
    (
        "0F51D913 47617C20 BD4AB07A EF4F26A1 AD1362A8 F9A3D42F BE1B8E6F 1C88AAD5",
        "9B4EA669 DABDF100 A7D4B6E6 EB76EE52 51912531 F426750A AC8A9DBB 51C54D8D "
        "6AB7DBF1 5FCBD768 EE68A173 F7B236EF C15A01E2 AA6CD1FE 98B947DA 7B38A2A0",
    ),
    (
        "0A4E8298 BE0839E4 6F19409F 637F4415 572251DD 0D39284F 0F0390D9 3BBCE9EC",
        "1D5A382B 962D4ED0 6193258C A6DE535D 8FD7FACB 853171E9 32EF93B5 EE800120 "
        "03DBB7B5 BD070363 80BAFA47 FCA7E6CA 3F179EDD D1AE5086 64790918 3628EDDC",
    ),
]


@pytest.mark.parametrize("d,q", KEYS)
def test_public_key_matches_standard(d, q):
    assert ecp.derive_public_key(h(d)) == h(q)


@pytest.mark.parametrize("d,q", KEYS[:2])
def test_sign_verify_with_standard_keys(d, q):
    msg = b"test"
    sig = ecp.sign(h(d), msg)
    assert ecp.verify(h(q), msg, sig) is True
    assert ecp.verify(h(q), msg + b"x", sig) is False


def test_generated_keypair_is_consistent():
    d, q = ecp.generate_keypair()
    assert ecp.derive_public_key(d) == q


def test_brng_output_is_the_standard_private_key():
    """В СТБ 34.101.66 личные ключи сторон получены генератором brng-ctr-hbelt."""
    out = ecp.brng_ctr(h(BRNG_K), h(BRNG_S), 1, h(BRNG_X)[:32])
    assert out == h(KEYS[0][0])
