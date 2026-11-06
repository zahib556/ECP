import ecp


def test_core_loaded():
    assert ecp.core_version() == "0.1.0"


def test_belt_hash_length():
    assert len(ecp.belt_hash(b"abc")) == 32


def test_belt_hash_standard_vector():
    # Тестовый пример СТБ 34.101.31, приложение А (belt-hash, первый пример)
    msg = bytes.fromhex("B194BAC80A08F53B366D008E58")
    expected = "ABEF9725D4C5A83597A367D14494CC2542F20F659DDFECC961A3EC550CBA8C75"
    assert ecp.belt_hash(msg).hex().upper() == expected
