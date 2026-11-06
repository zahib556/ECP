"""Кодирование и разбор ASN.1 DER (ГОСТ 34.974) - не зависит от криптоядра."""
from datetime import datetime, timezone

import pytest

from ecp import asn1


def test_integer_encoding():
    assert asn1.integer(0) == bytes.fromhex("020100")
    assert asn1.integer(127) == bytes.fromhex("02017F")
    assert asn1.integer(128) == bytes.fromhex("02020080")  # старший бит -> ведущий нуль
    assert asn1.integer(256) == bytes.fromhex("02020100")


def test_length_encoding():
    assert asn1.encode_length(0) == b"\x00"
    assert asn1.encode_length(127) == b"\x7f"
    assert asn1.encode_length(128) == b"\x81\x80"
    assert asn1.encode_length(256) == b"\x82\x01\x00"


def test_oid_known_values():
    # rsaEncryption
    assert asn1.oid("1.2.840.113549.1.1.1") == bytes.fromhex("06092A864886F70D010101")
    # belt-hash из СТБ 34.101.45, п. 4.2.5
    assert asn1.oid("1.2.112.0.2.0.34.101.31.81") == bytes.fromhex("06092A7000020022651F51")


def test_oid_roundtrip():
    for text in ("1.2.840.113549.1.9.16.2.47", "2.5.4.3", "1.2.112.0.2.0.34.101.45.12", "2.100.3"):
        assert asn1.parse(asn1.oid(text)).as_oid() == text


def test_set_of_is_sorted():
    a, b = asn1.integer(5), asn1.integer(3)
    assert asn1.set_of([a, b]) == asn1.set_of([b, a])
    assert asn1.set_of([a, b]) == bytes([0x31, 6]) + b + a


def test_sequence_roundtrip():
    data = asn1.seq(asn1.integer(300), asn1.octet_string(b"abc"), asn1.null(), asn1.boolean(True))
    node = asn1.parse(data)
    kids = node.children()
    assert [k.tag for k in kids] == [asn1.INTEGER, asn1.OCTET_STRING, asn1.NULL, asn1.BOOLEAN]
    assert kids[0].as_int() == 300
    assert kids[1].as_octets() == b"abc"


def test_long_content():
    payload = bytes(range(256)) * 3
    node = asn1.parse(asn1.octet_string(payload))
    assert node.content == payload


def test_explicit_and_bitstring():
    node = asn1.parse(asn1.explicit(0, asn1.bit_string(b"\xc0", 6)))
    assert node.tag == 0xA0
    unused, data = node.children()[0].as_bit_string()
    assert (unused, data) == (6, b"\xc0")


def test_time_choice_and_parse():
    dt = datetime(2026, 10, 13, 8, 54, 7, tzinfo=timezone.utc)
    enc = asn1.time_choice(dt)
    assert enc[0] == asn1.UTC_TIME and enc[2:] == b"261013085407Z"
    assert asn1.parse(enc).as_time() == dt
    far = datetime(2075, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    enc2 = asn1.time_choice(far)
    assert enc2[0] == asn1.GENERALIZED_TIME
    assert asn1.parse(enc2).as_time() == far
    old = datetime(1999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert asn1.parse(asn1.time_choice(old)).as_time() == old


@pytest.mark.parametrize(
    "bad",
    [b"", b"\x30", b"\x30\x05\x01", b"\x30\x80\x00\x00", b"\x1f\x01\x00", b"\x02\x01\x00\x00"],
)
def test_parse_rejects_bad_data(bad):
    with pytest.raises(asn1.Asn1Error):
        asn1.parse(bad)


def test_negative_integer_not_supported():
    with pytest.raises(asn1.Asn1Error):
        asn1.integer(-1)
