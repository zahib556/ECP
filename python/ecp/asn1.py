"""Минимальные кодирование (DER) и разбор ASN.1 (ГОСТ 34.974 / X.690).

Поддерживаются однобайтовые теги и определённая длина. Этого достаточно для CMS и X.509
в объёме проекта. Значения SET OF кодируются по отличительным правилам (сортировка).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Tuple

BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x30
SET = 0x31
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18


class Asn1Error(ValueError):
    """Ошибка кодирования или разбора ASN.1."""


# ------------------------------------------------------------------ кодирование
def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(items: Iterable[bytes]) -> bytes:
    """SET OF по отличительным правилам: элементы упорядочены по возрастанию кодов."""
    return tlv(SET, b"".join(sorted(items)))


def explicit(n: int, inner: bytes) -> bytes:
    return tlv(0xA0 | n, inner)


def integer(n: int) -> bytes:
    if n < 0:
        raise Asn1Error("отрицательные INTEGER не поддерживаются")
    return tlv(INTEGER, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def octet_string(data: bytes) -> bytes:
    return tlv(OCTET_STRING, data)


def bit_string(data: bytes, unused: int = 0) -> bytes:
    return tlv(BIT_STRING, bytes([unused]) + data)


def null() -> bytes:
    return b"\x05\x00"


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def utf8_string(text: str) -> bytes:
    return tlv(UTF8_STRING, text.encode("utf-8"))


def oid(dotted: str) -> bytes:
    try:
        arcs = [int(x) for x in dotted.split(".")]
    except ValueError:
        raise Asn1Error(f"неверный идентификатор объекта: {dotted}") from None
    if len(arcs) < 2 or any(a < 0 for a in arcs) or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        raise Asn1Error(f"неверный идентификатор объекта: {dotted}")
    values = [40 * arcs[0] + arcs[1]] + arcs[2:]
    out = bytearray()
    for v in values:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out.extend(reversed(chunk))
    return tlv(OID, bytes(out))


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def generalized_time(dt: datetime) -> bytes:
    """GeneralizedTime в формате YYYYMMDDhhmmssZ (СТБ 34.101.82, п. 7.2: секунды обязательны)."""
    return tlv(GENERALIZED_TIME, _utc(dt).replace(microsecond=0).strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def time_choice(dt: datetime) -> bytes:
    """Time по СТБ 34.101.23 (15.4): 1950-2049 - UTCTime, иначе GeneralizedTime; секунды обязательны."""
    dt = _utc(dt).replace(microsecond=0)
    if 1950 <= dt.year <= 2049:
        return tlv(UTC_TIME, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return tlv(GENERALIZED_TIME, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


# ------------------------------------------------------------------ разбор
@dataclass(frozen=True)
class Node:
    tag: int
    content: bytes
    raw: bytes  # полный TLV, как в исходных данных

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> List["Node"]:
        if not self.constructed:
            raise Asn1Error("примитивный элемент не содержит вложенных")
        return parse_all(self.content)

    def expect(self, tag: int, what: str) -> "Node":
        if self.tag != tag:
            raise Asn1Error(f"{what}: ожидался тег 0x{tag:02X}, получен 0x{self.tag:02X}")
        return self

    def as_int(self) -> int:
        self.expect(INTEGER, "INTEGER")
        return int.from_bytes(self.content, "big", signed=True)

    def as_oid(self) -> str:
        self.expect(OID, "OBJECT IDENTIFIER")
        return decode_oid(self.content)

    def as_bit_string(self) -> Tuple[int, bytes]:
        self.expect(BIT_STRING, "BIT STRING")
        if not self.content:
            raise Asn1Error("пустой BIT STRING")
        return self.content[0], self.content[1:]

    def as_octets(self) -> bytes:
        return self.expect(OCTET_STRING, "OCTET STRING").content

    def as_bool(self) -> bool:
        self.expect(BOOLEAN, "BOOLEAN")
        return self.content != b"\x00"

    def as_time(self) -> datetime:
        text = self.content.decode("ascii", errors="replace")
        try:
            if self.tag == UTC_TIME:
                year = int(text[0:2])
                year += 1900 if year >= 50 else 2000
                rest = text[2:]
            elif self.tag == GENERALIZED_TIME:
                year, rest = int(text[0:4]), re.sub(r"\.\d+Z$", "Z", text[4:])  # дробные секунды отбрасываются
            else:
                raise Asn1Error("ожидалось время (UTCTime или GeneralizedTime)")
            if not rest.endswith("Z") or len(rest) != 11:
                raise Asn1Error("время должно быть в формате ...Z с секундами")
            return datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                            int(rest[6:8]), int(rest[8:10]), tzinfo=timezone.utc)
        except ValueError as e:
            raise Asn1Error(f"неверное значение времени: {e}") from None


def decode_oid(content: bytes) -> str:
    if not content:
        raise Asn1Error("пустой идентификатор объекта")
    arcs: List[int] = []
    value = 0
    for b in content:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(value)
            value = 0
    if content[-1] & 0x80:
        raise Asn1Error("неполный идентификатор объекта")
    first = arcs[0]
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return ".".join(str(x) for x in (*head, *arcs[1:]))


def parse_tlv(data: bytes, pos: int = 0) -> Tuple[Node, int]:
    if pos + 2 > len(data):
        raise Asn1Error("неожиданный конец данных")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("многобайтовые теги не поддерживаются")
    first = data[pos + 1]
    p = pos + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise Asn1Error("неопределённая длина (BER) не поддерживается")
    else:
        n = first & 0x7F
        if n > 4 or p + n > len(data):
            raise Asn1Error("неверная длина элемента")
        length = int.from_bytes(data[p:p + n], "big")
        p += n
    end = p + length
    if end > len(data):
        raise Asn1Error("элемент выходит за границы данных")
    return Node(tag, data[p:end], data[pos:end]), end


def parse(data: bytes) -> Node:
    node, end = parse_tlv(data, 0)
    if end != len(data):
        raise Asn1Error("лишние данные после элемента")
    return node


def parse_all(data: bytes) -> List[Node]:
    nodes: List[Node] = []
    pos = 0
    while pos < len(data):
        node, pos = parse_tlv(data, pos)
        nodes.append(node)
    return nodes
