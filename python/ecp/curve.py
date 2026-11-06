"""Параметры bign-curve256v1 (СТБ 34.101.45-2013, табл. Б.1) и проверка открытого ключа (п. 6.2.3).

Открытые данные, поэтому вычисления на целых числах Python допустимы.
"""
from __future__ import annotations

from .errors import EcpError

P = (1 << 256) - 189
A = (1 << 256) - 192
B = int.from_bytes(
    bytes.fromhex("F1039CD66B7D2EB253928B976950F54CBEFBD8E4AB3AC1D2EDA8F315156CCE77"),
    "little",
)
Q_ORDER = int.from_bytes(bytes.fromhex("07663D2699BF5A7EFC4DFB0DD68E5CD9") + b"\xff" * 16, "little")

PUBLIC_KEY_LEN = 64


def is_on_curve(x: int, y: int) -> bool:
    """Условия п. 6.2.3: 0 <= x, y < p и y^2 = x^3 + ax + b (mod p)."""
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def check_public_key(q: bytes) -> None:
    """Алгоритм проверки открытого ключа. При отрицательном результате - EcpError."""
    if len(q) != PUBLIC_KEY_LEN:
        raise EcpError("Ошибка: неверный формат ключа (открытый ключ: 64 байта)")
    x = int.from_bytes(q[:32], "little")
    y = int.from_bytes(q[32:], "little")
    if not is_on_curve(x, y):
        raise EcpError("Ошибка: открытый ключ не принадлежит эллиптической кривой")
