"""Набор криптопримитивов, нужных форматам (CMS, X.509). По умолчанию - Rust-ядро.

Отдельный интерфейс позволяет проверять разбор/сборку ASN.1 независимо от ядра.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class Crypto:
    hash: Callable[[bytes], bytes]  # belt-hash
    sign: Callable[[bytes, bytes], bytes]  # (d, X) -> S, 48 байт
    verify: Callable[[bytes, bytes, bytes], bool]  # (Q, X, S) -> ДА/НЕТ
    derive_public_key: Callable[[bytes], bytes]  # d -> Q
    check_public_key: Callable[[bytes], None]  # п. 6.2.3, EcpError при НЕТ


def default_crypto() -> Crypto:
    from . import _core
    from .curve import check_public_key

    return Crypto(
        hash=_core.belt_hash,
        sign=_core.sign,
        verify=_core.verify,
        derive_public_key=_core.derive_public_key,
        check_public_key=check_public_key,
    )
