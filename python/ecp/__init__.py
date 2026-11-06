"""Средство выработки и проверки ЭЦП (СТБ 34.101.45-2013)."""
from ._core import (
    belt_hash,
    brng_ctr,
    core_version,
    derive_public_key,
    gen_k,
    generate_keypair,
    hmac_hbelt,
    sign,
    sign_hash_with_k,
    verify,
)

__version__ = core_version()

__all__ = [
    "belt_hash",
    "brng_ctr",
    "core_version",
    "derive_public_key",
    "gen_k",
    "generate_keypair",
    "hmac_hbelt",
    "sign",
    "sign_hash_with_k",
    "verify",
]
