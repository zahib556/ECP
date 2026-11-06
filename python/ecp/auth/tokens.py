"""JWT (HS256) на стандартной библиотеке: подпись HMAC-SHA256, срок жизни, привязка к устройству."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict


class TokenError(Exception):
    """Токен повреждён, подделан или имеет неверный формат."""


class TokenExpired(TokenError):
    """Срок жизни токена истёк."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise TokenError("неверная кодировка токена") from None


def _sign(signing_input: str, key: bytes) -> str:
    return _b64e(hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest())


def encode(claims: Dict[str, Any], key: bytes) -> str:
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header}.{payload}"
    return f"{signing_input}.{_sign(signing_input, key)}"


def decode(token: str, key: bytes, now: int, verify_exp: bool = True) -> Dict[str, Any]:
    """Проверяет подпись (алгоритм строго HS256) и срок. Возвращает claims."""
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 4096:
        raise TokenError("неверный формат токена")
    header_b64, payload_b64, signature = token.split(".")
    try:
        header = json.loads(_b64d(header_b64))
    except ValueError:
        raise TokenError("неверный заголовок токена") from None
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise TokenError("неподдерживаемый алгоритм подписи")
    expected = _sign(f"{header_b64}.{payload_b64}", key)
    if not hmac.compare_digest(expected.encode("ascii"), signature.encode("ascii", "replace")):
        raise TokenError("подпись токена не совпадает")
    try:
        claims = json.loads(_b64d(payload_b64))
    except ValueError:
        raise TokenError("неверное содержимое токена") from None
    if not isinstance(claims, dict) or not isinstance(claims.get("exp"), int):
        raise TokenError("в токене нет срока действия")
    if verify_exp and now >= claims["exp"]:
        raise TokenExpired("срок действия токена истёк")
    return claims
