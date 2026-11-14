"""Манифест обновления: формат, проверка полей, подпись Ed25519 (открытый ключ вшит в приложение).

Подписывается каноническая форма манифеста без поля «signature» (ключи по алфавиту, без пробелов, UTF-8).
Подпись хранится в manifest.sig (base64) и/или в поле «signature»; если указаны оба и различаются - отказ.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from ..errors import EcpError
from . import versions

MAX_MANIFEST_BYTES = 64 * 1024
MAX_PACKAGE_SIZE = 4 * 1024 ** 3
OS_NAMES = ("windows", "linux", "macos")
ARCHES = ("x64", "arm64", "x86")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ManifestError(EcpError):
    """Манифест повреждён, подделан или не подходит."""


class SignatureError(ManifestError):
    """Подпись манифеста неверна или отсутствует."""


@dataclass(frozen=True)
class SbomRef:
    format: str
    url: str
    sha256: str


@dataclass(frozen=True)
class UpdateManifest:
    version: str
    min_supported: str
    release_date: str
    os: str
    arch: str
    package_url: str
    package_size: int
    package_sha256: str
    sbom: SbomRef
    critical: bool
    raw: Dict[str, Any]


def _no_duplicates(pairs):
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"повторяющееся поле «{key}»")
        result[key] = value
    return result


def load_json(data: bytes) -> Dict[str, Any]:
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("Ошибка: манифест слишком большой")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as e:
        raise ManifestError(f"Ошибка: манифест не разобран ({e})") from None
    if not isinstance(obj, dict):
        raise ManifestError("Ошибка: манифест должен быть JSON-объектом")
    return obj


def canonical_bytes(obj: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _field(obj: Dict[str, Any], name: str, kind: type) -> Any:
    value = obj.get(name)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ManifestError(f"Ошибка: в манифесте нет поля «{name}» или оно неверного типа")
    return value


def validate(obj: Dict[str, Any]) -> UpdateManifest:
    version = _field(obj, "version", str)
    minimum = _field(obj, "min_supported", str)
    if not versions.is_valid(version) or not versions.is_valid(minimum):
        raise ManifestError("Ошибка: версии в манифесте должны иметь вид Major.Minor.Patch")
    if versions.parse(minimum) > versions.parse(version):
        raise ManifestError("Ошибка: min_supported больше версии обновления")
    date = _field(obj, "release_date", str)
    try:
        datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ManifestError("Ошибка: release_date должна быть вида 2026-10-23T10:00:00Z") from None
    os_name, arch = _field(obj, "os", str), _field(obj, "arch", str)
    if os_name not in OS_NAMES or arch not in ARCHES:
        raise ManifestError("Ошибка: неизвестная ОС или архитектура в манифесте")
    size = _field(obj, "package_size", int)
    if not 0 < size <= MAX_PACKAGE_SIZE:
        raise ManifestError("Ошибка: недопустимый размер пакета в манифесте")
    digest = _field(obj, "package_sha256", str)
    sbom = _field(obj, "sbom", dict)
    sbom_ref = SbomRef(str(sbom.get("format", "")), str(sbom.get("url", "")), str(sbom.get("sha256", "")))
    if not _SHA256.fullmatch(digest) or not _SHA256.fullmatch(sbom_ref.sha256):
        raise ManifestError("Ошибка: SHA-256 в манифесте должен быть 64 символа 0-9a-f")
    if not sbom_ref.format.startswith("CycloneDX-"):
        raise ManifestError("Ошибка: поддерживается только SBOM формата CycloneDX")
    critical = obj.get("critical", False)
    if not isinstance(critical, bool):
        raise ManifestError("Ошибка: поле «critical» должно быть true или false")
    url = obj.get("package_url", "")
    if not isinstance(url, str):
        raise ManifestError("Ошибка: поле «package_url» должно быть строкой")
    _field(obj, "signature", str) if "signature" in obj else None
    return UpdateManifest(version, minimum, date, os_name, arch, url, size, digest, sbom_ref, critical, obj)


# ------------------------------------------------------------------ Ed25519
def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        raise EcpError("Ошибка: не установлен пакет cryptography (pip install cryptography)") from None
    return ed25519, InvalidSignature


def decode_b64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError(f"Ошибка: {what} не в формате base64") from None


def sign_manifest(obj: Dict[str, Any], private_key: bytes) -> str:
    """base64-подпись канонической формы манифеста (используется при выпуске релиза и в тестах)."""
    ed25519, _ = _ed25519()
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return base64.b64encode(key.sign(canonical_bytes(obj))).decode("ascii")


def verify_manifest(manifest_bytes: bytes, sig_bytes: Optional[bytes], public_key: bytes) -> UpdateManifest:
    """Проверка подписи, затем полей манифеста. Любое расхождение - SignatureError / ManifestError."""
    ed25519, InvalidSignature = _ed25519()
    obj = load_json(manifest_bytes)
    from_file = sig_bytes.decode("ascii", "replace").strip() if sig_bytes else None
    from_field = obj.get("signature") if isinstance(obj.get("signature"), str) else None
    if from_file and from_field and from_file != from_field:
        raise SignatureError("Ошибка: подпись в manifest.sig не совпадает с полем «signature»")
    signature = from_file or from_field
    if not signature:
        raise SignatureError("Ошибка: манифест не подписан")
    raw_sig = decode_b64(signature, "подпись")
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    except ValueError:
        raise SignatureError("Ошибка: открытый ключ проверки обновлений повреждён") from None
    try:
        key.verify(raw_sig, canonical_bytes(obj))
    except InvalidSignature:
        raise SignatureError("Ошибка: подпись манифеста неверна (манифест изменён или подписан не тем ключом)") from None
    return validate(obj)
