"""SBOM (CycloneDX 1.5): проверка хэша и состава ключевых зависимостей, генерация."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from importlib import metadata
from typing import Dict, Iterable, List, Optional, Sequence

from ..errors import EcpError

REQUIRED_COMPONENTS = ("PySide6", "cryptography")
SPEC_VERSION = "1.5"
MAX_SBOM_BYTES = 8 * 1024 * 1024


class SbomMismatch(EcpError):
    """SBOM не совпадает с манифестом или не содержит обязательный состав (статус sbom_mismatch)."""


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(data: bytes, expected_sha256: str, app_version: str, fmt: str = "CycloneDX-1.5",
          required: Sequence[str] = REQUIRED_COMPONENTS) -> Dict[str, str]:
    """Проверка SBOM. Возвращает {имя: версия}. Любое расхождение - SbomMismatch."""
    if len(data) > MAX_SBOM_BYTES:
        raise SbomMismatch("Ошибка: SBOM слишком большой")
    if not hmac.compare_digest(sha256_hex(data), expected_sha256):
        raise SbomMismatch("Ошибка: SHA-256 SBOM не совпадает с манифестом")
    try:
        bom = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SbomMismatch("Ошибка: SBOM повреждён (не JSON)") from None
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise SbomMismatch("Ошибка: SBOM не в формате CycloneDX")
    if fmt != f"CycloneDX-{bom.get('specVersion')}":
        raise SbomMismatch("Ошибка: версия формата SBOM не совпадает с манифестом")
    meta = ((bom.get("metadata") or {}).get("component") or {}) if isinstance(bom.get("metadata"), dict) else {}
    if meta.get("version") != app_version:
        raise SbomMismatch("Ошибка: версия приложения в SBOM не совпадает с версией обновления")
    components = bom.get("components")
    if not isinstance(components, list):
        raise SbomMismatch("Ошибка: в SBOM нет списка компонентов")
    found: Dict[str, str] = {}
    for item in components:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
            raise SbomMismatch("Ошибка: компонент SBOM без имени")
        version = item.get("version")
        if not isinstance(version, str) or not version:
            raise SbomMismatch(f"Ошибка: у компонента «{item['name']}» нет версии")
        key = normalize(item["name"])
        if key in found:
            raise SbomMismatch(f"Ошибка: компонент «{item['name']}» указан в SBOM дважды")
        purl = item.get("purl")
        if purl is not None and purl != f"pkg:pypi/{key}@{version}":
            raise SbomMismatch(f"Ошибка: purl компонента «{item['name']}» не соответствует имени и версии")
        found[key] = version
    missing = [name for name in required if normalize(name) not in found]
    if missing:
        raise SbomMismatch("Ошибка: в SBOM нет обязательных зависимостей: " + ", ".join(missing))
    return found


def generate(app_name: str, version: str, packages: Iterable[str] = REQUIRED_COMPONENTS,
             installed: Optional[Dict[str, str]] = None) -> bytes:
    """CycloneDX 1.5 для приложения и перечисленных пакетов (версии - из установленного окружения)."""
    components: List[dict] = []
    for name in packages:
        try:
            ver = (installed or {}).get(name) or metadata.version(name)
        except metadata.PackageNotFoundError:
            raise EcpError(f"Ошибка: пакет «{name}» не установлен, SBOM построить нельзя") from None
        key = normalize(name)
        components.append({"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{key}@{ver}"})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION, "version": 1,
        "metadata": {"component": {"type": "application", "name": app_name, "version": version}},
        "components": components,
    }
    return json.dumps(bom, indent=2, ensure_ascii=False).encode("utf-8")
