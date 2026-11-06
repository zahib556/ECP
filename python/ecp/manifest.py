"""Целостность и подлинность ПО (СТБ 34.101.27: РС.2, СТ.3; практическое занятие, п. 6).

Целостность: belt-hash каждого файла программы сверяется с эталоном из MANIFEST.json.
Подлинность: эталон подписан ЭЦП разработчика (bign-with-hbelt, MANIFEST.sig), открытый ключ
разработчика - файл developer.pub. Отпечаток ключа (belt-hash) нужно публиковать отдельно.

Ограничение: самопроверка не защищает от подмены программы целиком вместе с ключом и эталоном.
Она обнаруживает случайные и частичные изменения. Доверие к ключу даёт его отпечаток.

Выпуск релиза:  python tools/build_release.py keygen   (один раз)
                python tools/build_release.py sign
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import _core
from .cryptoif import Crypto, default_crypto
from .errors import EcpError
from .version import BUILD_DATE_FORMAT, VERSION

MANIFEST_NAME = "MANIFEST.json"
SIGNATURE_NAME = "MANIFEST.sig"
PUBKEY_NAME = "developer.pub"
_SUFFIXES = {".py", ".pyd", ".so", ".pub"}


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def compute(base: Optional[Path] = None) -> Dict[str, str]:
    """belt-hash всех файлов программы: {относительный путь: хэш в hex}."""
    base = Path(base) if base else package_dir()
    result: Dict[str, str] = {}
    for p in sorted(base.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix in _SUFFIXES:
            result[p.relative_to(base).as_posix()] = _core.belt_hash(p.read_bytes()).hex()
    return result


def build_manifest(version: str = VERSION, now: Optional[datetime] = None,
                   base: Optional[Path] = None) -> bytes:
    now = (now or datetime.now()).replace(microsecond=0)
    body = {
        "format": 1,
        "version": version,
        "build_date": now.strftime(BUILD_DATE_FORMAT),
        "hash_algorithm": "belt-hash",
        "files": compute(base),
    }
    return json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------ выпуск релиза
def init_developer_key(out_dir: Path, base: Optional[Path] = None,
                       keypair: Optional[Tuple[bytes, bytes]] = None) -> Tuple[Path, Path]:
    """Ключи разработчика: личный - в out_dir (хранить отдельно!), открытый - в пакет."""
    base = Path(base) if base else package_dir()
    d, q = keypair or _core.generate_keypair()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / "developer.key"
    if private_path.exists() or (base / PUBKEY_NAME).exists():
        raise EcpError("Ошибка: ключи разработчика уже существуют, перезапись запрещена")
    private_path.write_bytes(d)
    (base / PUBKEY_NAME).write_bytes(q)
    return private_path, base / PUBKEY_NAME


def release(private_key: bytes, crypto: Optional[Crypto] = None, base: Optional[Path] = None,
            version: str = VERSION, now: Optional[datetime] = None) -> Path:
    """Создание MANIFEST.json и подписи MANIFEST.sig."""
    crypto = crypto or default_crypto()
    base = Path(base) if base else package_dir()
    pub_path = base / PUBKEY_NAME
    if not pub_path.exists():
        raise EcpError("Ошибка: нет открытого ключа разработчика (developer.pub), сначала выполните keygen")
    if crypto.derive_public_key(private_key) != pub_path.read_bytes():
        raise EcpError("Ошибка: личный ключ не соответствует developer.pub")
    data = build_manifest(version, now, base)
    (base / MANIFEST_NAME).write_bytes(data)
    (base / SIGNATURE_NAME).write_bytes(crypto.sign(private_key, data))
    return base / MANIFEST_NAME


# ------------------------------------------------------------------ проверка
@dataclass
class FileCheck:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class IntegrityReport:
    status: str = "absent"  # absent (режим разработки) | ok | failed
    authentic: Optional[bool] = None
    version: str = ""
    build_date: str = ""
    fingerprint: str = ""
    files: List[FileCheck] = field(default_factory=list)
    auth_problems: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)


def check(base: Optional[Path] = None, crypto: Optional[Crypto] = None) -> IntegrityReport:
    crypto = crypto or default_crypto()
    base = Path(base) if base else package_dir()
    manifest_path = base / MANIFEST_NAME
    if not manifest_path.exists():
        return IntegrityReport(status="absent")
    rep = IntegrityReport(status="failed")
    data = manifest_path.read_bytes()

    # --- подлинность: ЭЦП разработчика под манифестом
    pub_path, sig_path = base / PUBKEY_NAME, base / SIGNATURE_NAME
    if not pub_path.exists():
        rep.auth_problems.append("отсутствует открытый ключ разработчика (developer.pub)")
    elif not sig_path.exists():
        rep.auth_problems.append("отсутствует подпись манифеста (MANIFEST.sig)")
    else:
        q = pub_path.read_bytes()
        rep.fingerprint = crypto.hash(q).hex()
        try:
            crypto.check_public_key(q)
            rep.authentic = bool(crypto.verify(q, data, sig_path.read_bytes()))
        except (EcpError, ValueError):
            rep.authentic = False
        if not rep.authentic:
            rep.auth_problems.append("ЭЦП манифеста неверна: подлинность ПО не подтверждена")
    if rep.authentic is None:
        rep.authentic = False

    # --- целостность: хэши файлов
    try:
        body = json.loads(data.decode("utf-8"))
        expected = dict(body["files"])
        rep.version = str(body.get("version", ""))
        rep.build_date = str(body.get("build_date", ""))
    except (ValueError, KeyError, TypeError):
        rep.problems.append("манифест повреждён")
        return rep
    current = compute(base)
    for name in sorted(set(expected) | set(current)):
        if name not in current:
            rep.files.append(FileCheck(name, False, "файл отсутствует"))
        elif name not in expected:
            rep.files.append(FileCheck(name, False, "файл не входит в эталон"))
        elif expected[name] != current[name]:
            rep.files.append(FileCheck(name, False, "хэш не совпал"))
        else:
            rep.files.append(FileCheck(name, True))
    rep.status = "ok" if rep.authentic and all(f.ok for f in rep.files) else "failed"
    return rep
