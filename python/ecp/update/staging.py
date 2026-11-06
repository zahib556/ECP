"""Безопасная распаковка пакета в staging: защита от Zip Slip, символьных ссылок и «бомб»."""
from __future__ import annotations

import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable

from ..errors import EcpError

SKIP_NAMES = ("manifest.json", "manifest.sig")  # служебные файлы обновления не попадают в программу
MAX_FILES = 50_000
MAX_TOTAL = 4 * 1024 ** 3
_DRIVE = re.compile(r"^[A-Za-z]:")


class PackageError(EcpError):
    """Пакет повреждён или небезопасен."""


def _safe_name(name: str) -> PurePosixPath:
    text = name.replace("\\", "/")
    if not text or text.startswith("/") or _DRIVE.match(text) or "\x00" in text:
        raise PackageError(f"Ошибка: небезопасный путь в пакете «{name}»")
    path = PurePosixPath(text)
    if any(part in ("..", "") for part in path.parts):
        raise PackageError(f"Ошибка: небезопасный путь в пакете «{name}»")
    return path


def extract(package: Path, dest: Path, limit: int = MAX_TOTAL, skip: Iterable[str] = SKIP_NAMES) -> int:
    """Распаковывает пакет в dest. Возвращает число файлов. dest должен не существовать или быть пустым."""
    skip_set = set(skip)
    try:
        zf = zipfile.ZipFile(package)
    except (zipfile.BadZipFile, OSError) as e:
        raise PackageError(f"Ошибка: пакет не открывается как ZIP ({e})") from None
    with zf:
        infos = zf.infolist()
        if not infos or len(infos) > MAX_FILES:
            raise PackageError("Ошибка: пакет пуст или содержит слишком много файлов")
        seen = set()
        plan = []
        declared = 0
        for info in infos:
            rel = _safe_name(info.filename)
            if (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK:
                raise PackageError(f"Ошибка: в пакете символьная ссылка «{info.filename}»")
            if str(rel) in skip_set:
                continue
            folded = str(rel).casefold()
            if folded in seen and not info.is_dir():
                raise PackageError(f"Ошибка: в пакете повторяющееся имя «{info.filename}» (с учётом регистра)")
            seen.add(folded)
            declared += info.file_size
            plan.append((info, rel))
        if declared > limit:
            raise PackageError("Ошибка: распакованный размер пакета превышает допустимый")
        dest.mkdir(parents=True, exist_ok=True)
        root = dest.resolve()
        written = 0
        total = 0
        for info, rel in plan:
            target = (root / Path(*rel.parts)).resolve()
            if root != target and root not in target.parents:
                raise PackageError(f"Ошибка: путь выходит за пределы каталога установки «{info.filename}»")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit or total > declared + 1024:  # заголовок занизил размер - бомба
                        raise PackageError("Ошибка: размер данных в пакете больше заявленного")
                    out.write(chunk)
            written += 1
        if written == 0:
            raise PackageError("Ошибка: в пакете нет файлов программы")
        return written
