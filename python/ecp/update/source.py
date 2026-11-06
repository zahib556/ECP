"""Источники обновления. Updater работает с IUpdateSource; offline - FileSource, online - HttpSource (вариант А)."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Optional, Protocol, Tuple, runtime_checkable

from ..errors import EcpError
from .release import MAX_MANIFEST_BYTES, UpdateManifest

PACKAGE_DEFAULT_NAME = "package.zip"


@runtime_checkable
class IUpdateSource(Protocol):
    description: str

    def read_manifest(self) -> Tuple[bytes, Optional[bytes]]:
        """Байты manifest.json и (если есть) manifest.sig."""

    def open_package(self, manifest: UpdateManifest) -> Path:
        """Локальный путь к ZIP-пакету (HttpSource скачивает, FileSource берёт файл рядом с манифестом)."""


class FileSource:
    """manifest.json, manifest.sig и пакет лежат в одной папке (вариант Б)."""

    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = Path(manifest_path)
        self.description = f"файл «{self.manifest_path.name}»"

    def _read(self, path: Path, limit: int) -> bytes:
        try:
            if path.stat().st_size > limit:
                raise EcpError(f"Ошибка: файл «{path.name}» слишком большой")
            return path.read_bytes()
        except OSError as e:
            raise EcpError(f"Ошибка: не удалось прочитать «{path.name}»: {e.strerror or e}") from None

    def read_manifest(self) -> Tuple[bytes, Optional[bytes]]:
        manifest = self._read(self.manifest_path, MAX_MANIFEST_BYTES)
        sig_path = self.manifest_path.with_name("manifest.sig")
        sig = self._read(sig_path, 4096) if sig_path.is_file() else None
        return manifest, sig

    def open_package(self, manifest: UpdateManifest) -> Path:
        folder = self.manifest_path.parent
        names = []
        if manifest.package_url:  # берём только имя файла: путь из манифеста не используется
            base = PurePosixPath(manifest.package_url.replace("\\", "/")).name
            if base:
                names.append(base)
        names.append(PACKAGE_DEFAULT_NAME)
        for name in names:
            path = folder / name
            if path.is_file():
                return path
        raise EcpError(f"Ошибка: пакет обновления не найден рядом с манифестом (ожидается {' или '.join(names)})")
