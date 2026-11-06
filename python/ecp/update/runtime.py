"""Где лежит приложение и как его проверять и перезапускать (исходники или собранный .exe)."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Tuple

HELPER_NAME = "ecp-updater.exe"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_dir() -> Path:
    """Каталог, который заменяется целиком: папка exe (PyInstaller --onedir) или пакет python/ecp."""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def entry_files() -> Tuple[str, ...]:
    return (Path(sys.executable).name,) if is_frozen() else ("__main__.py",)


def health_command(folder: Path) -> List[str]:
    """Проверка запуска новой версии: «--check» (самотестирование и целостность) должен вернуть 0."""
    if is_frozen():
        return [str(folder / Path(sys.executable).name), "--check"]
    return [sys.executable, "-m", "ecp", "--check"]


def launch_command() -> List[str]:
    return [sys.executable] if is_frozen() else [sys.executable, "-m", "ecp.gui"]


def helper_exe(folder: Path) -> Optional[Path]:
    path = folder / HELPER_NAME
    return path if is_frozen() and path.is_file() else None
