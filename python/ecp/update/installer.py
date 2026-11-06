"""Атомарная замена файлов и откат. Только стандартная библиотека: модуль копируется во временную
папку и запускается отдельным процессом после закрытия приложения (Windows не даёт переименовать
каталог с загруженными .pyd/.dll, а сам ecp в этот момент заменяется).

    python installer.py --app DIR --staging DIR --backup DIR --pid N --result FILE --from 1.2.0 --to 1.3.0
                        --health '["python","-m","ecp","--check"]' --launch '["python","-m","ecp.gui"]'
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

HEALTH_TIMEOUT = 90


@dataclass
class SwapResult:
    status: str          # installed | rolled_back | failed
    error: str = ""


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def rollback(app: Path, backup: Path) -> None:
    """Возвращает предыдущую версию: сломанная новая удаляется, backup становится app."""
    if app.exists():
        broken = app.with_name(app.name + ".broken")
        _remove(broken)
        os.replace(app, broken)
        shutil.rmtree(broken, ignore_errors=True)
    os.replace(backup, app)


def perform_swap(app: Path, staging: Path, backup: Path,
                 health_check: Optional[Callable[[Path], bool]] = None) -> SwapResult:
    """app -> backup, staging -> app; при любой ошибке - откат из backup.

    installed   - новая версия на месте и (если задана) прошла проверку запуска;
    rolled_back - замена или проверка не удались, восстановлена предыдущая версия;
    failed      - замена не началась (например, файлы заняты) либо откат невозможен.
    """
    if not staging.is_dir():
        return SwapResult("failed", "каталог staging не найден")
    if not app.is_dir():
        return SwapResult("failed", "каталог приложения не найден")
    try:
        _remove(backup)
        os.replace(app, backup)           # шаг 1: текущая версия -> backup
    except OSError as e:
        return SwapResult("failed", f"не удалось отодвинуть текущую версию (файлы заняты?): {e}")
    try:
        os.replace(staging, app)          # шаг 2: новая версия -> app
        if health_check is not None and not health_check(app):
            raise RuntimeError("новая версия не прошла проверку запуска")
    except Exception as e:  # noqa: BLE001 - любая ошибка = откат
        try:
            rollback(app, backup)
        except OSError as e2:
            return SwapResult("failed", f"{e}; откат не удался ({e2}), восстановите папку из «{backup}» вручную")
        return SwapResult("rolled_back", str(e))
    return SwapResult("installed")


def command_health_check(command: List[str], cwd: Optional[Path] = None, timeout: int = HEALTH_TIMEOUT):
    """Проверка запуска: команда должна завершиться с кодом 0 (например, «--check» новой версии)."""
    def check(app: Path) -> bool:
        try:
            done = subprocess.run(command, cwd=str(cwd or app.parent), timeout=timeout,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return False
        return done.returncode == 0
    return check


def wait_for_exit(pid: int, timeout: float = 60.0) -> bool:
    """Ждёт завершения процесса приложения. False - не дождались."""
    deadline = time.monotonic() + timeout
    if sys.platform.startswith("win"):
        import ctypes
        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return True
        try:
            return kernel.WaitForSingleObject(handle, int(timeout * 1000)) == 0
        finally:
            kernel.CloseHandle(handle)
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.2)
    return False


def write_result(path: Path, status: str, from_version: str, to_version: str, error: str = "") -> None:
    data = {"status": status, "from_version": from_version, "to_version": to_version, "error": error,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser()
    for name in ("app", "staging", "backup", "result", "from", "to"):
        p.add_argument(f"--{name}", required=True)
    p.add_argument("--pid", type=int, default=0)
    p.add_argument("--health", default="[]")
    p.add_argument("--launch", default="[]")
    a = p.parse_args(argv)
    app, staging, backup, result = Path(a.app), Path(a.staging), Path(a.backup), Path(a.result)
    health, launch = json.loads(a.health), json.loads(a.launch)
    if a.pid and not wait_for_exit(a.pid):
        write_result(result, "failed", a.__dict__["from"], a.to, "приложение не закрылось, обновление отложено")
        outcome = SwapResult("failed")
    else:
        check = command_health_check(health) if health else None
        outcome = perform_swap(app, staging, backup, check)
        write_result(result, outcome.status, a.__dict__["from"], a.to, outcome.error)
    if launch:  # запускаем приложение в любом случае: новая версия, предыдущая после отката или прежняя
        try:
            subprocess.Popen(launch, close_fds=True, **(
                {"creationflags": 0x00000008 | 0x00000200} if sys.platform.startswith("win")
                else {"start_new_session": True}))
        except OSError:
            pass
    return 0 if outcome.status == "installed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
