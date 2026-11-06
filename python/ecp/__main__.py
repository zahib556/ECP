"""Командная строка:  python -m ecp --version | --check | --gui"""
from __future__ import annotations

import argparse
from typing import List, Optional

from . import service
from .version import APP_NAME


def version_text() -> str:
    """Версия ПО и дата сборки (практическое занятие, п. 5)."""
    info = service.build_info()
    if info.status == "absent":
        build = "не определена (режим разработки, релиз не подписан)"
    elif info.authentic:
        build = f"{info.build_date} (подтверждена ЭЦП разработчика)"
    else:
        build = f"{info.build_date} (НЕ подтверждена: нарушены целостность или подпись)"
    lines = [APP_NAME, f"Версия ПО: {info.version}", f"Дата сборки: {build}",
             f"Версия криптоядра: {info.core_version}"]
    if info.fingerprint:
        lines.append(f"Отпечаток ключа разработчика (belt-hash): {info.fingerprint.upper()}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ecp", description=APP_NAME)
    parser.add_argument("--version", action="store_true", help="версия ПО и дата сборки")
    parser.add_argument("--check", action="store_true", help="самотестирование и проверка целостности ПО")
    parser.add_argument("--gui", action="store_true", help="запустить графический интерфейс")
    args = parser.parse_args(argv)
    if args.version:
        print(version_text())
        return 0
    if args.check:
        results = service.self_test()
        for r in results:
            print(("OK   " if r.ok else "FAIL ") + r.name + (f" — {r.detail}" if r.detail else ""))
        return 0 if all(r.ok for r in results) else 1
    if args.gui:
        from .gui.app import main as gui_main
        return gui_main()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
