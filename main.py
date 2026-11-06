"""Точка входа для PyInstaller: без аргументов - графический интерфейс, иначе - как `python -m ecp`."""
import sys

from ecp.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["--gui"]))
