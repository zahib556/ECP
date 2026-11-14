"""Atheris-вариант (только Linux/WSL: Atheris не поддерживает Windows). Те же цели, что у run_fuzz.py.

    pip install atheris
    python fuzz/fuzz_atheris.py asn1_parse -max_total_time=60

Имя цели - первый аргумент (список: python fuzz/run_fuzz.py --list). Остальные аргументы получает libFuzzer.
"""
import sys
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parent))
from targets import TARGETS  # noqa: E402

target = TARGETS[sys.argv.pop(1)]


def test_one_input(data: bytes) -> None:
    try:
        target.func(data)
    except target.allowed:
        pass  # ожидаемый отказ на плохие данные - не дефект; всё остальное - потенциальный баг


atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
