"""Короткий прогон собственного фаззера (fuzz/run_fuzz.py) как обычный тест: падений быть не должно.

Работает без hypothesis. Для длительного запуска (>= 60 с) используйте сам fuzz/run_fuzz.py. Related to #N4.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fuzz"))
import run_fuzz  # noqa: E402
from targets import TARGETS  # noqa: E402


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_fuzz_target_survives_two_seconds(name, tmp_path):
    run_fuzz.CRASH_DIR = tmp_path / "crashes"
    wd = run_fuzz.Watchdog(timeout=10.0)
    wd.start()
    result = run_fuzz.run_target(name, seconds=2.0, seed=12345, wd=wd)
    assert result["execs"] > 100
    assert result["crashes"] == {}, f"фаззер нашёл падения в цели {name}: {list(result['crashes'])}"
