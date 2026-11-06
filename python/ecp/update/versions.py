"""Сравнение версий Major.Minor.Patch."""
from __future__ import annotations

import re
from typing import Tuple

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def parse(text: str) -> Tuple[int, int, int]:
    m = _SEMVER.match(text) if isinstance(text, str) else None
    if not m:
        raise ValueError(f"неверная версия «{text}», ожидается Major.Minor.Patch")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def is_valid(text: object) -> bool:
    return isinstance(text, str) and bool(_SEMVER.match(text))
