"""Версия ПО по семантической нумерации Major.Minor.Patch (semver.org)."""
from __future__ import annotations

import re

APP_NAME = "Средство выработки и проверки ЭЦП"
STANDARD = "СТБ 34.101.45-2013"
VERSION = "1.4.0"

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
BUILD_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def is_semver(text: str) -> bool:
    return bool(_SEMVER.match(text))
