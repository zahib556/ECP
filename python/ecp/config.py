"""Файл конфигурации (INI): группы «Логирование» и «Криптографические алгоритмы».

Все функции принимают явные пути, поэтому тестируются без обращения к профилю пользователя.
"""
from __future__ import annotations

import configparser
import copy
import io
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field, fields
from datetime import timedelta
from pathlib import Path
from typing import Dict, List, Optional

from . import _core
from .errors import EcpError

LOG_FORMATS = ("JSON", "CSV", "CEF")
# Допустимые значения алгоритмов: только алгоритмы белорусских стандартов, реализованные в программе.
SUPPORTED_ALGORITHMS: Dict[str, tuple] = {
    "encryption": ("belt-keywrap",),
    "hashing": ("belt-hash",),
    "digital_signature": ("bign-with-hbelt",),
}
CONFIG_NAME = "config.ini"
STATE_NAME = "state.json"


# ------------------------------------------------------------------ пути
def app_data_dir() -> Path:
    base = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "ecp"


def default_config_path() -> Path:
    return app_data_dir() / CONFIG_NAME


# ------------------------------------------------------------------ разбор значений
_PERIOD = re.compile(r"^\s*(\d+)\s*([dDhH])\s*$")
_SIZE = re.compile(r"^\s*(\d+)\s*(KB|MB|GB)\s*$", re.IGNORECASE)
_SIZE_UNITS = {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}
MIN_SIZE = 1024
MAX_SIZE = 10 * 1024 ** 3
MAX_PERIOD = timedelta(days=3650)


def parse_period(text: str) -> timedelta:
    """«30d» - 30 дней, «12h» - 12 часов."""
    m = _PERIOD.match(text or "")
    if not m:
        raise ValueError("ожидается число с единицей d (дни) или h (часы), например 30d")
    count = int(m.group(1))
    delta = timedelta(days=count) if m.group(2).lower() == "d" else timedelta(hours=count)
    if count < 1 or delta > MAX_PERIOD:
        raise ValueError("допустимый срок: от 1h до 3650d")
    return delta


def parse_size(text: str) -> int:
    """«100MB» - размер в байтах."""
    m = _SIZE.match(text or "")
    if not m:
        raise ValueError("ожидается число с единицей KB, MB или GB, например 100MB")
    size = int(m.group(1)) * _SIZE_UNITS[m.group(2).upper()]
    if not MIN_SIZE <= size <= MAX_SIZE:
        raise ValueError("допустимый размер: от 1KB до 10GB")
    return size


def format_size(size: int) -> str:
    for unit in ("GB", "MB", "KB"):
        if size % _SIZE_UNITS[unit] == 0:
            return f"{size // _SIZE_UNITS[unit]}{unit}"
    return f"{size}B"


# ------------------------------------------------------------------ модель
@dataclass
class LoggingConfig:
    log_path: str = ""
    log_format: str = "JSON"
    cleanup_period: str = "30d"
    max_file_size: str = "100MB"


@dataclass
class CryptoConfig:
    encryption: str = "belt-keywrap"
    hashing: str = "belt-hash"
    digital_signature: str = "bign-with-hbelt"


@dataclass
class Config:
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)

    def sections(self) -> Dict[str, Dict[str, str]]:
        return {"logging": asdict(self.logging), "crypto": asdict(self.crypto)}


def default_config(base_dir: Optional[Path] = None) -> Config:
    base = Path(base_dir) if base_dir else app_data_dir()
    cfg = Config()
    cfg.logging.log_path = str(base / "logs" / "security.log")
    return cfg


def _section_object(cfg: Config, section: str):
    return cfg.logging if section == "logging" else cfg.crypto


# ------------------------------------------------------------------ проверка
def check_param(section: str, name: str, value: str) -> Optional[str]:
    """Текст ошибки или None, если значение допустимо."""
    v = str(value).strip()
    try:
        if section == "logging":
            if name == "log_path":
                if not v:
                    raise ValueError("путь не задан")
                if "\x00" in v or v.endswith(("/", "\\")):
                    raise ValueError("ожидается путь к файлу, например security.log")
            elif name == "log_format":
                if v.upper() not in LOG_FORMATS:
                    raise ValueError("допустимо: " + ", ".join(LOG_FORMATS))
            elif name == "cleanup_period":
                parse_period(v)
            elif name == "max_file_size":
                parse_size(v)
            else:
                return f"неизвестный параметр {section}.{name}"
        elif section == "crypto":
            allowed = SUPPORTED_ALGORITHMS.get(name)
            if allowed is None:
                return f"неизвестный параметр {section}.{name}"
            if v.lower() not in allowed:
                raise ValueError("поддерживается: " + ", ".join(allowed))
        else:
            return f"неизвестная группа параметров {section}"
    except ValueError as e:
        return f"{section}.{name}: {e}"
    return None


def normalize_value(section: str, name: str, value: str) -> str:
    v = str(value).strip()
    if name == "log_format":
        return v.upper()
    if section == "crypto":
        return v.lower()
    return v


def validate(cfg: Config) -> List[str]:
    problems: List[str] = []
    for section, params in cfg.sections().items():
        for name, value in params.items():
            problem = check_param(section, name, value)
            if problem:
                problems.append(problem)
    return problems


def diff(old: Config, new: Config) -> List[str]:
    changes: List[str] = []
    old_s, new_s = old.sections(), new.sections()
    for section in new_s:
        for name, value in new_s[section].items():
            if old_s[section][name] != value:
                changes.append(f"{section}.{name}: «{old_s[section][name]}» → «{value}»")
    return changes


# ------------------------------------------------------------------ чтение и запись
@dataclass
class LoadResult:
    config: Config
    problems: List[str]
    created: bool = False


def _render(cfg: Config) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    for section, params in cfg.sections().items():
        parser[section] = params
    buf = io.StringIO()
    parser.write(buf)
    header = "# Конфигурация средства выработки и проверки ЭЦП (СТБ 34.101.45-2013)\n"
    return header + buf.getvalue()


def save(path: Path, cfg: Config) -> None:
    """Запись конфигурации (атомарно). Недопустимые значения не записываются."""
    problems = validate(cfg)
    if problems:
        raise EcpError("Ошибка: неверная конфигурация: " + "; ".join(problems))
    for section, params in cfg.sections().items():
        obj = _section_object(cfg, section)
        for name, value in params.items():
            setattr(obj, name, normalize_value(section, name, value))
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(_render(cfg), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as e:
        raise EcpError(f"Ошибка: не удалось записать файл конфигурации «{path.name}»: {e.strerror or e}") from None


def _parse(path: Path, defaults: Config, strict: bool) -> LoadResult:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(Path(path).read_text(encoding="utf-8"))
    except (configparser.Error, OSError, UnicodeDecodeError) as e:
        if strict:
            raise EcpError(f"Ошибка: не удалось прочитать файл конфигурации: {e}") from None
        return LoadResult(defaults, [f"не удалось прочитать файл конфигурации ({e}), использованы значения по умолчанию"])
    cfg = copy.deepcopy(defaults)
    problems: List[str] = []
    for section, params in defaults.sections().items():
        obj = _section_object(cfg, section)
        for name, default_value in params.items():
            if not parser.has_option(section, name):
                problems.append(f"{section}.{name}: параметр отсутствует, использовано значение по умолчанию")
                continue
            value = normalize_value(section, name, parser.get(section, name))
            problem = check_param(section, name, value)
            if problem:
                problems.append(f"{problem}; использовано значение по умолчанию")
            else:
                setattr(obj, name, value)
    return LoadResult(cfg, problems)


def load(path: Path) -> LoadResult:
    """Чтение конфигурации. Если файла нет - создаётся файл по умолчанию.

    Неверные значения заменяются значениями по умолчанию, замечания возвращаются в `problems`.
    """
    path = Path(path)
    defaults = default_config(path.parent)
    if not path.exists():
        save(path, defaults)
        return LoadResult(defaults, [], created=True)
    return _parse(path, defaults, strict=False)


def read_strict(path: Path) -> Config:
    """Чтение с отказом при любом замечании (для импорта чужого файла)."""
    result = _parse(Path(path), default_config(Path(path).parent), strict=True)
    if result.problems:
        raise EcpError("Ошибка: файл конфигурации не принят: " + "; ".join(result.problems))
    return result.config


def export_config(src: Path, dst: Path) -> None:
    try:
        shutil.copyfile(src, dst)
    except OSError as e:
        raise EcpError(f"Ошибка: не удалось экспортировать конфигурацию: {e.strerror or e}") from None


# ------------------------------------------------------------------ состояние (контроль правок вне приложения)
def hash_file(path: Path) -> str:
    return _core.belt_hash(Path(path).read_bytes()).hex()


def load_state(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, data: dict) -> None:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass  # состояние вспомогательное, его потеря не должна останавливать работу
