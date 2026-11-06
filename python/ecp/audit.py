"""Журнал событий информационной безопасности (приказ ОАЦ № 130, п. 3.4).

Запись содержит 8 обязательных полей задания и 4 дополнительных (level, status, action, object),
по которым строится цветовая разметка. Форматы журнала: JSON (по строке на запись), CSV, CEF.
В журнал не пишутся секреты: ключи и содержимое файлов.
"""
from __future__ import annotations

import csv
import getpass
import io
import ipaddress
import json
import os
import re
import socket
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, Iterator, List, Optional, Tuple

from .config import format_size
from .version import VERSION

FIELDS = [
    "event_datetime", "source_name", "user_account", "source_ip", "host_ip",
    "operation_start", "operation_end", "description",
    "level", "status", "action", "object",
]
LEVELS = ("info", "warning", "error", "critical")
STATUSES = ("success", "failure", "cancelled", "")
ACTIONS = ("access", "create", "modify", "delete", "copy", "move", "execute")
FORMATS = ("JSON", "CSV", "CEF")

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
CSV_HEADER = ",".join(FIELDS)
_MAX_TEXT = 2000
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


# ------------------------------------------------------------------ время и вспомогательные
def format_time(dt: datetime) -> str:
    """YYYY-MM-DD HH:MM:SS.mmm"""
    return dt.strftime(TIME_FORMAT) + f".{dt.microsecond // 1000:03d}"


def parse_time(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text, TIME_FORMAT + ".%f")
    except (ValueError, TypeError):
        return None


def clean(text: object, limit: int = _MAX_TEXT) -> str:
    """Управляющие символы (в том числе переводы строк) заменяются пробелами: одна запись - одна строка."""
    return _CONTROL.sub(" ", str(text))[:limit]


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser может падать в нестандартных средах
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def detect_host_ip() -> str:
    """IP-адрес хоста. UDP-«соединение» ничего не отправляет, но выбирает исходящий интерфейс."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        ipaddress.ip_address(ip)
        return ip
    except (OSError, ValueError):
        return "127.0.0.1"


# ------------------------------------------------------------------ запись
@dataclass
class AuditEvent:
    event_datetime: str = ""
    source_name: str = ""
    user_account: str = ""
    source_ip: str = ""
    host_ip: str = ""
    operation_start: str = ""
    operation_end: str = ""
    description: str = ""
    level: str = "info"
    status: str = ""
    action: str = "access"
    object: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def values(self) -> List[str]:
        return [getattr(self, name) for name in FIELDS]


# ---- JSON
def to_json(ev: AuditEvent) -> str:
    return json.dumps(ev.as_dict(), ensure_ascii=False)


def from_json(line: str) -> Optional[AuditEvent]:
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict) or "event_datetime" not in data:
        return None
    return AuditEvent(**{name: clean(data.get(name, "")) for name in FIELDS})


# ---- CSV
def _csv_safe(value: str) -> str:
    # защита от формул при открытии журнала в электронных таблицах
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def to_csv(ev: AuditEvent) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow([_csv_safe(v) for v in ev.values()])
    return buf.getvalue()


def from_csv(line: str) -> Optional[AuditEvent]:
    try:
        row = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        return None
    if len(row) != len(FIELDS) or row == FIELDS:
        return None
    row = [v[1:] if len(v) > 1 and v[0] == "'" and v[1] in "=+-@" else v for v in row]
    return AuditEvent(**dict(zip(FIELDS, row)))


# ---- CEF
_SEVERITY = {"info": 3, "warning": 5, "error": 7, "critical": 10}
_CEF_EXT = re.compile(r"(\w+)=((?:\\.|[^\\=])*?)(?=\s+\w+=|\s*$)")


def _cef_header(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _cef_value(text: str) -> str:
    return text.replace("\\", "\\\\").replace("=", "\\=")


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) == "n" else m.group(1), text)


def _epoch_ms(text: str) -> Optional[int]:
    dt = parse_time(text)
    return round(dt.timestamp() * 1000) if dt else None


def _from_epoch_ms(ms: int) -> str:
    base = datetime.fromtimestamp(ms // 1000).replace(microsecond=(ms % 1000) * 1000)
    return format_time(base)


def to_cef(ev: AuditEvent, version: str = VERSION) -> str:
    ext = {
        "rt": _epoch_ms(ev.event_datetime),
        "start": _epoch_ms(ev.operation_start),
        "end": _epoch_ms(ev.operation_end),
        "suser": ev.user_account,
        "src": ev.source_ip,
        "dvc": ev.host_ip,
        "msg": ev.description,
        "act": ev.action,
        "outcome": ev.status,
        "cs1Label": "level",
        "cs1": ev.level,
        "fname": ev.object,
    }
    extension = " ".join(f"{k}={_cef_value(str(v))}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join([
        "CEF:0", "ECP", "ECP", _cef_header(version),
        _cef_header(ev.source_name or "ecp"), _cef_header(ev.description[:80]),
        str(_SEVERITY.get(ev.level, 3)),
    ])
    return f"{header}|{extension}"


def _split_cef(line: str) -> Optional[Tuple[List[str], str]]:
    parts: List[str] = []
    cur: List[str] = []
    i = 0
    while i < len(line) and len(parts) < 7:
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i:i + 2])
            i += 2
            continue
        if c == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return (parts, line[i:]) if len(parts) == 7 else None


def from_cef(line: str) -> Optional[AuditEvent]:
    if not line.startswith("CEF:"):
        return None
    split = _split_cef(line)
    if split is None:
        return None
    parts, extension = split
    ext = {m.group(1): _unescape(m.group(2)) for m in _CEF_EXT.finditer(extension)}

    def when(key: str) -> str:
        try:
            return _from_epoch_ms(int(ext[key])) if key in ext else ""
        except (ValueError, OverflowError, OSError):
            return ""

    level = ext.get("cs1", "") if ext.get("cs1Label") == "level" else ""
    if not level:
        reverse = {v: k for k, v in _SEVERITY.items()}
        level = reverse.get(int(parts[6]) if parts[6].isdigit() else 3, "info")
    return AuditEvent(
        event_datetime=when("rt"), source_name=_unescape(parts[4]),
        user_account=ext.get("suser", ""), source_ip=ext.get("src", ""), host_ip=ext.get("dvc", ""),
        operation_start=when("start"), operation_end=when("end"),
        description=ext.get("msg", _unescape(parts[5])),
        level=level, status=ext.get("outcome", ""), action=ext.get("act", ""), object=ext.get("fname", ""),
    )


def format_line(ev: AuditEvent, fmt: str) -> str:
    if fmt == "JSON":
        return to_json(ev)
    if fmt == "CSV":
        return to_csv(ev)
    return to_cef(ev)


def parse_line(line: str) -> Optional[AuditEvent]:
    """Формат определяется по самой строке: в одном файле могут встретиться записи разных форматов."""
    s = line.strip()
    if not s:
        return None
    if s.startswith("{"):
        return from_json(s)
    if s.startswith("CEF:"):
        return from_cef(s)
    return from_csv(s)


def read_events(path: Path, limit: Optional[int] = None) -> Tuple[List[AuditEvent], int]:
    """Чтение журнала. Возвращает (последние `limit` записей, число нераспознанных строк)."""
    events: Deque[AuditEvent] = deque(maxlen=limit)
    bad = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s == CSV_HEADER:
                continue
            ev = parse_line(s)
            if ev is None:
                bad += 1
            else:
                events.append(ev)
    return list(events), bad


# ------------------------------------------------------------------ журнал
class _Op:
    """Изменяемое описание операции: тело `with` уточняет результат."""

    def __init__(self, description: str, level: str, action: str, obj: str) -> None:
        self.description = description
        self.level = level
        self.status = "success"
        self.action = action
        self.obj = obj


class AuditLog:
    def __init__(
        self,
        path: Path,
        log_format: str = "JSON",
        max_size: int = 100 * 1024 ** 2,
        cleanup_period: timedelta = timedelta(days=30),
        user: Optional[str] = None,
        source_ip: str = "127.0.0.1",
        host_ip: Optional[str] = None,
        version: str = VERSION,
        clock=None,
    ) -> None:
        self._lock = threading.RLock()
        self._clock = clock or datetime.now
        self.user = user or current_user()
        self.source_ip = source_ip
        self.host_ip = host_ip or detect_host_ip()
        self.version = version
        self.last_error: Optional[str] = None
        self._last_cleanup: Optional[float] = None
        self._first_time: Optional[datetime] = None
        self.reconfigure(path, log_format, max_size, cleanup_period)

    def reconfigure(self, path: Path, log_format: str, max_size: int, cleanup_period: timedelta) -> None:
        fmt = log_format.upper()
        if fmt not in FORMATS:
            raise ValueError(f"неизвестный формат журнала: {log_format}")
        with self._lock:
            self.path = Path(path)
            self.format = fmt
            self.max_size = max_size
            self.cleanup_period = cleanup_period
            self._first_time = None
            self._last_cleanup = None

    # ---- создание записей
    def _event(self, source: str, description: str, level: str, status: str, action: str,
               obj: str, start: Optional[datetime], end: Optional[datetime]) -> AuditEvent:
        if level not in LEVELS:
            raise ValueError(f"недопустимый level: {level}")
        if status not in STATUSES:
            raise ValueError(f"недопустимый status: {status}")
        if action not in ACTIONS:
            raise ValueError(f"недопустимый action: {action}")
        now = self._clock()
        return AuditEvent(
            event_datetime=format_time(now),
            source_name=clean(source),
            user_account=clean(self.user),
            source_ip=self.source_ip,
            host_ip=self.host_ip,
            operation_start=format_time(start or now),
            operation_end=format_time(end or now),
            description=clean(description),
            level=level, status=status, action=action,
            object=clean(obj),
        )

    def log(self, source: str, description: str, *, level: str = "info", status: str = "success",
            action: str = "access", obj: str = "", start: Optional[datetime] = None,
            end: Optional[datetime] = None) -> AuditEvent:
        ev = self._event(source, description, level, status, action, obj, start, end)
        self.write(ev)
        return ev

    def info(self, source: str, description: str, *, action: str = "execute", obj: str = "") -> AuditEvent:
        """Информационное событие без результата операции (status пустой)."""
        return self.log(source, description, level="info", status="", action=action, obj=obj)

    @contextmanager
    def operation(self, source: str, description: str, *, action: str = "access",
                  obj: str = "", level: str = "info") -> Iterator[_Op]:
        """Запись об операции с временем начала и окончания. Исключение фиксируется как неуспех."""
        op = _Op(description, level, action, obj)
        start = self._clock()
        try:
            yield op
        except Exception as exc:
            op.status = "failure"
            if op.level in ("info", "warning"):
                op.level = "error"
            op.description = f"{op.description}: {clean(exc, 500)}"
            self.log(source, op.description, level=op.level, status=op.status, action=op.action,
                     obj=op.obj, start=start, end=self._clock())
            raise
        self.log(source, op.description, level=op.level, status=op.status, action=op.action,
                 obj=op.obj, start=start, end=self._clock())

    # ---- файл журнала
    def write(self, ev: AuditEvent) -> bool:
        """Добавление записи. Сбой записи не должен ронять приложение: ошибка сохраняется в last_error."""
        with self._lock:
            try:
                extra = self._maintain()
                for e in extra + [ev]:
                    self._append(e)
                self.last_error = None
                return True
            except (OSError, ValueError) as exc:
                self.last_error = f"не удалось записать журнал «{self.path}»: {exc}"
                return False

    def _append(self, ev: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self.path.exists() or self.path.stat().st_size == 0
        with open(self.path, "a", encoding="utf-8", newline="") as f:
            if is_new and self.format == "CSV":
                f.write(CSV_HEADER + "\n")
            f.write(format_line(ev, self.format) + "\n")
        if is_new:
            self._first_time = parse_time(ev.event_datetime)

    def _first_record_time(self) -> Optional[datetime]:
        if self._first_time is None and self.path.exists():
            with open(self.path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    ev = parse_line(line)
                    if ev is not None:
                        self._first_time = parse_time(ev.event_datetime)
                        break
        return self._first_time

    def _archive_pattern(self) -> "re.Pattern[str]":
        return re.compile(rf"^{re.escape(self.path.stem)}\.(\d{{8}}-\d{{6}})(-\d+)?{re.escape(self.path.suffix)}$")

    def archives(self) -> List[Path]:
        if not self.path.parent.exists():
            return []
        pattern = self._archive_pattern()
        return sorted(p for p in self.path.parent.iterdir() if p.is_file() and pattern.match(p.name))

    def _archive_time(self, archive: Path) -> Optional[datetime]:
        """Момент перемещения в архив - берётся из имени файла."""
        m = self._archive_pattern().match(archive.name)
        try:
            return datetime.strptime(m.group(1), "%Y%m%d-%H%M%S") if m else None
        except ValueError:
            return None

    def _archive_name(self, now: datetime) -> Path:
        base = f"{self.path.stem}.{now:%Y%m%d-%H%M%S}"
        candidate = self.path.with_name(base + self.path.suffix)
        n = 1
        while candidate.exists():
            candidate = self.path.with_name(f"{base}-{n}{self.path.suffix}")
            n += 1
        return candidate

    def _maintain(self) -> List[AuditEvent]:
        """Ротация по размеру и сроку, удаление старых архивов. Возвращает записи об этих действиях."""
        events: List[AuditEvent] = []
        now = self._clock()
        if self.path.exists():
            reason = None
            if self.path.stat().st_size >= self.max_size:
                reason = f"достигнут предел размера {format_size(self.max_size)}"
            else:
                first = self._first_record_time()
                if first is not None and now - first >= self.cleanup_period:
                    reason = "истёк срок хранения записей в текущем файле"
            if reason:
                archive = self._archive_name(now)
                os.replace(self.path, archive)
                self._first_time = None
                events.append(self._event(
                    "ecp.audit", f"Журнал перемещён в архив «{archive.name}»: {reason}",
                    "info", "success", "move", str(archive), None, None))
        due = self._last_cleanup is None or time.monotonic() - self._last_cleanup >= 60 or bool(events)
        if due:
            self._last_cleanup = time.monotonic()
            for archive in self.archives():
                try:
                    stamp = self._archive_time(archive)
                    if stamp is not None and now - stamp >= self.cleanup_period:
                        archive.unlink()
                        events.append(self._event(
                            "ecp.audit", f"Удалён архив журнала «{archive.name}»: истёк срок хранения",
                            "info", "success", "delete", str(archive), None, None))
                except OSError:
                    continue
        return events
