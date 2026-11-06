"""Журнал событий: форматы JSON/CSV/CEF, запись, ротация, очистка."""
import re
from datetime import datetime, timedelta

import pytest

from ecp import audit
from ecp.audit import AuditEvent, AuditLog

TRICKY = AuditEvent(
    event_datetime="2026-10-14 09:41:07.318",
    source_name="ecp.sign",
    user_account="makar",
    source_ip="127.0.0.1",
    host_ip="192.168.1.15",
    operation_start="2026-10-14 09:41:07.296",
    operation_end="2026-10-14 09:41:07.318",
    description='Подпись «отчёт.pdf», a=b c=d | x \\n "кавычки", =формула',
    level="warning",
    status="failure",
    action="create",
    object=r"C:\Users\makar\Doc=1\отчёт.sig",
)


@pytest.mark.parametrize("fmt", ["JSON", "CSV", "CEF"])
def test_format_roundtrip(fmt):
    line = audit.format_line(TRICKY, fmt)
    assert "\n" not in line
    assert audit.parse_line(line) == TRICKY


def test_info_event_without_status_roundtrip():
    ev = AuditEvent(event_datetime="2026-10-14 09:41:07.001", source_name="ecp.app",
                    description="Запуск", level="info", status="", action="execute")
    for fmt in ("JSON", "CSV", "CEF"):
        assert audit.parse_line(audit.format_line(ev, fmt)) == ev


def test_csv_formula_protection():
    ev = AuditEvent(event_datetime="2026-10-14 09:41:07.001", source_name="s", description="=cmd|calc")
    line = audit.to_csv(ev)
    assert "'=cmd" in line  # в файле формула обезврежена
    assert audit.from_csv(line).description == "=cmd|calc"  # при чтении восстановлена


def test_cef_header_and_severity():
    line = audit.to_cef(TRICKY, "0.2.0")
    assert line.startswith("CEF:0|ECP|ECP|0.2.0|ecp.sign|")
    assert "|5|" in line  # warning
    assert "cs1Label=level cs1=warning" in line


def test_parse_line_rejects_garbage():
    assert audit.parse_line("") is None
    assert audit.parse_line(audit.CSV_HEADER) is None
    assert audit.parse_line("не журнал") is None
    assert audit.parse_line("{broken json") is None
    assert audit.parse_line('{"a": 1}') is None
    assert audit.parse_line("CEF:0|too|few") is None


def test_clean_control_characters():
    assert audit.clean("a\r\nb\tc\x00d") == "a  b c d"
    assert len(audit.clean("x" * 5000)) == 2000


def test_time_helpers():
    dt = datetime(2026, 10, 14, 9, 41, 7, 318000)
    text = audit.format_time(dt)
    assert text == "2026-10-14 09:41:07.318"
    assert audit.parse_time(text) == dt
    assert audit.parse_time("вчера") is None
    ip = audit.detect_host_ip()
    assert re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip)


@pytest.mark.parametrize("fmt", ["JSON", "CSV", "CEF"])
def test_log_writes_all_fields(tmp_path, fmt):
    log = AuditLog(tmp_path / "security.log", fmt, user="alice", host_ip="10.0.0.5")
    log.log("ecp.sign", "Подпись создана", action="create", obj="a.sig")
    log.info("ecp.app", "Запуск")
    events, bad = audit.read_events(log.path)
    assert bad == 0 and len(events) == 2
    first = events[0]
    assert first.user_account == "alice" and first.host_ip == "10.0.0.5"
    assert first.source_ip == "127.0.0.1"
    assert first.status == "success" and first.action == "create" and first.object == "a.sig"
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}", first.event_datetime)
    assert events[1].status == "" and events[1].action == "execute"


def test_csv_header_written_once(tmp_path):
    log = AuditLog(tmp_path / "s.log", "CSV")
    for i in range(3):
        log.log("s", f"запись {i}")
    text = log.path.read_text(encoding="utf-8")
    assert text.count(audit.CSV_HEADER) == 1
    assert len(audit.read_events(log.path)[0]) == 3


def test_mixed_formats_in_one_file(tmp_path):
    log = AuditLog(tmp_path / "s.log", "JSON")
    log.log("s", "в JSON")
    log.reconfigure(log.path, "CSV", log.max_size, log.cleanup_period)
    log.log("s", "в CSV")
    log.reconfigure(log.path, "CEF", log.max_size, log.cleanup_period)
    log.log("s", "в CEF")
    events, bad = audit.read_events(log.path)
    assert [e.description for e in events] == ["в JSON", "в CSV", "в CEF"] and bad == 0


def test_read_events_limit_and_bad_lines(tmp_path):
    log = AuditLog(tmp_path / "s.log", "JSON")
    for i in range(10):
        log.log("s", f"n{i}")
    with open(log.path, "a", encoding="utf-8") as f:
        f.write("мусор\n")
    events, bad = audit.read_events(log.path, limit=3)
    assert [e.description for e in events] == ["n7", "n8", "n9"] and bad == 1


def test_operation_success_and_failure(tmp_path):
    log = AuditLog(tmp_path / "s.log")
    with log.operation("ecp.keys", "Генерация", action="create", obj="k") as op:
        op.description = "Готово"
    with pytest.raises(RuntimeError):
        with log.operation("ecp.keys", "Генерация", action="create") as op:
            raise RuntimeError("сбой")
    ok, failed = audit.read_events(log.path)[0]
    assert ok.status == "success" and ok.description == "Готово" and ok.object == "k"
    assert failed.status == "failure" and failed.level == "error" and "сбой" in failed.description
    assert ok.operation_start <= ok.operation_end


def test_invalid_enum_values(tmp_path):
    log = AuditLog(tmp_path / "s.log")
    with pytest.raises(ValueError):
        log.log("s", "x", level="fatal")
    with pytest.raises(ValueError):
        log.log("s", "x", status="ok")
    with pytest.raises(ValueError):
        log.log("s", "x", action="read")
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "s.log", "XML")


def test_rotation_by_size_keeps_all_events(tmp_path):
    log = AuditLog(tmp_path / "security.log", "JSON", max_size=600)
    for i in range(12):
        log.log("s", f"запись номер {i}")
    archives = log.archives()
    assert archives, "ожидалась ротация по размеру"
    total = []
    for p in archives + [log.path]:
        total += audit.read_events(p)[0]
    moves = [e for e in total if e.action == "move"]
    assert moves and all(e.level == "info" for e in moves)
    assert len([e for e in total if e.source_name == "s"]) == 12


def test_rotation_by_age_and_cleanup(tmp_path):
    now = [datetime(2026, 1, 1, 12, 0, 0)]
    log = AuditLog(tmp_path / "security.log", "JSON", cleanup_period=timedelta(days=30),
                   clock=lambda: now[0])
    log.log("s", "старая запись")
    now[0] += timedelta(days=31)
    log.log("s", "новая запись")
    assert len(log.archives()) == 1  # файл старше срока перемещён в архив
    current = audit.read_events(log.path)[0]
    assert [e.action for e in current] == ["move", "access"]
    now[0] += timedelta(days=31)
    log.log("s", "ещё запись")
    deleted = [e for e in audit.read_events(log.path)[0] if e.action == "delete"]
    assert deleted
    assert len(log.archives()) == 1  # прежний архив удалён, появился новый
    assert log.archives()[0].name.startswith("security.20260304")


def test_foreign_files_are_never_deleted(tmp_path):
    now = [datetime(2026, 1, 1)]
    log = AuditLog(tmp_path / "security.log", "JSON", cleanup_period=timedelta(days=1),
                   clock=lambda: now[0])
    foreign = tmp_path / "security.backup.log"
    foreign.write_text("важное", encoding="utf-8")
    log.log("s", "x")
    now[0] += timedelta(days=400)
    log.log("s", "y")
    assert foreign.exists()


def test_write_failure_does_not_raise(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    log = AuditLog(blocker / "sub" / "s.log")
    log.log("s", "x")  # каталог создать нельзя - исключения нет
    assert log.last_error and "не удалось записать журнал" in log.last_error
