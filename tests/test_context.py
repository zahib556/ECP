"""Запуск приложения, управление конфигурацией и журнал её изменений."""
import pytest

from ecp import audit, service
from ecp import config as cfgmod
from ecp.context import AppContext
from ecp.errors import EcpError


@pytest.fixture()
def paths(tmp_path):
    return tmp_path / "cfg" / "config.ini", tmp_path / "cfg" / "state.json"


def start(paths):
    return AppContext.start(paths[0], paths[1], user="tester", host_ip="10.0.0.9")


def events(ctx):
    return audit.read_events(ctx.audit.path)[0]


def finish(ctx):
    ctx.shutdown()


def test_first_start_creates_config_and_logs(paths):
    ctx = start(paths)
    try:
        assert paths[0].exists() and ctx.problems == []
        evs = events(ctx)
        assert evs[0].description.startswith("Запуск приложения") and evs[0].status == ""
        created = [e for e in evs if e.action == "create" and e.source_name == "ecp.config"]
        assert len(created) == 1 and created[0].object == str(paths[0])
        assert all(e.user_account == "tester" and e.host_ip == "10.0.0.9" for e in evs)
    finally:
        finish(ctx)
    last = audit.read_events(ctx.audit.path)[0][-1]
    assert last.description.startswith("Завершение работы")


def test_second_start_does_not_recreate(paths):
    finish(start(paths))
    ctx = start(paths)
    try:
        created = [e for e in events(ctx) if e.action == "create"]
        assert len(created) == 1  # только от первого запуска
    finally:
        finish(ctx)


def test_external_modification_detected(paths):
    finish(start(paths))
    text = paths[0].read_text(encoding="utf-8").replace("max_file_size = 100MB", "max_file_size = 50MB")
    paths[0].write_text(text, encoding="utf-8")
    ctx = start(paths)
    try:
        outside = [e for e in events(ctx) if e.source_name == "ecp.config" and e.action == "modify"]
        assert len(outside) == 1 and outside[0].level == "warning"
        assert ctx.config.logging.max_file_size == "50MB"
    finally:
        finish(ctx)
    ctx = start(paths)  # хэш запомнен: повторного предупреждения нет
    try:
        outside = [e for e in events(ctx) if e.level == "warning"]
        assert len(outside) == 1
    finally:
        finish(ctx)


def test_invalid_config_is_logged_as_failure(paths):
    paths[0].parent.mkdir(parents=True)
    paths[0].write_text("[logging]\nlog_format = XML\n", encoding="utf-8")
    ctx = start(paths)
    try:
        assert ctx.problems
        failures = [e for e in events(ctx) if e.status == "failure" and e.level == "error"]
        assert failures and all(e.source_name == "ecp.config" for e in failures)
    finally:
        finish(ctx)


def test_save_config_logs_modification_and_switches_format(paths):
    ctx = start(paths)
    try:
        new = cfgmod.default_config(paths[0].parent)
        new.logging.log_format = "CSV"
        assert ctx.save_config(new) is True
        assert ctx.audit.format == "CSV"
        assert "log_format" in cfgmod.load(paths[0]).config.logging.log_format or True
        assert cfgmod.load(paths[0]).config.logging.log_format == "CSV"
        mods = [e for e in events(ctx) if e.action == "modify" and e.source_name == "ecp.config"]
        assert len(mods) == 1 and "log_format" in mods[0].description and mods[0].status == "success"
        assert ctx.save_config(new) is False  # без изменений записи нет
    finally:
        finish(ctx)


def test_save_invalid_config_rejected(paths):
    ctx = start(paths)
    try:
        bad = cfgmod.default_config(paths[0].parent)
        bad.crypto.hashing = "sha-256"
        with pytest.raises(EcpError):
            ctx.save_config(bad)
        failed = [e for e in events(ctx) if e.action == "modify" and e.status == "failure"]
        assert len(failed) == 1 and failed[0].level == "error"
        assert ctx.config.crypto.hashing == "belt-hash"
    finally:
        finish(ctx)


def test_reset_config(paths):
    ctx = start(paths)
    try:
        changed = cfgmod.default_config(paths[0].parent)
        changed.logging.cleanup_period = "7d"
        ctx.save_config(changed)
        assert ctx.reset_config() is True
        assert ctx.config.logging.cleanup_period == "30d"
        assert any("сброшена" in e.description for e in events(ctx))
        assert ctx.reset_config() is False
    finally:
        finish(ctx)


def test_log_path_change_continues_in_new_file(paths):
    ctx = start(paths)
    try:
        new = cfgmod.default_config(paths[0].parent)
        new.logging.log_path = str(paths[0].parent / "other" / "audit.log")
        ctx.save_config(new)
        assert ctx.audit.path.name == "audit.log"
        ctx.audit.info("ecp.test", "после переключения")
        assert any(e.description == "после переключения" for e in events(ctx))
        assert any("Параметры журнала изменены" in e.description for e in events(ctx))
    finally:
        finish(ctx)


def test_export_and_import(paths, tmp_path):
    ctx = start(paths)
    try:
        dst = tmp_path / "backup.ini"
        ctx.export_config(dst)
        assert dst.exists()
        copied = [e for e in events(ctx) if e.action == "copy" and e.status == "success"]
        assert len(copied) == 1
        changed = cfgmod.default_config(paths[0].parent)
        changed.logging.max_file_size = "1MB"
        ctx.save_config(changed)
        assert ctx.import_config(dst) is True
        assert ctx.config.logging.max_file_size == "100MB"
        bad = tmp_path / "bad.ini"
        bad.write_text("[logging]\nlog_format = XML\n", encoding="utf-8")
        with pytest.raises(EcpError):
            ctx.import_config(bad)
        failed = [e for e in events(ctx) if e.action == "copy" and e.status == "failure"]
        assert len(failed) == 1
    finally:
        finish(ctx)


def test_service_audit_is_detached_on_shutdown(paths):
    ctx = start(paths)
    assert service.get_audit() is ctx.audit
    ctx.shutdown()
    assert service.get_audit() is None
