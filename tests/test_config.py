"""Конфигурация: значения, проверка, чтение/запись, состояние."""
from datetime import timedelta

import pytest

from ecp import config as cfgmod
from ecp.errors import EcpError


def test_parse_period():
    assert cfgmod.parse_period("30d") == timedelta(days=30)
    assert cfgmod.parse_period(" 12H ") == timedelta(hours=12)
    for bad in ("", "30", "d", "0d", "-5d", "4000d", "30 days", "1.5d"):
        with pytest.raises(ValueError):
            cfgmod.parse_period(bad)


def test_parse_size():
    assert cfgmod.parse_size("100MB") == 100 * 1024 ** 2
    assert cfgmod.parse_size("1 kb") == 1024
    assert cfgmod.parse_size("2GB") == 2 * 1024 ** 3
    for bad in ("", "100", "MB", "0KB", "11GB", "10XB"):
        with pytest.raises(ValueError):
            cfgmod.parse_size(bad)


def test_format_size():
    assert cfgmod.format_size(100 * 1024 ** 2) == "100MB"
    assert cfgmod.format_size(2048) == "2KB"
    assert cfgmod.format_size(1500) == "1500B"


def test_default_config_is_valid(tmp_path):
    cfg = cfgmod.default_config(tmp_path)
    assert cfg.logging.log_path.endswith("security.log")
    assert cfgmod.validate(cfg) == []
    assert cfg.crypto.hashing == "belt-hash"
    assert cfg.crypto.digital_signature == "bign-with-hbelt"


def test_load_creates_default_file(tmp_path):
    path = tmp_path / "config.ini"
    first = cfgmod.load(path)
    assert first.created and path.exists() and first.problems == []
    second = cfgmod.load(path)
    assert not second.created and second.problems == []
    assert second.config == first.config


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "config.ini"
    cfg = cfgmod.default_config(tmp_path)
    cfg.logging.log_format = "csv"
    cfg.logging.cleanup_period = "7d"
    cfg.logging.max_file_size = "5MB"
    cfgmod.save(path, cfg)
    loaded = cfgmod.load(path).config
    assert loaded.logging.log_format == "CSV"  # нормализуется
    assert loaded.logging.cleanup_period == "7d"
    assert loaded.logging.max_file_size == "5MB"
    assert not list(tmp_path.glob("*.tmp"))


def test_log_path_with_percent_is_kept(tmp_path):
    path = tmp_path / "config.ini"
    cfg = cfgmod.default_config(tmp_path)
    cfg.logging.log_path = str(tmp_path / "50%" / "my log.log")
    cfgmod.save(path, cfg)
    assert cfgmod.load(path).config.logging.log_path == cfg.logging.log_path


def test_invalid_values_fall_back_to_defaults(tmp_path):
    path = tmp_path / "config.ini"
    path.write_text(
        "[logging]\nlog_path = x.log\nlog_format = XML\ncleanup_period = soon\nmax_file_size = 5TB\n"
        "[crypto]\nencryption = AES\nhashing = SHA-256\ndigital_signature = ECDSA\n",
        encoding="utf-8",
    )
    result = cfgmod.load(path)
    defaults = cfgmod.default_config(tmp_path)
    assert len(result.problems) == 6
    assert result.config.logging.log_path == "x.log"  # корректное значение сохранено
    assert result.config.logging.log_format == defaults.logging.log_format
    assert result.config.crypto == defaults.crypto


def test_missing_option_reported(tmp_path):
    path = tmp_path / "config.ini"
    path.write_text("[logging]\nlog_path = a.log\n", encoding="utf-8")
    result = cfgmod.load(path)
    assert any("max_file_size" in p for p in result.problems)
    assert any("crypto.hashing" in p for p in result.problems)


def test_garbage_file(tmp_path):
    path = tmp_path / "config.ini"
    path.write_bytes(b"\xff\xfe\x00garbage[[[")
    result = cfgmod.load(path)
    assert result.problems and result.config == cfgmod.default_config(tmp_path)


def test_save_rejects_invalid(tmp_path):
    cfg = cfgmod.default_config(tmp_path)
    cfg.crypto.hashing = "sha-256"
    with pytest.raises(EcpError, match="hashing"):
        cfgmod.save(tmp_path / "config.ini", cfg)
    assert not (tmp_path / "config.ini").exists()


def test_diff(tmp_path):
    a = cfgmod.default_config(tmp_path)
    b = cfgmod.default_config(tmp_path)
    assert cfgmod.diff(a, b) == []
    b.logging.log_format = "CEF"
    b.logging.max_file_size = "1MB"
    changes = cfgmod.diff(a, b)
    assert len(changes) == 2 and any("log_format" in c for c in changes)


def test_read_strict_and_export(tmp_path):
    good = tmp_path / "good.ini"
    cfgmod.save(good, cfgmod.default_config(tmp_path))
    assert cfgmod.read_strict(good) == cfgmod.default_config(tmp_path)
    bad = tmp_path / "bad.ini"
    bad.write_text("[logging]\nlog_format = XML\n", encoding="utf-8")
    with pytest.raises(EcpError, match="не принят"):
        cfgmod.read_strict(bad)
    out = tmp_path / "copy.ini"
    cfgmod.export_config(good, out)
    assert out.read_bytes() == good.read_bytes()
    with pytest.raises(EcpError):
        cfgmod.export_config(tmp_path / "нет.ini", tmp_path / "x.ini")


def test_state_and_hash(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    h1 = cfgmod.hash_file(f)
    f.write_bytes(b"abd")
    assert cfgmod.hash_file(f) != h1 and len(h1) == 64
    state = tmp_path / "state.json"
    assert cfgmod.load_state(state) == {}
    cfgmod.save_state(state, {"config_hash": h1})
    assert cfgmod.load_state(state) == {"config_hash": h1}
    state.write_text("[1,2]", encoding="utf-8")
    assert cfgmod.load_state(state) == {}
