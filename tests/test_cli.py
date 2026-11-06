"""Командная строка и вывод версии."""
import contextlib
import io

from ecp import __main__ as cli
from ecp import service
from ecp.version import VERSION


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


def test_version_output():
    code, out = run(["--version"])
    assert code == 0
    assert f"Версия ПО: {VERSION}" in out
    assert "Дата сборки:" in out and "Версия криптоядра:" in out


def test_version_text_matches_build_info():
    info = service.build_info()
    text = cli.version_text()
    assert info.version in text
    if info.status == "absent":
        assert "режим разработки" in text
    else:
        assert info.build_date in text


def test_no_arguments_prints_help():
    code, out = run([])
    assert code == 0 and "--version" in out and "--check" in out
