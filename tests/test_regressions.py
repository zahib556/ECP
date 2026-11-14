"""Регрессионные тесты дефектов, найденных фаззингом и негативными тестами (ПЗ-6, п. 5.5).

Каждый тест ПАДАЛ на коде до исправления и проходит после. Идентификаторы BUG-n соответствуют разделу 4
файла TESTING_REPORT.md (в GitHub - Issues с меткой bug). Related to #N4.
"""
import hashlib
import json
import threading
import zipfile

import pytest

from ecp import asn1
from ecp.auth import passwords, tokens
from ecp.auth.device import is_valid_device_id
from ecp import config, version
from ecp.update import release, sbom, staging, versions
from helpers import manifest


def _within(seconds, func, *args):
    """Вызывает func в потоке; зависание = провал теста (а не бесконечное ожидание CI)."""
    box = {}

    def run():
        try:
            box["value"] = func(*args)
        except BaseException as e:  # noqa: BLE001
            box["error"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"{func.__name__}{args} завис (> {seconds} с)"
    if "error" in box:
        raise box["error"]
    return box["value"]


def test_bug1_oid_with_negative_arc_hangs_forever():
    # вход фаззера 00 02 03 -> арки 0.2.-3; раньше asn1.oid() уходил в бесконечный цикл (сдвиг -1 >> 7 == -1)
    for dotted in ("0.2.-3", "1.2.-3", "-1.2"):
        with pytest.raises(asn1.Asn1Error):
            _within(5, asn1.oid, dotted)


def test_bug1b_oid_with_negative_second_arc_was_silently_encoded_wrong():
    with pytest.raises(asn1.Asn1Error):
        asn1.oid("1.-5")      # раньше кодировался как 1.35


def test_bug2_version_with_trailing_newline_or_unicode_digits_was_accepted():
    for text in ("1.0.0\n", "0.2\u0663.30", "1.0.0\r\n"):
        assert versions.is_valid(text) is False
        assert version.is_semver(text) is False
        with pytest.raises(ValueError):
            versions.parse(text)


def test_bug2b_sha256_and_device_id_with_trailing_newline_were_accepted():
    with pytest.raises(release.ManifestError):
        release.validate(manifest(package_sha256="a" * 64 + "\n"))
    assert is_valid_device_id("0123456789abcdef" * 4 + "\n") is False


def test_bug3_sbom_with_non_object_component_raised_attribute_error():
    data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": [1]},
                       "components": []}).encode()
    with pytest.raises(sbom.SbomMismatch):
        sbom.check(data, hashlib.sha256(data).hexdigest(), "1.0.0")


def test_bug4_token_with_non_ascii_characters_raised_unicode_error():
    token = tokens.encode({"exp": 10}, b"k" * 32)
    head, payload, sig = token.split(".")
    with pytest.raises(tokens.TokenError):
        tokens.decode(f"{head}.{payload}\ufffd.{sig}", b"k" * 32, now=0)


def _zip_with_mutation(tmp_path, mutate):
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ecp/main.py", "print('hi')\n" * 20)
    data = bytearray(buf.getvalue())
    mutate(data)
    pkg = tmp_path / "p.zip"
    pkg.write_bytes(bytes(data))
    return pkg


def _central(d):
    return d.index(b"PK\x01\x02")      # запись в центральном каталоге: именно её читает zipfile


@pytest.mark.parametrize("name, mutate", [
    ("плохая CRC-32", lambda d: d.__setitem__(slice(_central(d) + 16, _central(d) + 20), b"\x00\x00\x00\x00")),
    ("неизвестный метод сжатия", lambda d: d.__setitem__(slice(_central(d) + 10, _central(d) + 12), b"\x63\x00")),
    ("флаг шифрования", lambda d: d.__setitem__(_central(d) + 8, d[_central(d) + 8] | 1)),
    ("повреждённый поток deflate", lambda d: d.__setitem__(slice(30 + 11 + 2, 30 + 11 + 6), b"\xff\xff\xff\xff")),
    ("подмена имени в локальном заголовке", lambda d: d.__setitem__(30 + 8, ord("X"))),
])
def test_bug5_corrupt_zip_raised_library_exception_instead_of_package_error(tmp_path, name, mutate):
    pkg = _zip_with_mutation(tmp_path, mutate)
    with pytest.raises(staging.PackageError):
        staging.extract(pkg, tmp_path / "out")


def test_bug6_verify_password_with_non_ascii_record_raised_unicode_error():
    assert passwords.verify_password("Hunter2-secure", "00" * 16, "pbkdf2_sha256$200000$é") is False


def test_bug7_config_period_overflow_raised_overflow_error(tmp_path):
    with pytest.raises(ValueError):
        config.parse_period("99999999999d")
    assert config.check_param("logging", "cleanup_period", "99999999999999999999h")
    path = tmp_path / "config.ini"
    path.write_text("[logging]\ncleanup_period = 99999999999d\n", encoding="utf-8")
    assert any("cleanup_period" in p for p in config.load(path).problems)   # раньше загрузка файла падала
