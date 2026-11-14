"""ПЗ-6, часть 4. Контроль КРАЕВЫХ значений: на границе, на единицу ниже и на единицу выше.

Числа, строки, коллекции, время и даты. Related to #N3.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from ecp import asn1, audit, config
from ecp.auth import AuthError, AuthService, passwords, tokens
from ecp.auth.service import normalize_login
from ecp.update import release, staging, versions
from helpers import DEV, make_zip, manifest

UTC = timezone.utc
PW = "Hunter2-secure"


# ------------------------------------------------------------------ 4.1 числа
@pytest.mark.parametrize("text, ok", [
    ("0h", False), ("1h", True), ("2h", True),
    ("87599h", True), ("87600h", True), ("87601h", False),      # 3650 суток = 87600 часов
    ("0d", False), ("1d", True), ("3649d", True), ("3650d", True), ("3651d", False),
])
def test_cleanup_period_boundaries(text, ok):
    if ok:
        assert config.parse_period(text) <= config.MAX_PERIOD
    else:
        with pytest.raises(ValueError):
            config.parse_period(text)


@pytest.mark.parametrize("text, ok", [
    ("0KB", False), ("1KB", True), ("2KB", True),
    ("1023KB", True), ("1024KB", True),
    ("10239MB", True), ("10240MB", True), ("10241MB", False),     # верхняя граница 10 GB
    ("10GB", True), ("11GB", False),
])
def test_max_file_size_boundaries(text, ok):
    if ok:
        assert config.MIN_SIZE <= config.parse_size(text) <= config.MAX_SIZE
    else:
        with pytest.raises(ValueError):
            config.parse_size(text)


@pytest.mark.parametrize("iterations, ok", [(199_999, False), (200_000, True), (200_001, True)])
def test_pbkdf2_iterations_boundary(iterations, ok):
    if ok:
        assert passwords.hash_password(PW, "00" * 16, iterations).split("$")[1] == str(iterations)
    else:
        with pytest.raises(ValueError):
            passwords.hash_password(PW, "00" * 16, iterations)


@pytest.mark.parametrize("size, ok", [
    (-1, False), (0, False), (1, True), (2, True),
    (release.MAX_PACKAGE_SIZE - 1, True), (release.MAX_PACKAGE_SIZE, True), (release.MAX_PACKAGE_SIZE + 1, False),
])
def test_manifest_package_size_boundaries(size, ok):
    if ok:
        assert release.validate(manifest(package_size=size)).package_size == size
    else:
        with pytest.raises(release.ManifestError):
            release.validate(manifest(package_size=size))


@pytest.mark.parametrize("minimum, ok", [("1.2.2", True), ("1.2.3", True), ("1.2.4", False), ("0.0.0", True)])
def test_manifest_min_supported_not_above_version(minimum, ok):
    if ok:
        release.validate(manifest(version="1.2.3", min_supported=minimum))
    else:
        with pytest.raises(release.ManifestError):
            release.validate(manifest(version="1.2.3", min_supported=minimum))


def test_version_components_are_unbounded_integers():
    assert versions.parse("0.0.0") == (0, 0, 0)
    assert versions.parse("999999999.999999999.999999999") == (999999999,) * 3


# ------------------------------------------------------------------ 4.2 строки и коллекции
@pytest.mark.parametrize("length, ok", [(0, False), (1, False), (2, False), (3, True), (4, True),
                                        (31, True), (32, True), (33, False)])
def test_login_length_boundaries(length, ok):
    login = "a" * length
    if ok:
        assert normalize_login(login) == login
    else:
        with pytest.raises(AuthError):
            normalize_login(login)


@pytest.mark.parametrize("length, ok", [(0, False), (6, False), (7, False), (8, True), (9, True),
                                        (127, True), (128, True), (129, False)])
def test_password_length_boundaries(length, ok):
    password = ("Ab1Cd2Ef3Gh4" * 12)[:length]   # разные символы и три класса: проверяется именно длина
    assert (passwords.policy_problems(password) == []) is ok


def test_password_with_only_three_distinct_characters_is_rejected_but_four_pass():
    assert passwords.policy_problems("abababab1")
    assert passwords.policy_problems("abcabcab1") == []


@pytest.mark.parametrize("length", [2, 4095, 4096, 4097, 100_000])
def test_token_length_boundary_always_token_error(length):
    token = ("a" * (length - 2)) + ".."        # граница 4096 символов: до и после неё - TokenError, не падение
    with pytest.raises(tokens.TokenError):
        tokens.decode(token, b"k" * 32, now=0)


@pytest.mark.parametrize("length, header", [(126, b"\x7e"), (127, b"\x7f"), (128, b"\x81\x80"), (255, b"\x81\xff"),
                                            (256, b"\x82\x01\x00"), (65535, b"\x82\xff\xff"), (65536, b"\x83\x01\x00\x00")])
def test_asn1_length_encoding_boundaries(length, header):
    assert asn1.encode_length(length) == header
    data = bytes(length)
    node = asn1.parse(asn1.octet_string(data))
    assert node.as_octets() == data


def test_asn1_integer_byte_boundaries():
    for n in (0, 127, 128, 255, 256, 2 ** 63 - 1, 2 ** 63, 2 ** 64, 2 ** 255, 2 ** 256 - 1):
        assert asn1.parse(asn1.integer(n)).as_int() == n


def test_asn1_empty_and_single_element_collections():
    assert asn1.parse(asn1.seq()).children() == []
    assert len(asn1.parse(asn1.seq(asn1.null())).children()) == 1
    assert asn1.parse_all(b"") == []
    assert asn1.parse(asn1.set_of([])).children() == []


def test_sbom_and_manifest_size_limits():
    from ecp.update import sbom
    with pytest.raises(release.ManifestError):
        release.load_json(b" " * (release.MAX_MANIFEST_BYTES + 1))
    assert release.load_json(b"{}" + b" " * (release.MAX_MANIFEST_BYTES - 2)) == {}   # ровно 64 KiB
    with pytest.raises(sbom.SbomMismatch):
        sbom.check(b" " * (sbom.MAX_SBOM_BYTES + 1), "0" * 64, "1.0.0")


@pytest.mark.parametrize("limit, ok", [(99, False), (100, True), (101, True)])
def test_package_unpacked_size_limit_boundary(tmp_path, limit, ok):
    pkg = tmp_path / "p.zip"
    make_zip({"a.bin": b"x" * 100}, pkg)
    if ok:
        assert staging.extract(pkg, tmp_path / "out", limit=limit) == 1
    else:
        with pytest.raises(staging.PackageError):
            staging.extract(pkg, tmp_path / "out", limit=limit)


# ------------------------------------------------------------------ 4.3 время и даты
@pytest.mark.parametrize("year, tag", [(1949, asn1.GENERALIZED_TIME), (1950, asn1.UTC_TIME), (2049, asn1.UTC_TIME),
                                       (2050, asn1.GENERALIZED_TIME)])
def test_time_choice_switches_encoding_at_1950_and_2049(year, tag):
    dt = datetime(year, 12, 31, 23, 59, 59, tzinfo=UTC)
    node = asn1.parse(asn1.time_choice(dt))
    assert node.tag == tag and node.as_time() == dt


@pytest.mark.parametrize("text, year", [(b"491231235959Z", 2049), (b"500101000000Z", 1950)])
def test_utc_time_two_digit_year_pivot(text, year):
    assert asn1.parse(asn1.tlv(asn1.UTC_TIME, text)).as_time().year == year


@pytest.mark.parametrize("dt", [
    datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC),    # конец года
    datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),         # начало года
    datetime(2026, 10, 31, 23, 59, 59, tzinfo=UTC),    # конец месяца
    datetime(2028, 2, 29, 12, 0, 0, tzinfo=UTC),       # 29 февраля (високосный)
    datetime(2026, 2, 28, 23, 59, 59, tzinfo=UTC),
])
def test_time_roundtrip_at_calendar_boundaries(dt):
    assert asn1.parse(asn1.time_choice(dt)).as_time() == dt
    assert asn1.parse(asn1.generalized_time(dt)).as_time() == dt


def test_midnight_transition_keeps_order():
    before = asn1.parse(asn1.time_choice(datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC))).as_time()
    after = asn1.parse(asn1.time_choice(datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC))).as_time()
    assert after - before == timedelta(seconds=1)


@pytest.mark.parametrize("date, ok", [
    ("2026-12-31T23:59:59Z", True), ("2027-01-01T00:00:00Z", True), ("2028-02-29T00:00:00Z", True),
    ("2027-02-29T00:00:00Z", False), ("2026-12-31T24:00:00Z", False), ("2026-12-31T23:59:60Z", False),
    ("2026-13-01T00:00:00Z", False), ("2026-00-10T00:00:00Z", False),
])
def test_manifest_release_date_boundaries(date, ok):
    if ok:
        assert release.validate(manifest(release_date=date)).release_date == date
    else:
        with pytest.raises(release.ManifestError):
            release.validate(manifest(release_date=date))


def test_microseconds_are_dropped_when_encoding_time():
    dt = datetime(2026, 10, 24, 12, 0, 0, 999999, tzinfo=UTC)
    assert asn1.parse(asn1.time_choice(dt)).as_time() == dt.replace(microsecond=0)


@pytest.mark.parametrize("now, expired", [(1799, False), (1800 - 1, False), (1800, True), (1801, True)])
def test_token_exp_boundary(now, expired):
    key = b"k" * 32
    token = tokens.encode({"exp": 1800}, key)
    if expired:
        with pytest.raises(tokens.TokenExpired):
            tokens.decode(token, key, now=now)
    else:
        assert tokens.decode(token, key, now=now)["exp"] == 1800


# ------------------------------------------------------------------ границы бизнес-правил входа
class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 23, 23, 59, 30, tzinfo=UTC)    # близко к полуночи

    def __call__(self):
        return self.now


@pytest.fixture()
def world(tmp_path):
    clock = Clock()
    svc = AuthService(tmp_path / "users.db", tmp_path / "auth.key", clock=clock)
    svc.register("student", PW, DEV)
    yield svc, clock
    svc.close()


def _fail(svc, times):
    for _ in range(times):
        with pytest.raises(AuthError):
            svc.login("student", "wrong-Pass1", DEV)


def test_lockout_starts_exactly_at_fifth_failure(world):
    svc, _ = world
    _fail(svc, 4)
    assert svc.login("student", PW, DEV).login == "student"        # 4 ошибки - ещё не блокировка (и счётчик сброшен)
    _fail(svc, 5)
    with pytest.raises(AuthError, match="слишком много"):
        svc.login("student", PW, DEV)                              # даже верный пароль отклонён


def test_lockout_ends_exactly_after_five_minutes(world):
    svc, clock = world
    _fail(svc, 5)
    clock.now += timedelta(minutes=5) - timedelta(seconds=1)
    with pytest.raises(AuthError, match="слишком много"):
        svc.login("student", PW, DEV)
    clock.now += timedelta(seconds=1)
    assert svc.login("student", PW, DEV).login == "student"


def test_session_lives_exactly_30_minutes_and_crosses_midnight(world):
    svc, clock = world
    token = svc.login("student", PW, DEV).token                    # 23:59:30 -> истекает 00:29:30 следующих суток
    clock.now += timedelta(minutes=30) - timedelta(seconds=1)
    assert clock.now.day == 24 and svc.me(token, DEV).login == "student"
    clock.now += timedelta(seconds=1)
    with pytest.raises(AuthError):
        svc.me(token, DEV)
