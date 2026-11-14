"""ПЗ-6, часть 5. Фаззинг в составе pytest: property-based (hypothesis) и короткий прогон собственного фаззера.

Длительный фаззинг (минимум 60 с) запускается отдельно: python fuzz/run_fuzz.py --target all --time 60
Related to #N4.
"""
import sys
from pathlib import Path

import pytest

from ecp import asn1, audit, config, x509
from ecp.auth import passwords, tokens
from ecp.errors import EcpError
from ecp.update import release, sbom, staging, versions

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fuzz"))

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

FAST = settings(max_examples=300, deadline=1000)


# ------------------------------------------------------------------ «никогда не падает»
@FAST
@given(st.binary(max_size=300))
def test_asn1_parser_never_crashes(data):
    try:
        for node in asn1.parse_all(data):
            for conv in (node.as_int, node.as_oid, node.as_bit_string, node.as_bool, node.as_time):
                try:
                    conv()
                except asn1.Asn1Error:
                    pass
    except asn1.Asn1Error:
        pass


@FAST
@given(st.binary(max_size=400))
def test_certificate_parser_never_crashes(data):
    try:
        x509.parse_certificate(data)
    except EcpError:
        pass


@FAST
@given(st.text(max_size=300))
def test_audit_line_parser_never_crashes(text):
    audit.parse_line(text)                      # возвращает событие или None, исключений быть не должно


@FAST
@given(st.text(max_size=200))
def test_token_decoder_raises_only_token_error(text):
    try:
        tokens.decode(text, b"k" * 32, now=0)
    except tokens.TokenError:
        pass


@FAST
@given(st.binary(max_size=300))
def test_manifest_loader_raises_only_manifest_error(data):
    try:
        release.validate(release.load_json(data))
    except release.ManifestError:
        pass


@FAST
@given(st.binary(max_size=300))
def test_sbom_checker_raises_only_sbom_mismatch(data):
    try:
        sbom.check(data, sbom.sha256_hex(data), "1.0.0")
    except sbom.SbomMismatch:
        pass


@FAST
@given(st.text(max_size=300))
def test_config_values_never_crash(text):
    for section, name in (("logging", "cleanup_period"), ("logging", "max_file_size"), ("logging", "log_path"),
                          ("logging", "log_format"), ("crypto", "hashing")):
        config.check_param(section, name, text)         # возвращает текст ошибки или None


# ------------------------------------------------------------------ свойства (инварианты)
@FAST
@given(st.integers(min_value=0, max_value=2 ** 600))
def test_integer_roundtrip(n):
    assert asn1.parse(asn1.integer(n)).as_int() == n


@FAST
@given(st.binary(max_size=1000))
def test_octet_string_roundtrip(data):
    assert asn1.parse(asn1.octet_string(data)).as_octets() == data


@FAST
@given(st.integers(0, 2), st.lists(st.integers(0, 2 ** 40), min_size=1, max_size=8))
def test_oid_roundtrip(first, rest):
    second = rest[0] % 40
    dotted = ".".join(str(x) for x in [first, second, *rest[1:]])
    assert asn1.decode_oid(asn1.parse(asn1.oid(dotted)).content) == dotted


@FAST
@given(st.text(max_size=40))
def test_semver_accepts_only_canonical_ascii_triples(text):
    if versions.is_valid(text):
        major, minor, patch = versions.parse(text)
        assert text == f"{major}.{minor}.{patch}"


@FAST
@given(st.text(max_size=300))
def test_password_policy_and_strength_total(text):
    passwords.policy_problems(text)
    score, label = passwords.strength(text)
    assert 0 <= score <= 4 and label == passwords.STRENGTH_LABELS[score]


@FAST
@given(st.dictionaries(st.text(max_size=8), st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)),
                       max_size=6))
def test_canonical_form_is_stable_and_ignores_signature(obj):
    assert release.canonical_bytes({**obj, "signature": "x"}) == release.canonical_bytes(obj)
    assert release.canonical_bytes(obj) == release.canonical_bytes(dict(reversed(list(obj.items()))))


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=1500))
def test_package_extractor_raises_only_package_error(data):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "p.zip"
        pkg.write_bytes(data)
        try:
            staging.extract(pkg, Path(tmp) / "out", limit=1 << 20)
        except staging.PackageError:
            pass
