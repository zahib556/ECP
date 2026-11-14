"""Общие вспомогательные функции ПЗ-6 (не тесты)."""
import io
import json
import zipfile
from datetime import datetime, timezone

from ecp import asn1, x509

DEV = "a1" * 32
GOOD_MANIFEST = {
    "version": "1.3.0", "min_supported": "0.5.0", "release_date": "2026-10-23T10:00:00Z", "os": "windows",
    "arch": "x64", "package_url": "ecp-1.3.0-windows-x64.zip", "package_size": 1024,
    "package_sha256": "a" * 64, "sbom": {"format": "CycloneDX-1.5", "url": "sbom.json", "sha256": "b" * 64},
    "critical": False,
}


def manifest(**changes):
    obj = json.loads(json.dumps(GOOD_MANIFEST))
    obj.update(changes)
    return obj


def make_zip(files, path=None, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    if path is not None:
        path.write_bytes(buf.getvalue())
    return buf.getvalue()


def fake_cert(cn="Тестовый владелец", key=bytes(range(64)), timestamping=True):
    """Сертификат нужной структуры без настоящей подписи (для проверки разбора, криптоядро не нужно)."""
    name = x509.name_from_cn(cn)
    exts = []
    if timestamping:
        exts.append(asn1.seq(asn1.oid(x509.OID_EXT_KEY_USAGE), asn1.boolean(True),
                             asn1.octet_string(asn1.seq(asn1.oid(x509.OID_KP_TIME_STAMPING)))))
    tbs = asn1.seq(
        asn1.explicit(0, asn1.integer(2)), asn1.integer(123456789),
        x509.algorithm_identifier(x509.OID_BIGN_WITH_HBELT), name,
        asn1.seq(asn1.time_choice(datetime(2026, 10, 24, 12, tzinfo=timezone.utc)),
                 asn1.time_choice(datetime(2036, 10, 24, tzinfo=timezone.utc))),
        name, x509.public_key_info(key), asn1.explicit(3, asn1.seq(*exts)))
    return asn1.seq(tbs, x509.algorithm_identifier(x509.OID_BIGN_WITH_HBELT), asn1.bit_string(bytes(48)))
