"""Штамп времени на уровне файлов: локальная служба, запрос/ответ/проверка, CAdES-B-T, журнал."""
import pytest

from ecp import audit, service, tsp
from ecp.context import AppContext
from ecp.errors import EcpError

DATA = "Договор №1".encode("utf-8")


@pytest.fixture()
def work(tmp_path):
    data = tmp_path / "doc.txt"
    data.write_bytes(DATA)
    return data, tmp_path / "tsa"


def stamp(work, tmp_path):
    data, tsa_dir = work
    tsq = tmp_path / "doc.tsq"
    tsr = tmp_path / "doc.tsr"
    service.create_tsq(data, tsq)
    issued = service.issue_tsr(tsq, tsr, tsa_dir)
    return tsq, tsr, issued


def test_local_tsa_is_created_once(tmp_path):
    folder = tmp_path / "tsa"
    assert service.trusted_tsa_key(folder) is None
    first = service.load_local_tsa(folder)
    assert (folder / service.TSA_KEY_NAME).stat().st_size == 32
    assert (folder / service.TSA_CERT_NAME).exists()
    second = service.load_local_tsa(folder)
    assert first.public_key == second.public_key == service.trusted_tsa_key(folder)


def test_tsq_tsr_roundtrip(work, tmp_path):
    data, tsa_dir = work
    tsq, tsr, issued = stamp(work, tmp_path)
    assert issued.status == tsp.GRANTED and issued.serial and issued.gen_time
    request = tsp.parse_request(tsq.read_bytes())
    assert request.imprint == service._core.belt_hash(DATA) and request.nonce and request.cert_req
    result = service.verify_tsr(data, tsr, tsq, tsa_dir)
    assert result.ok, [(c.name, c.detail) for c in result.checks if not c.ok]
    assert result.serial == issued.serial and result.nonce == request.nonce


def test_modified_data_is_detected(work, tmp_path):
    data, tsa_dir = work
    tsq, tsr, _ = stamp(work, tmp_path)
    data.write_bytes(DATA + b"!")
    assert service.verify_tsr(data, tsr, None, tsa_dir).ok is False  # без запроса: штамп не относится к данным
    with pytest.raises(EcpError, match="другим данным"):
        service.verify_tsr(data, tsr, tsq, tsa_dir)  # с запросом: запрос относится к другим данным


def test_stamp_from_foreign_service_is_untrusted(work, tmp_path):
    data, tsa_dir = work
    tsq, tsr, _ = stamp(work, tmp_path)
    other_dir = tmp_path / "other_tsa"
    service.load_local_tsa(other_dir)  # другая служба с другим ключом
    result = service.verify_tsr(data, tsr, tsq, other_dir)
    assert not result.ok and any("доверенным" in c.name and not c.ok for c in result.checks)


def test_rejected_request_is_reported(work, tmp_path):
    data, tsa_dir = work
    tsq = tmp_path / "bad.tsq"
    tsq.write_bytes(b"garbage")
    tsr = tmp_path / "bad.tsr"
    issued = service.issue_tsr(tsq, tsr, tsa_dir)
    assert issued.status == tsp.REJECTION and issued.gen_time is None and "badDataFormat" in issued.reason
    assert tsr.exists()
    with pytest.raises(EcpError, match="отклонён"):
        service.verify_tsr(data, tsr, None, tsa_dir)


def test_missing_files(work, tmp_path):
    data, tsa_dir = work
    with pytest.raises(EcpError, match="не удалось прочитать"):
        service.create_tsq(tmp_path / "нет.txt", tmp_path / "x.tsq")
    with pytest.raises(EcpError, match="не удалось прочитать"):
        service.issue_tsr(tmp_path / "нет.tsq", tmp_path / "x.tsr", tsa_dir)


def make_signer(tmp_path):
    keys = service.generate_keys(tmp_path / "keys")
    msg = tmp_path / "contract.txt"
    msg.write_bytes(DATA)
    return keys, msg


def test_cades_bt_files(tmp_path):
    keys, msg = make_signer(tmp_path)
    tsa_dir = tmp_path / "tsa"
    out = tmp_path / "contract.p7s"
    res = service.sign_cades_file(msg, keys.private_path, out, "Иванов И.И.", tsa_dir=tsa_dir)
    assert res.timestamped and res.stamp_time is not None
    ok = service.verify_cades_file(msg, out, tsa_dir=tsa_dir)
    assert ok.ok and ok.timestamped and ok.notes == []
    assert ok.timestamp.tsa_name == service.TSA_NAME


def test_cades_bb_has_no_timestamp(tmp_path):
    keys, msg = make_signer(tmp_path)
    out = tmp_path / "contract.p7s"
    res = service.sign_cades_file(msg, keys.private_path, out, "Иванов И.И.")
    assert not res.timestamped and res.stamp_time is None
    assert not service.verify_cades_file(msg, out).timestamped


def test_cades_bt_unknown_service_gives_note(tmp_path):
    keys, msg = make_signer(tmp_path)
    out = tmp_path / "contract.p7s"
    service.sign_cades_file(msg, keys.private_path, out, "Иванов И.И.", tsa_dir=tmp_path / "tsa")
    unknown = service.verify_cades_file(msg, out, tsa_dir=tmp_path / "нет_службы")
    assert unknown.ok and any("не проверена на доверие" in n for n in unknown.notes)
    service.load_local_tsa(tmp_path / "other")
    wrong = service.verify_cades_file(msg, out, tsa_dir=tmp_path / "other")
    assert not wrong.ok


def test_selftest_item_for_timestamps():
    assert service._kat_tsp() is True


def test_timestamp_events_are_logged(tmp_path):
    ctx = AppContext.start(tmp_path / "cfg" / "config.ini", user="tester", host_ip="10.0.0.9")
    try:
        data = tmp_path / "doc.txt"
        data.write_bytes(DATA)
        tsa_dir = tmp_path / "cfg"
        tsq, tsr = tmp_path / "doc.tsq", tmp_path / "doc.tsr"
        service.create_tsq(data, tsq)
        service.issue_tsr(tsq, tsr, tsa_dir)
        service.verify_tsr(data, tsr, tsq, tsa_dir)
        bad = tmp_path / "bad.tsq"
        bad.write_bytes(b"x")
        service.issue_tsr(bad, tmp_path / "bad.tsr", tsa_dir)
        events = audit.read_events(ctx.audit.path)[0]

        def find(**kw):
            return [e for e in events if all(getattr(e, k) == v for k, v in kw.items())]

        assert len(find(source_name="ecp.tsa", action="create", status="success", level="info")) >= 2
        assert find(source_name="ecp.tsp", action="create", status="success")
        ok = find(source_name="ecp.tsp", action="access", status="success")
        assert ok and "ДА" in ok[-1].description
        rejected = find(source_name="ecp.tsa", status="failure")
        assert len(rejected) == 1 and rejected[0].level == "warning" and "отклонён" in rejected[0].description
        assert any(e.object.endswith("tsa.key") and e.action == "create" for e in events)
    finally:
        ctx.shutdown()
