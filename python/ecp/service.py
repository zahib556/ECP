"""Слой приложения: файлы, проверки входных данных, сообщения об ошибках, самотестирование.

Не зависит от GUI, поэтому тестируется отдельно. Все ошибки пользователя - EcpError.
События безопасности пишутся в журнал, если он подключён через set_audit().
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Union

from . import _core, cades, manifest, tsp, x509
from .audit import AuditLog
from .cryptoif import default_crypto
from .curve import check_public_key
from .errors import EcpError
from .version import VERSION

PathLike = Union[str, Path]

MAX_FILE_SIZE = 256 * 1024 * 1024
PRIVATE_KEY_LEN = 32
PUBLIC_KEY_LEN = 64
SIGNATURE_LEN = 48
PRIVATE_KEY_NAME = "private.key"
PUBLIC_KEY_NAME = "public.key"

# ---------------------------------------------------------------- журнал событий
_audit: Optional[AuditLog] = None


def set_audit(audit: Optional[AuditLog]) -> None:
    global _audit
    _audit = audit


def get_audit() -> Optional[AuditLog]:
    return _audit


# ---------------------------------------------------------------- контроль доступа
_access_guard: Optional[Callable[[], None]] = None


def set_access_guard(guard: Optional[Callable[[], None]]) -> None:
    """Проверка права на операции (вход выполнен). Без неё - операции доступны всем (CLI, тесты)."""
    global _access_guard
    _access_guard = guard


class _NullOp:
    description = ""
    level = "info"
    status = "success"
    action = "access"
    obj = ""


@contextmanager
def _op(source: str, description: str, action: str, obj: PathLike = "") -> Iterator[object]:
    """Операция с записью в журнал (если он подключён); без журнала - обычное выполнение.

    Все операции с файлами проходят через _op, поэтому проверка входа стоит здесь."""
    if _access_guard is not None:
        _access_guard()
    if _audit is None:
        yield _NullOp()
        return
    with _audit.operation(source, description, action=action, obj=str(obj)) as op:
        yield op


def audit_cancel(source: str, description: str, action: str = "create", obj: PathLike = "") -> None:
    """Отменённое пользователем действие (например, закрыт диалог сохранения)."""
    if _audit is not None:
        _audit.log(source, description, level="info", status="cancelled", action=action, obj=str(obj))


def _log_file(action: str, path: Path, what: str, error: str = "") -> None:
    if _audit is None:
        return
    verb = "Чтение" if action == "access" else "Запись"
    ok = not error
    _audit.log(
        "ecp.files",
        f"{verb} {what} «{path.name}»" + (f": {error}" if error else ""),
        level="info" if ok else "error",
        status="success" if ok else "failure",
        action=action,
        obj=str(path),
    )


# ---------------------------------------------------------------- файлы
def read_file(path: PathLike, what: str = "файл") -> bytes:
    p = Path(path)
    try:
        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            raise EcpError(
                f"Ошибка: {what} «{p.name}» слишком большой ({size} байт, максимум {MAX_FILE_SIZE})"
            )
        data = p.read_bytes()
    except EcpError as e:
        _log_file("access", p, what, str(e))
        raise
    except OSError as e:
        error = EcpError(f"Ошибка: не удалось прочитать {what} «{p.name}»: {e.strerror or e}")
        _log_file("access", p, what, str(error))
        raise error from None
    _log_file("access", p, what)
    return data


def write_file(path: PathLike, data: bytes, what: str = "файл") -> None:
    p = Path(path)
    action = "modify" if p.exists() else "create"  # перезапись существующего объекта = изменение
    try:
        p.write_bytes(data)
    except OSError as e:
        error = EcpError(f"Ошибка: не удалось записать файл «{p.name}»: {e.strerror or e}")
        _log_file(action, p, what, str(error))
        raise error from None
    _log_file(action, p, what)


def format_hex(data: bytes, group: int = 4, per_line: int = 4) -> str:
    """Шестнадцатеричная запись группами по 4 байта, как в стандартах."""
    words = [data[i : i + group].hex().upper() for i in range(0, len(data), group)]
    lines = [" ".join(words[i : i + per_line]) for i in range(0, len(words), per_line)]
    return "\n".join(lines)


# ---------------------------------------------------------------- загрузка ключей и подписи
def load_private_key(path: PathLike) -> bytes:
    data = read_file(path, "файл личного ключа")
    if len(data) != PRIVATE_KEY_LEN:
        raise EcpError("Ошибка: неверный формат ключа (личный ключ: 32 байта)")
    try:
        _core.derive_public_key(data)  # проверка диапазона 1 <= d < q
    except ValueError as e:
        raise EcpError(str(e)) from None
    return data


def load_public_key(path: PathLike) -> bytes:
    data = read_file(path, "файл открытого ключа")
    check_public_key(data)
    return data


def load_signature(path: PathLike) -> bytes:
    data = read_file(path, "файл подписи")
    if len(data) != SIGNATURE_LEN:
        raise EcpError("Ошибка: неверная длина подписи (|S| ≠ 3l, ожидается 48 байт)")
    return data


# ---------------------------------------------------------------- операции
@dataclass
class SignResult:
    signature: bytes
    message_hash: bytes
    signature_path: Path


def sign_file(message_path: PathLike, key_path: PathLike, out_path: PathLike) -> SignResult:
    """Выработка ЭЦП файла (СТБ 34.101.45, п. 7.1.3, h = belt-hash)."""
    name = Path(message_path).name
    with _op("ecp.sign", f"Выработка ЭЦП файла «{name}»", "create", out_path) as op:
        message = read_file(message_path, "сообщение")
        d = load_private_key(key_path)
        try:
            h = _core.belt_hash(message)
            k = _core.gen_k(d, h)
            s = _core.sign_hash_with_k(d, k, h)
            # контроль выходной информации: выработанная подпись обязана проходить проверку
            if not _core.verify(_core.derive_public_key(d), message, s):
                raise EcpError("Ошибка: контроль выработанной подписи не пройден")
        except ValueError as e:
            raise EcpError(str(e)) from None
        write_file(out_path, s, "файл подписи")
        op.description = f"Выработана ЭЦП файла «{name}»: {Path(out_path).name} ({len(s)} байт)"
    return SignResult(signature=s, message_hash=h, signature_path=Path(out_path))


@dataclass
class VerifyResult:
    ok: bool
    message_hash: bytes
    corrupted_demo: bool


def verify_files(
    message_path: PathLike,
    signature_path: PathLike,
    key_path: PathLike,
    corrupt: bool = False,
) -> VerifyResult:
    """Проверка ЭЦП (п. 7.1.4). corrupt=True - демонстрация: в подписи меняется один бит."""
    name = Path(message_path).name
    with _op("ecp.verify", f"Проверка ЭЦП файла «{name}»", "access", message_path) as op:
        message = read_file(message_path, "сообщение")
        s = load_signature(signature_path)
        q = load_public_key(key_path)
        if corrupt:
            broken = bytearray(s)
            broken[0] ^= 0x01
            s = bytes(broken)
        try:
            ok = _core.verify(q, message, s)
        except ValueError as e:
            raise EcpError(str(e)) from None
        demo = " (демонстрация: подпись повреждена)" if corrupt else ""
        if ok:
            op.description = f"Проверка ЭЦП файла «{name}»: ДА — подпись верна{demo}"
        else:
            op.status, op.level = "failure", "warning"
            op.description = f"Проверка ЭЦП файла «{name}»: НЕТ — подпись неверна{demo}"
    return VerifyResult(ok=ok, message_hash=_core.belt_hash(message), corrupted_demo=corrupt)


@dataclass
class KeygenResult:
    private_path: Path
    public_path: Path
    private_key: bytes
    public_key: bytes
    consistent: bool  # проверка Q = d*G


def generate_keys(directory: PathLike, overwrite: bool = False) -> KeygenResult:
    """Генерация пары ключей (п. 6.2.2) и сохранение в каталог."""
    folder = Path(directory)
    priv, pub = folder / PRIVATE_KEY_NAME, folder / PUBLIC_KEY_NAME
    with _op("ecp.keys", "Генерация пары ключей", "create", folder) as op:
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise EcpError(f"Ошибка: не удалось создать каталог «{folder}»: {e.strerror or e}") from None
        if not overwrite and (priv.exists() or pub.exists()):
            raise EcpError(
                f"Ошибка: в каталоге уже есть {PRIVATE_KEY_NAME} или {PUBLIC_KEY_NAME}, "
                "выберите другой каталог"
            )
        d, q = _core.generate_keypair()
        consistent = _core.derive_public_key(d) == q
        check_public_key(q)
        if not consistent:
            raise EcpError("Ошибка: контроль соответствия Q = d·G не пройден, ключи не сохранены")
        write_file(priv, d, "файл личного ключа")
        write_file(pub, q, "файл открытого ключа")
        op.description = f"Сгенерирована пара ключей, сохранена в каталог «{folder}»"
    return KeygenResult(priv, pub, d, q, consistent)


# ---------------------------------------------------------------- расширенная ЭЦП (CAdES-B-B, СТБ 34.101.80)
@dataclass
class CadesSignResult:
    cms: bytes
    message_hash: bytes
    signing_time: datetime
    signer: str
    cert_serial: int
    path: Path
    timestamped: bool = False
    stamp_time: Optional[datetime] = None


def sign_cades_file(
    message_path: PathLike,
    key_path: PathLike,
    out_path: PathLike,
    common_name: str,
    attach: bool = False,
    tsa_dir: Optional[PathLike] = None,
) -> CadesSignResult:
    """Расширенная ЭЦП файла: самоподписанный сертификат владельца ключа + CAdES-B-B.

    tsa_dir задан - к подписи добавляется штамп времени локальной службы (профиль CAdES-B-T).
    """
    name = Path(message_path).name
    profile = "CAdES-B-T" if tsa_dir is not None else "CAdES-B-B"
    with _op("ecp.cades", f"Выработка расширенной ЭЦП ({profile}) файла «{name}»", "create", out_path) as op:
        message = read_file(message_path, "сообщение")
        d = load_private_key(key_path)
        crypto = default_crypto()
        authority = load_local_tsa(tsa_dir) if tsa_dir is not None else None
        try:
            cert_der = x509.build_self_signed(d, common_name, crypto)
            provider = tsp.make_provider(authority, crypto) if authority is not None else None
            cms = cades.build_cades_bb(message, d, cert_der, crypto, attach=attach, timestamp_provider=provider)
            checked = cades.verify_cades(cms, None if attach else message, crypto,  # контроль выхода
                                         trusted_tsa_key=authority.public_key if authority else None)
        except ValueError as e:
            raise EcpError(str(e)) from None
        if not checked.ok:
            raise EcpError("Ошибка: контроль выработанной расширенной подписи не пройден")
        write_file(out_path, cms, "файл расширенной подписи")
        op.description = (f"Выработана расширенная ЭЦП ({profile}) файла «{name}»: "
                          f"{Path(out_path).name}, владелец «{common_name}»")
    cert = x509.parse_certificate(cert_der)
    stamp = checked.timestamp.gen_time if checked.timestamp is not None else None
    return CadesSignResult(cms, checked.digest, checked.signing_time, cert.subject_cn,
                           cert.serial, Path(out_path), timestamped=checked.timestamped, stamp_time=stamp)


def is_cades_data(data: bytes) -> bool:
    """Подпись ГОСТ 34.101.45 - ровно 48 байт; контейнер CMS длиннее и начинается с SEQUENCE."""
    return len(data) != SIGNATURE_LEN and data[:1] == b"\x30"


def verify_cades_file(
    message_path: Optional[PathLike],
    cms_path: PathLike,
    key_path: Optional[PathLike] = None,
    tsa_dir: Optional[PathLike] = None,
) -> cades.CadesResult:
    name = Path(cms_path).name
    with _op("ecp.cades", f"Проверка расширенной ЭЦП «{name}»", "access", cms_path) as op:
        cms = read_file(cms_path, "файл расширенной подписи")
        message = read_file(message_path, "сообщение") if message_path else None
        trusted = load_public_key(key_path) if key_path else None
        trusted_tsa = trusted_tsa_key(tsa_dir) if tsa_dir is not None else None
        try:
            result = cades.verify_cades(cms, message, default_crypto(), trusted, trusted_tsa)
        except ValueError as e:
            raise EcpError(str(e)) from None
        if result.ok:
            op.description = f"Проверка расширенной ЭЦП «{name}»: ДА — подпись верна, владелец «{result.signer}»"
        else:
            failed = "; ".join(c.name for c in result.checks if not c.ok)
            op.status, op.level = "failure", "warning"
            op.description = f"Проверка расширенной ЭЦП «{name}»: НЕТ — не пройдено: {failed}"
    return result


# ---------------------------------------------------------------- штамп времени (СТБ 34.101.82)
TSA_KEY_NAME = "tsa.key"
TSA_CERT_NAME = "tsa.cer"
TSA_NAME = "ECP Local Time-Stamping Authority"


def load_local_tsa(directory: PathLike) -> tsp.TimeStampAuthority:
    """Локальная служба штампов времени. При первом обращении создаются её ключ и сертификат."""
    folder = Path(directory)
    key_path, cert_path = folder / TSA_KEY_NAME, folder / TSA_CERT_NAME
    with _op("ecp.tsa", "Загрузка локальной службы штампов времени", "access", folder) as op:
        if key_path.exists() and cert_path.exists():
            d = read_file(key_path, "ключ службы штампов времени")
            cert = read_file(cert_path, "сертификат службы штампов времени")
        else:
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise EcpError(f"Ошибка: не удалось создать каталог «{folder}»: {e.strerror or e}") from None
            d, _ = _core.generate_keypair()
            cert = x509.build_self_signed(d, TSA_NAME, default_crypto(), time_stamping=True)
            write_file(key_path, d, "ключ службы штампов времени")
            write_file(cert_path, cert, "сертификат службы штампов времени")
            op.action = "create"
            op.description = "Создана локальная служба штампов времени (ключ и сертификат)"
        authority = tsp.TimeStampAuthority(d, cert, default_crypto())
    return authority


def trusted_tsa_key(directory: PathLike) -> Optional[bytes]:
    """Открытый ключ локальной службы, которой доверяем; None - службы нет."""
    path = Path(directory) / TSA_CERT_NAME
    try:
        return x509.parse_certificate(path.read_bytes()).public_key if path.exists() else None
    except (OSError, EcpError):
        return None


@dataclass
class TsqResult:
    request: bytes
    imprint: bytes
    nonce: int
    path: Path


def create_tsq(data_path: PathLike, out_path: PathLike) -> TsqResult:
    """Запрос на получение штампа времени (TimeStampReq) для файла."""
    name = Path(data_path).name
    with _op("ecp.tsp", f"Формирование запроса штампа времени для файла «{name}»", "create", out_path) as op:
        data = read_file(data_path, "файл данных")
        imprint = _core.belt_hash(data)
        nonce = tsp.new_nonce()
        request = tsp.build_request(imprint, nonce=nonce, cert_req=True)
        write_file(out_path, request, "файл запроса (.tsq)")
        op.description = f"Сформирован запрос штампа времени «{Path(out_path).name}» для файла «{name}»"
    return TsqResult(request, imprint, nonce, Path(out_path))


@dataclass
class TsrIssueResult:
    response: bytes
    status: int
    status_text: str
    reason: str
    serial: Optional[int]
    gen_time: Optional[datetime]
    path: Path


def issue_tsr(tsq_path: PathLike, out_path: PathLike, tsa_dir: PathLike) -> TsrIssueResult:
    """Ответ локальной службы штампов времени (TimeStampResp) на запрос."""
    name = Path(tsq_path).name
    with _op("ecp.tsa", f"Выпуск штампа времени по запросу «{name}»", "create", out_path) as op:
        request = read_file(tsq_path, "файл запроса (.tsq)")
        authority = load_local_tsa(tsa_dir)
        response = authority.respond(request)
        status, text, fail, token = tsp.parse_response_status(response)
        serial = gen_time = None
        if token is not None:
            req = tsp.parse_request(request)
            info = tsp.verify_token(token, req.imprint, req.nonce, default_crypto(),
                                    trusted_key=authority.public_key)
            serial, gen_time = info.serial, info.gen_time
        reason = "; ".join(x for x in (text, tsp.FAIL_TEXT.get(fail, "") if fail is not None else "") if x)
        write_file(out_path, response, "файл ответа (.tsr)")
        status_text = tsp.STATUS_TEXT.get(status, f"статус {status}")
        if token is not None:
            op.description = (f"Выпущен штамп времени «{Path(out_path).name}», серийный номер {serial:X}, "
                              f"время {gen_time:%Y-%m-%d %H:%M:%S} UTC")
        else:
            op.status, op.level = "failure", "warning"
            op.description = f"Запрос «{name}» отклонён службой: {reason}"
    return TsrIssueResult(response, status, status_text, reason, serial, gen_time, Path(out_path))


def verify_tsr(
    data_path: PathLike,
    tsr_path: PathLike,
    tsq_path: Optional[PathLike] = None,
    tsa_dir: Optional[PathLike] = None,
) -> tsp.TspResult:
    """Проверка ответа службы: штамп относится к данным, подпись службы, nonce (если есть запрос)."""
    name = Path(tsr_path).name
    with _op("ecp.tsp", f"Проверка штампа времени «{name}»", "access", tsr_path) as op:
        data = read_file(data_path, "файл данных")
        response = read_file(tsr_path, "файл ответа (.tsr)")
        imprint = _core.belt_hash(data)
        nonce = None
        if tsq_path:
            req = tsp.parse_request(read_file(tsq_path, "файл запроса (.tsq)"))
            if req.imprint != imprint:
                raise EcpError("Ошибка: запрос штампа времени относится к другим данным")
            nonce = req.nonce
        trusted = trusted_tsa_key(tsa_dir) if tsa_dir is not None else None
        try:
            result = tsp.verify_response(response, imprint, nonce, default_crypto(), trusted_key=trusted)
        except ValueError as e:
            raise EcpError(str(e)) from None
        if result.ok:
            op.description = f"Проверка штампа времени «{name}»: ДА — штамп верен ({result.gen_time:%Y-%m-%d %H:%M:%S} UTC)"
        else:
            failed = "; ".join(c.name for c in result.checks if not c.ok)
            op.status, op.level = "failure", "warning"
            op.description = f"Проверка штампа времени «{name}»: НЕТ — не пройдено: {failed}"
    return result


# ---------------------------------------------------------------- самотестирование (СТБ 34.101.27: СТ.3)
@dataclass
class TestResult:
    __test__ = False  # не тест для pytest
    name: str
    ok: bool
    detail: str = ""


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


_K32 = "E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6"
_D = "1F66B5B8 4B733967 4533F032 9C74F218 34281FED 0732429E 0C79235F C273E269"
_Q = (
    "BD1A5650 179D79E0 3FCEE49D 4C2BD5DD F54CE46D 0CF11E4F F87BF7A8 90857FD0 "
    "7AC6A603 61E8C817 3491686D 461B2826 190C2EDA 5909054A 9AB84D2A B9D99A90"
)
_H2 = "ABEF9725 D4C5A835 97A367D1 4494CC25 42F20F65 9DDFECC9 61A3EC55 0CBA8C75"
_X3 = (
    "B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D "
    "5BE3D612 17B96181 FE6786AD 716B890B"
)
_S3 = (
    "47A63C8B 9C936E94 B5FAB3D9 CBD78366 290F3210 E163EEC8 DB4E921E 8479D413 "
    "8F112CC2 3E6DCE65 EC5FF21D F4231C28"
)


def _kat_belt_hash() -> bool:
    return _core.belt_hash(_h("B194BAC8 0A08F53B 366D008E 58")) == _h(_H2)


def _kat_hmac() -> bool:
    x = "BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF8C A58450BF 66D2E88A"
    y = "41FFE864 5AEC0612 E952D2CD F8DD508F 3E4A1D9B 53F6A1DB 293B19FE 76B1879F"
    return _core.hmac_hbelt(_h(_K32), _h(x)) == _h(y)


def _kat_brng() -> bool:
    s = "BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF8C A58450BF 66D2E88A"
    first = _h(_X3)[:32]
    return _core.brng_ctr(_h(_K32), _h(s), 1, first) == _h(_D)


def _kat_public_key() -> bool:
    return _core.derive_public_key(_h(_D)) == _h(_Q)


def _kat_gen_k() -> bool:
    k = "829614D8 411DBBC4 E1F2471A 40045864 40FD8C95 53FAB6A1 A45CE417 AE97111E"
    return _core.gen_k(_h(_D), _h(_H2)) == _h(k)


def _kat_sign() -> bool:
    k = "4C0E74B2 CD5811AD 21F23DE7 E0FA742C 3ED6EC48 3C461CE1 5C33A77A A308B7D2"
    s = (
        "E36B7F03 77AE4C52 4027C387 FADF1B20 CE72F153 0B71F2B5 FD3A8C58 4FE2E1AE "
        "D20082E3 0C8AF650 11F4FB54 649DFD3D"
    )
    return _core.sign_hash_with_k(_h(_D), _h(k), _h(_H2)) == _h(s)


def _kat_verify() -> bool:
    good = _core.verify(_h(_Q), _h(_X3), _h(_S3)) is True
    bad = _core.verify(_h(_Q), _h(_X3) + b"\x00", _h(_S3)) is False
    return good and bad


def _kat_cades() -> bool:
    crypto = default_crypto()
    d = _h(_D)
    msg = b"selftest"
    cert = x509.build_self_signed(d, "Самотестирование", crypto)
    cms = cades.build_cades_bb(msg, d, cert, crypto)
    good = cades.verify_cades(cms, msg, crypto).ok
    bad = not cades.verify_cades(cms, msg + b"x", crypto).ok
    return good and bad


def _kat_tsp() -> bool:
    crypto = default_crypto()
    d = _h(_D)
    cert = x509.build_self_signed(d, "Самотестирование СШВ", crypto, time_stamping=True)
    authority = tsp.TimeStampAuthority(d, cert, crypto)
    imprint, nonce = _core.belt_hash(b"selftest"), tsp.new_nonce()
    response = authority.respond(tsp.build_request(imprint, nonce=nonce))
    good = tsp.verify_response(response, imprint, nonce, crypto, trusted_key=authority.public_key).ok
    other = _core.belt_hash(b"other")
    bad = not tsp.verify_response(response, other, nonce, crypto, trusted_key=authority.public_key).ok
    return good and bad


def _integrity_results() -> List[TestResult]:
    """Целостность (belt-hash файлов) и подлинность (ЭЦП разработчика под эталоном)."""
    n_int = "Целостность файлов программы (belt-hash)"
    n_aut = "Подлинность ПО (ЭЦП разработчика, bign-with-hbelt)"
    rep = manifest.check(crypto=default_crypto())
    if rep.status == "absent":
        note = "эталон не создан (режим разработки): python tools/build_release.py sign"
        return [TestResult(n_int, True, note), TestResult(n_aut, True, note)]
    bad = [f"{f.name}: {f.detail}" for f in rep.files if not f.ok] + rep.problems
    return [
        TestResult(n_int, not bad, "; ".join(bad)),
        TestResult(n_aut, bool(rep.authentic), "; ".join(rep.auth_problems)),
    ]


def _log_selftest(results: List[TestResult]) -> None:
    if _audit is None:
        return
    failed = [r for r in results if not r.ok]
    for r in failed:
        _audit.log("ecp.selftest", f"Не пройдено: {r.name}" + (f" — {r.detail}" if r.detail else ""),
                   level="critical", status="failure", action="execute")
    if not failed:
        _audit.log("ecp.selftest", f"Самотестирование пройдено ({len(results)} проверок)",
                   level="info", status="success", action="execute")


def self_test() -> List[TestResult]:
    """Тесты работоспособности: алгоритмы по эталонным примерам и целостность файлов."""
    checks: List[tuple] = [
        ("belt-hash (СТБ 34.101.31, табл. А.23)", _kat_belt_hash),
        ("hmac-hbelt (СТБ 34.101.47, табл. В.1)", _kat_hmac),
        ("brng-ctr-hbelt (СТБ 34.101.47, табл. В.2)", _kat_brng),
        ("Пара ключей Q = d·G (СТБ 34.101.45, табл. Г.1)", _kat_public_key),
        ("Одноразовый ключ k (СТБ 34.101.45, табл. Г.6)", _kat_gen_k),
        ("Выработка ЭЦП (СТБ 34.101.45, табл. Г.2)", _kat_sign),
        ("Проверка ЭЦП (СТБ 34.101.45, табл. Г.3)", _kat_verify),
        ("Расширенная ЭЦП CAdES-B-B: формирование и проверка (СТБ 34.101.80)", _kat_cades),
        ("Штамп времени: запрос, ответ службы, проверка (СТБ 34.101.82)", _kat_tsp),
    ]
    results: List[TestResult] = []
    for name, fn in checks:
        try:
            ok = bool(fn())
            results.append(TestResult(name, ok, "" if ok else "результат не совпал с эталоном"))
        except Exception as e:  # noqa: BLE001 - любой сбой теста = ошибка самотестирования
            results.append(TestResult(name, False, f"{type(e).__name__}: {e}"))
    results.extend(_integrity_results())
    _log_selftest(results)
    return results


def program_checksums() -> dict:
    """Сервис вывода контрольных характеристик файлов программы (РС.2)."""
    return manifest.compute()


def version() -> str:
    return VERSION


def core_version() -> str:
    return _core.core_version()


@dataclass
class BuildInfo:
    version: str
    build_date: str  # пусто - сборка не выпускалась (режим разработки)
    authentic: Optional[bool]  # None - ЭЦП нет (режим разработки)
    fingerprint: str
    status: str
    core_version: str


def integrity_report() -> manifest.IntegrityReport:
    return manifest.check(crypto=default_crypto())


def check_integrity() -> manifest.IntegrityReport:
    """Проверка целостности и подлинности ПО по запросу пользователя, с записью в журнал."""
    rep = integrity_report()
    if _audit is not None:
        if rep.status == "ok":
            _audit.log("ecp.selftest", "Проверка целостности и подлинности ПО: успешно",
                       level="info", status="success", action="execute")
        elif rep.status == "absent":
            _audit.info("ecp.selftest", "Проверка целостности ПО: эталон не создан (режим разработки)")
        else:
            problems = [f"{f.name}: {f.detail}" for f in rep.files if not f.ok] + rep.auth_problems + rep.problems
            _audit.log("ecp.selftest", "Проверка целостности и подлинности ПО не пройдена: " + "; ".join(problems),
                       level="critical", status="failure", action="execute")
    return rep


def build_info() -> BuildInfo:
    rep = integrity_report()
    authentic = None if rep.status == "absent" else rep.authentic
    return BuildInfo(VERSION, rep.build_date, authentic, rep.fingerprint, rep.status, _core.core_version())
