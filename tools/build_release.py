"""Выпуск релиза: подпись ЭЦП разработчика под контрольными хэшами файлов программы.

    python tools/build_release.py keygen                 # один раз: ключи разработчика
    python tools/build_release.py sign                   # после финальных изменений кода
    python tools/build_release.py check                  # проверка результата

Личный ключ разработчика (dev_keys/developer.key) хранить отдельно от программы и не распространять.
Открытый ключ (python/ecp/developer.pub) входит в состав программы; его отпечаток публикуется отдельно.
После `sign` любое изменение файлов программы приведёт к блокировке самотестированием.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from ecp import manifest, service  # noqa: E402
from ecp.errors import EcpError  # noqa: E402
from ecp.version import VERSION, is_semver  # noqa: E402


def cmd_keygen(args: argparse.Namespace) -> int:
    private, public = manifest.init_developer_key(Path(args.out))
    print(f"Личный ключ разработчика: {private}  (хранить отдельно!)")
    print(f"Открытый ключ:            {public}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    if not is_semver(args.version):
        print("Ошибка: версия должна иметь вид Major.Minor.Patch, например 1.0.0")
        return 2
    d = service.read_file(args.key, "файл личного ключа разработчика")
    path = manifest.release(d, version=args.version)
    rep = manifest.check()
    print(f"Манифест: {path}")
    print(f"Версия: {rep.version}, дата сборки: {rep.build_date}")
    print(f"Отпечаток ключа разработчика (belt-hash): {rep.fingerprint.upper()}")
    print("Проверка:", "успешно" if rep.status == "ok" else "НЕ ПРОЙДЕНА")
    return 0 if rep.status == "ok" else 1


def cmd_check(_: argparse.Namespace) -> int:
    rep = manifest.check()
    print("Статус:", rep.status, "| подлинность:", rep.authentic)
    for f in rep.files:
        print(("  OK   " if f.ok else "  FAIL ") + f.name + (f" — {f.detail}" if f.detail else ""))
    for p in rep.auth_problems + rep.problems:
        print("  !", p)
    return 0 if rep.status == "ok" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Выпуск релиза ecp")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen", help="создать ключи разработчика")
    p.add_argument("--out", default=str(ROOT / "dev_keys"), help="каталог для личного ключа")
    p.set_defaults(func=cmd_keygen)
    p = sub.add_parser("sign", help="создать и подписать манифест")
    p.add_argument("--key", default=str(ROOT / "dev_keys" / "developer.key"))
    p.add_argument("--version", default=VERSION)
    p.set_defaults(func=cmd_sign)
    p = sub.add_parser("check", help="проверить целостность и подлинность")
    p.set_defaults(func=cmd_check)
    args = parser.parse_args()
    try:
        return args.func(args)
    except EcpError as e:
        print(e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
