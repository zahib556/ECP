"""Выпуск обновления: ключ подписи, .exe (PyInstaller), ZIP-пакет, SBOM, подписанный манифест.

    python tools/build_update.py keygen                      # один раз; открытый ключ вшивается в приложение
    python tools/build_update.py exe                         # PyInstaller --onedir + ecp-updater.exe -> dist/ecp
    python tools/build_update.py release --version 1.3.0 --min-supported 0.5.0 [--signtool]
                                                             # всё сразу: версия -> exe -> (SignTool) -> проверка -> ZIP+SBOM+манифест
    python tools/build_update.py package --version 1.3.0 --min-supported 0.4.0 --source dist/ecp
    python tools/build_update.py package --version 1.3.0 --min-supported 0.4.0   # из исходников python/ecp

Результат в release/: ecp-<версия>-<ОС>-<арх>.zip (внутри sbom.json), manifest.json, manifest.sig.
Личный ключ (dev_keys/update_signing.key) хранить отдельно и не распространять. После keygen пересоберите приложение:
вшитый открытый ключ - python/ecp/update/pubkey.py. SHA-256 считается от финального ZIP.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from ecp.errors import EcpError  # noqa: E402
from ecp.update import release, sbom, updater  # noqa: E402
from ecp.update import versions  # noqa: E402

APP = "ecp"
DEFAULT_KEY = ROOT / "dev_keys" / "update_signing.key"
PUBKEY_FILE = ROOT / "python" / "ecp" / "update" / "pubkey.py"
_SKIP_DIRS = {"__pycache__", ".git"}


def keygen(key_path: Path = DEFAULT_KEY, pubkey_file: Optional[Path] = PUBKEY_FILE) -> bytes:
    """Новая пара Ed25519: личный ключ - в файл (hex), открытый - в pubkey.py. Возвращает открытый ключ."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if key_path.exists():
        raise EcpError(f"Ошибка: {key_path} уже существует (повторный keygen сделал бы старые обновления недействительными)")
    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(raw.hex())
    if pubkey_file is not None:
        text = pubkey_file.read_text(encoding="utf-8")
        text = re.sub(r'UPDATE_PUBLIC_KEY_B64 = ".*"', f'UPDATE_PUBLIC_KEY_B64 = "{base64.b64encode(public).decode()}"', text)
        pubkey_file.write_text(text, encoding="utf-8")
    return public


def load_private_key(path: Path) -> bytes:
    try:
        raw = bytes.fromhex(Path(path).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        raise EcpError(f"Ошибка: личный ключ подписи обновлений «{path}» не прочитан") from None
    if len(raw) != 32:
        raise EcpError("Ошибка: личный ключ подписи обновлений повреждён")
    return raw


def build_package(payload: Path, out_dir: Path, version: str, min_supported: str, private_key: bytes,
                  os_name: Optional[str] = None, arch: Optional[str] = None, critical: bool = False,
                  app_name: str = APP, components: Sequence[str] = sbom.REQUIRED_COMPONENTS,
                  installed: Optional[Dict[str, str]] = None, now: Optional[datetime] = None) -> Path:
    """ZIP из каталога payload + sbom.json, затем подписанный manifest.json. Возвращает путь к manifest.json."""
    versions.parse(version)
    versions.parse(min_supported)
    os_name, arch = os_name or updater.current_os(), arch or updater.current_arch()
    payload, out_dir = Path(payload), Path(out_dir)
    if not payload.is_dir() or not any(payload.iterdir()):
        raise EcpError(f"Ошибка: каталог с файлами программы «{payload}» пуст или не найден")
    out_dir.mkdir(parents=True, exist_ok=True)
    sbom_bytes = sbom.generate(app_name, version, components, installed)
    package = out_dir / f"{app_name}-{version}-{os_name}-{arch}.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(payload.rglob("*")):
            if path.is_file() and not (_SKIP_DIRS & set(path.relative_to(payload).parts)) and path.suffix != ".pyc":
                if path.name != "sbom.json":
                    z.write(path, path.relative_to(payload).as_posix())
        z.writestr("sbom.json", sbom_bytes)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()  # хэш финального ZIP
    manifest = {
        "version": version, "min_supported": min_supported,
        "release_date": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os": os_name, "arch": arch, "package_url": package.name, "package_size": package.stat().st_size,
        "package_sha256": digest,
        "sbom": {"format": f"CycloneDX-{sbom.SPEC_VERSION}", "url": "sbom.json", "sha256": sbom.sha256_hex(sbom_bytes)},
        "critical": critical,
    }
    signature = release.sign_manifest(manifest, private_key)
    manifest["signature"] = signature
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "manifest.sig").write_text(signature, encoding="ascii")
    return manifest_path


def _exe(folder: Path, name: str = APP) -> Path:
    return folder / (name + (".exe" if sys.platform.startswith("win") else ""))


def set_version(version: str, version_file: Path = ROOT / "python" / "ecp" / "version.py") -> None:
    """Версия внутри программы должна совпадать с версией пакета, иначе после установки приложение
    продолжит считать себя старым (и будет предлагать то же обновление)."""
    versions.parse(version)
    text = version_file.read_text(encoding="utf-8")
    new, n = re.subn(r'^VERSION = ".*"$', f'VERSION = "{version}"', text, count=1, flags=re.M)
    if n != 1:
        raise EcpError(f"Ошибка: в {version_file.name} не найдена строка VERSION = \"...\"")
    version_file.write_text(new, encoding="utf-8")


def build_exe() -> Path:
    """PyInstaller: приложение (--onedir, без консоли) и отдельный ecp-updater.exe, который кладётся рядом."""
    dist = ROOT / "dist"
    run = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", str(dist),
           "--workpath", str(ROOT / "build"), "--specpath", str(ROOT / "build")]
    subprocess.run(run + ["--onedir", "--windowed", "--name", APP, "--paths", str(ROOT / "python"),
                          "--hidden-import", "ecp._core", "--collect-submodules", "ecp",
                          str(ROOT / "main.py")], check=True, cwd=ROOT)
    subprocess.run(run + ["--onefile", "--console", "--name", "ecp-updater",
                          str(ROOT / "python" / "ecp" / "update" / "installer.py")], check=True, cwd=ROOT)
    folder = dist / APP
    shutil.copyfile(_exe(dist, "ecp-updater"), _exe(folder, "ecp-updater"))
    return folder


def signtool_sign(files: Sequence[Path], timestamp_url: str = "http://timestamp.digicert.com") -> None:
    """Подпись .exe (Windows Code Signing). Выполняется ДО упаковки: SHA-256 считается от финального ZIP."""
    tool = shutil.which("signtool")
    if not tool:
        raise EcpError("Ошибка: signtool не найден в PATH (Windows SDK); запустите «x64 Native Tools Command Prompt»")
    for f in files:
        subprocess.run([tool, "sign", "/tr", timestamp_url, "/td", "sha256", "/fd", "sha256", "/a", str(f)], check=True)
        subprocess.run([tool, "verify", "/pa", str(f)], check=True)


def smoke_test(folder: Path) -> None:
    """Запуск собранной программы с «--check» (самотестирование): тот же тест проводит установщик после замены."""
    exe = _exe(folder)
    if not exe.is_file():
        raise EcpError(f"Ошибка: «{exe}» не найден")
    try:
        done = subprocess.run([str(exe), "--check"], timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        raise EcpError(f"Ошибка: собранная программа не запустилась: {e}") from None
    if done.returncode != 0:
        raise EcpError(f"Ошибка: «{exe.name} --check» вернул код {done.returncode}: сборка неработоспособна, "
                       "пакет не создаётся (проверьте, что в окружении установлено криптоядро: maturin develop)")


def build_release(version: str, min_supported: str, out_dir: Path, private_key: bytes, sign_exe: bool = False,
                  critical: bool = False) -> Path:
    """Полный выпуск: версия -> exe -> (SignTool) -> проверка запуска -> ZIP + SBOM + подписанный манифест."""
    if not public_key_embedded():
        raise EcpError("Ошибка: открытый ключ не вшит; выполните keygen и пересоберите (python/ecp/update/pubkey.py)")
    set_version(version)
    folder = build_exe()
    if sign_exe:
        signtool_sign([_exe(folder), _exe(folder, "ecp-updater")])
    smoke_test(folder)
    return build_package(folder, out_dir, version, min_supported, private_key, critical=critical)


def public_key_embedded() -> bool:
    return bool(re.search(r'UPDATE_PUBLIC_KEY_B64 = "[A-Za-z0-9+/=]{40,}"', PUBKEY_FILE.read_text(encoding="utf-8")))


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("exe")
    rl = sub.add_parser("release", help="всё сразу: exe + ZIP + SBOM + подписанный манифест")
    rl.add_argument("--version", required=True)
    rl.add_argument("--min-supported", required=True)
    rl.add_argument("--out", default=str(ROOT / "release"))
    rl.add_argument("--key", default=str(DEFAULT_KEY))
    rl.add_argument("--signtool", action="store_true", help="подписать .exe через SignTool до упаковки")
    rl.add_argument("--critical", action="store_true")
    pk = sub.add_parser("package")
    pk.add_argument("--version", required=True)
    pk.add_argument("--min-supported", required=True)
    pk.add_argument("--source", default=str(ROOT / "python" / "ecp"))
    pk.add_argument("--out", default=str(ROOT / "release"))
    pk.add_argument("--key", default=str(DEFAULT_KEY))
    pk.add_argument("--os", dest="os_name")
    pk.add_argument("--arch")
    pk.add_argument("--critical", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.cmd == "keygen":
            public = keygen()
            print(f"Личный ключ: {DEFAULT_KEY} (хранить отдельно!)")
            print(f"Открытый ключ вшит в {PUBKEY_FILE.relative_to(ROOT)}: {base64.b64encode(public).decode()}")
        elif args.cmd == "exe":
            print("Собрано:", build_exe())
        elif args.cmd == "release":
            path = build_release(args.version, args.min_supported, Path(args.out), load_private_key(Path(args.key)),
                                 args.signtool, args.critical)
            data = json.loads(path.read_text(encoding="utf-8"))
            print(f"Манифест: {path}\nПакет: {path.parent / data['package_url']}\nSHA-256 пакета: {data['package_sha256']}")
        else:
            path = build_package(Path(args.source), Path(args.out), args.version, args.min_supported,
                                 load_private_key(Path(args.key)), args.os_name, args.arch, args.critical)
            data = json.loads(path.read_text(encoding="utf-8"))
            print(f"Манифест: {path}\nПакет: {path.parent / data['package_url']}\nSHA-256 пакета: {data['package_sha256']}")
    except (EcpError, ValueError, subprocess.CalledProcessError) as e:
        print(e)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
