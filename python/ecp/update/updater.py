"""Updater: проверка манифеста, пакета и SBOM, подготовка staging и установка.

Не зависит от GUI. Каждый исход фиксируется через recorder(status, from_version, to_version, detail),
статусы update_audit: verified | installed | failed | rolled_back | sbom_mismatch.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from ..errors import EcpError
from . import installer, sbom, staging, versions
from .pubkey import UPDATE_PUBLIC_KEY_B64
from .release import ManifestError, UpdateManifest, decode_b64, verify_manifest
from .source import IUpdateSource

Recorder = Callable[[str, str, str, str], None]


class UpdateError(EcpError):
    """Обновление отклонено. status - значение для update_audit."""

    def __init__(self, message: str, status: str = "failed") -> None:
        super().__init__(message)
        self.status = status


@dataclass
class UpdatePlan:
    manifest: UpdateManifest
    source: IUpdateSource


@dataclass
class PreparedUpdate:
    manifest: UpdateManifest
    app_dir: Path
    staging: Path
    backup: Path
    from_version: str


def current_os() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def current_arch() -> str:
    machine = platform.machine().lower()
    return "arm64" if machine in ("arm64", "aarch64") else "x64" if machine in ("amd64", "x86_64", "x64") else "x86"


def embedded_public_key() -> bytes:
    if not UPDATE_PUBLIC_KEY_B64:
        raise UpdateError("Ошибка: ключ проверки обновлений не задан в приложении "
                          "(python tools/build_update.py keygen)")
    key = decode_b64(UPDATE_PUBLIC_KEY_B64, "вшитый ключ обновлений")
    if len(key) != 32:
        raise UpdateError("Ошибка: вшитый ключ обновлений повреждён")
    return key


class Updater:
    def __init__(self, app_dir: Path, current_version: str, public_key: Optional[bytes] = None,
                 recorder: Optional[Recorder] = None, guard: Optional[Callable[[], None]] = None,
                 os_name: Optional[str] = None, arch: Optional[str] = None,
                 required_components: Sequence[str] = sbom.REQUIRED_COMPONENTS,
                 entry_files: Sequence[str] = ()) -> None:
        self.app_dir = Path(app_dir)
        self.current_version = current_version
        self._public_key = public_key
        self._record = recorder or (lambda *a: None)
        self._guard = guard
        self.os_name = os_name or current_os()
        self.arch = arch or current_arch()
        self.required = tuple(required_components)
        self.entry_files = tuple(entry_files)

    # ---------------------------------------------------------------- служебное
    @property
    def staging_dir(self) -> Path:
        return self.app_dir.parent / (self.app_dir.name + ".staging")

    @property
    def backup_dir(self) -> Path:
        return self.app_dir.parent / (self.app_dir.name + ".backup")

    def _fail(self, error: EcpError, to_version: str = "", status: Optional[str] = None) -> UpdateError:
        st = status or getattr(error, "status", "failed")
        self._record(st, self.current_version, to_version, str(error))
        return error if isinstance(error, UpdateError) else UpdateError(str(error), st)

    # ---------------------------------------------------------------- шаги 1-2: манифест и подпись
    def check(self, source: IUpdateSource) -> UpdatePlan:
        """Читает манифест, проверяет подпись и совместимость. При отказе - UpdateError, запись failed."""
        if self._guard:
            self._guard()
        try:
            manifest_bytes, sig = source.read_manifest()
            key = self._public_key if self._public_key is not None else embedded_public_key()
            manifest = verify_manifest(manifest_bytes, sig, key)
        except ManifestError as e:
            raise self._fail(e) from None
        except EcpError as e:
            raise self._fail(e) from None
        self._check_compatible(manifest)
        self._record("verified", self.current_version, manifest.version, "подпись манифеста подтверждена")
        return UpdatePlan(manifest, source)

    def _check_compatible(self, m: UpdateManifest) -> None:
        cur = versions.parse(self.current_version)
        problems = []
        if versions.parse(m.min_supported) > cur:
            problems.append(f"текущая версия {self.current_version} ниже минимальной для обновления "
                            f"({m.min_supported}): обновление заблокировано, требуется ручная установка «с нуля»")
        elif versions.parse(m.version) <= cur:
            problems.append(f"версия {m.version} не новее установленной ({self.current_version}): "
                            "понижение версии запрещено")
        if m.os != self.os_name or m.arch != self.arch:
            problems.append(f"пакет для {m.os}/{m.arch}, а приложение работает на {self.os_name}/{self.arch}")
        if problems:
            raise self._fail(UpdateError("Ошибка: " + "; ".join(problems)), m.version)

    # ---------------------------------------------------------------- шаги 3-6: пакет, staging, SBOM
    def prepare(self, plan: UpdatePlan) -> PreparedUpdate:
        """Размер и SHA-256 пакета, распаковка в staging, проверка SBOM. При ошибке staging удаляется."""
        if self._guard:
            self._guard()
        m = plan.manifest
        stage = self.staging_dir
        try:
            package = plan.source.open_package(m)
            if package.stat().st_size != m.package_size:
                raise UpdateError("Ошибка: размер пакета не совпадает с манифестом")
            digest = hashlib.sha256()
            with open(package, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
            if not hmac.compare_digest(digest.hexdigest(), m.package_sha256):
                raise UpdateError("Ошибка: SHA-256 пакета не совпадает с манифестом (пакет подменён или повреждён)")
            if stage.exists():
                shutil.rmtree(stage)
            staging.extract(package, stage)
            self._check_sbom(stage, m)
            for name in self.entry_files:
                if not (stage / name).is_file():
                    raise UpdateError(f"Ошибка: в пакете нет обязательного файла «{name}»")
        except EcpError as e:
            shutil.rmtree(stage, ignore_errors=True)
            raise self._fail(e, m.version) from None
        except OSError as e:
            shutil.rmtree(stage, ignore_errors=True)
            raise self._fail(UpdateError(f"Ошибка: не удалось подготовить обновление: {e.strerror or e}"), m.version) from None
        return PreparedUpdate(m, self.app_dir, stage, self.backup_dir, self.current_version)

    def _check_sbom(self, stage: Path, m: UpdateManifest) -> None:
        path = stage / "sbom.json"
        if not path.is_file():
            raise UpdateError("Ошибка: в пакете нет sbom.json", "sbom_mismatch")
        try:
            sbom.check(path.read_bytes(), m.sbom.sha256, m.version, m.sbom.format, self.required)
        except sbom.SbomMismatch as e:
            raise UpdateError(str(e), "sbom_mismatch") from None

    def discard(self, prepared: PreparedUpdate) -> None:
        shutil.rmtree(prepared.staging, ignore_errors=True)

    # ---------------------------------------------------------------- шаги 7-9: установка
    def install(self, prepared: PreparedUpdate,
                health_check: Optional[Callable[[Path], bool]] = None) -> installer.SwapResult:
        """Замена «на месте» в этом же процессе (тесты, неблокируемые каталоги)."""
        if self._guard:
            self._guard()
        result = installer.perform_swap(prepared.app_dir, prepared.staging, prepared.backup, health_check)
        self._record(result.status, prepared.from_version, prepared.manifest.version, result.error)
        return result

    def launch_installer(self, prepared: PreparedUpdate, pid: int, result_file: Path,
                         health_command: List[str], launch_command: List[str],
                         helper: Optional[Path] = None) -> None:
        """Запускает отдельный процесс замены: приложение должно закрыться сразу после вызова.

        Итог (installed / rolled_back / failed) процесс записывает в result_file; приложение внесёт его в
        update_audit при следующем запуске."""
        if self._guard:
            self._guard()
        work = Path(tempfile.mkdtemp(prefix="ecp-update-"))
        if helper is None:
            copy = work / "installer.py"
            shutil.copyfile(installer.__file__, copy)
            base = [sys.executable, str(copy)]
        else:  # собранный ecp-updater.exe: копия вне каталога приложения
            copy = work / helper.name
            shutil.copyfile(helper, copy)
            base = [str(copy)]
        args = base + ["--app", str(prepared.app_dir), "--staging", str(prepared.staging),
                       "--backup", str(prepared.backup), "--pid", str(pid), "--result", str(result_file),
                       "--from", prepared.from_version, "--to", prepared.manifest.version,
                       "--health", json.dumps(health_command), "--launch", json.dumps(launch_command)]
        flags = ({"creationflags": 0x00000008 | 0x00000200} if sys.platform.startswith("win")
                 else {"start_new_session": True})
        try:
            subprocess.Popen(args, close_fds=True, **flags)
        except OSError as e:
            raise self._fail(UpdateError(f"Ошибка: не удалось запустить установщик: {e.strerror or e}"),
                             prepared.manifest.version) from None
