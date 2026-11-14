"""Отпечаток устройства (Device Fingerprint): SHA-256 от «hostname|platform|mac|machine_id»."""
from __future__ import annotations

import hashlib
import platform
import re
import socket
import sys
import uuid
from dataclasses import dataclass
from typing import Optional

_DEVICE_ID = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class DeviceInfo:
    hostname: str
    platform: str
    mac: str
    machine_id: str


def read_machine_id() -> str:
    """Linux - /etc/machine-id, Windows - MachineGuid из реестра; иначе пустая строка."""
    try:
        if sys.platform.startswith("win"):
            import winreg  # type: ignore[import-not-found]
            access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, access) as key:
                return str(winreg.QueryValueEx(key, "MachineGuid")[0])
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, encoding="ascii") as f:
                    value = f.read().strip()
                if value:
                    return value
            except OSError:
                continue
    except Exception:  # noqa: BLE001 - отпечаток не должен ронять приложение
        pass
    return ""


def collect() -> DeviceInfo:
    return DeviceInfo(
        hostname=socket.gethostname(),
        platform=f"{platform.system()} {platform.release()}",
        mac=f"{uuid.getnode():012x}",
        machine_id=read_machine_id(),
    )


def fingerprint(info: DeviceInfo) -> str:
    raw = "|".join((info.hostname, info.platform, info.mac, info.machine_id))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def current_device_id() -> str:
    return fingerprint(collect())


def is_valid_device_id(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(_DEVICE_ID.fullmatch(value))
