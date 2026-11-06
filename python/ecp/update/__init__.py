"""Безопасное обновление ПО (вариант Б - монолитное приложение, только offline).

Порядок: manifest.json + manifest.sig -> проверка подписи Ed25519 -> совместимость (min_supported, ОС, архитектура)
-> SHA-256 пакета -> распаковка в staging -> проверка SBOM -> атомарная замена (app -> backup, staging -> app)
-> проверка запуска новой версии -> при сбое откат из backup. Каждый исход пишется в update_audit и журнал.
"""
from .updater import PreparedUpdate, UpdateError, UpdatePlan, Updater
from .source import FileSource, IUpdateSource

__all__ = ["FileSource", "IUpdateSource", "PreparedUpdate", "UpdateError", "UpdatePlan", "Updater"]
