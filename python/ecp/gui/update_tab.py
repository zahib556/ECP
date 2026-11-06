"""Вкладка «Обновление ПО» (вариант Б, offline): выбор manifest.json, проверка подписи, SHA-256 и SBOM,
затем установка отдельным процессом с откатом при сбое."""
from __future__ import annotations

import os
from typing import Callable, Optional

from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..context import AppContext
from ..errors import EcpError
from ..update import FileSource, PreparedUpdate, runtime
from ..version import VERSION
from .widgets import FilePicker, StatusLabel, make_details, title_label

STATUS_TEXT = {
    "verified": "подпись проверена", "downloaded": "получен", "installed": "установлено",
    "failed": "отказ", "rolled_back": "откат", "sbom_mismatch": "SBOM не совпал",
}


class UpdateTab(QWidget):
    def __init__(self, ctx: AppContext, quit_app: Callable[[], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self._quit = quit_app
        self._prepared: Optional[PreparedUpdate] = None
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label(
            "Обновление ПО",
            "Подпись манифеста Ed25519 · SHA-256 пакета · SBOM CycloneDX · атомарная замена · откат при сбое"))
        layout.addWidget(QLabel(f"Установленная версия: <b>{VERSION}</b>"))
        self.manifest = FilePicker("Манифест обновления", "manifest.json; рядом должны лежать manifest.sig и пакет .zip")
        layout.addWidget(self.manifest)
        row = QHBoxLayout()
        self.check_button = QPushButton("1. Проверить обновление")
        self.check_button.clicked.connect(self.check)
        self.install_button = QPushButton("2. Установить и перезапустить")
        self.install_button.setEnabled(False)
        self.install_button.clicked.connect(self.install)
        row.addWidget(self.check_button)
        row.addWidget(self.install_button)
        layout.addLayout(row)
        self.status = StatusLabel()
        self.details = make_details()
        layout.addWidget(self.status)
        layout.addWidget(self.details, 1)
        layout.addWidget(QLabel("<b>Журнал обновлений</b>"))
        self.history = QTableWidget(0, 4)
        self.history.setHorizontalHeaderLabels(["Время (UTC)", "Результат", "С версии", "На версию"])
        self.history.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history.horizontalHeader().setStretchLastSection(True)
        self.history.setMaximumHeight(170)
        layout.addWidget(self.history)
        self.refresh_history()

    # ---------------------------------------------------------------- журнал обновлений
    def refresh_history(self) -> None:
        try:
            rows = self.ctx.update_db.list_update_audit(20)
        except Exception:  # noqa: BLE001 - база недоступна: таблица остаётся пустой
            rows = []
        self.history.setRowCount(len(rows))
        for i, (ts, status, frm, to, _user, _device, _ip) in enumerate(rows):
            for j, text in enumerate((ts, STATUS_TEXT.get(status, status), frm or "", to or "")):
                self.history.setItem(i, j, QTableWidgetItem(text))

    # ---------------------------------------------------------------- шаги
    def _drop_prepared(self, updater=None) -> None:
        if self._prepared is not None:
            (updater or self.ctx.make_updater()).discard(self._prepared)
            self._prepared = None
        self.install_button.setEnabled(False)

    def check(self) -> None:
        """Подпись -> совместимость -> SHA-256 -> распаковка в staging -> SBOM. Файлы приложения не меняются."""
        self.details.clear()
        try:
            self._drop_prepared()
            path = self.manifest.require("файл manifest.json")
            updater = self.ctx.make_updater()
            plan = updater.check(FileSource(path))
            prepared = updater.prepare(plan)
        except EcpError as e:
            self.status.fail(str(e))
            self.refresh_history()
            return
        self._prepared = prepared
        m = prepared.manifest
        self.details.setPlainText("\n".join([
            f"Версия обновления: {m.version}" + ("   (КРИТИЧЕСКОЕ)" if m.critical else ""),
            f"Минимальная поддерживаемая версия: {m.min_supported}",
            f"Дата выпуска: {m.release_date}",
            f"Платформа: {m.os}/{m.arch}",
            f"Размер пакета: {m.package_size} байт",
            f"SHA-256 пакета: {m.package_sha256}",
            "",
            "Подпись манифеста Ed25519: подтверждена",
            "SHA-256 пакета: совпадает",
            "SBOM (хэш и состав зависимостей): проверен",
        ]))
        self.status.ok(f"Обновление {m.version} проверено и готово к установке")
        self.install_button.setEnabled(True)
        self.refresh_history()

    def install(self) -> None:
        if self._prepared is None:
            return
        prepared = self._prepared
        answer = QMessageBox.question(
            self, "Установка обновления",
            f"Установить версию {prepared.manifest.version}?\n\nПриложение закроется, файлы будут заменены, затем оно "
            "запустится снова. Если новая версия не пройдёт проверку запуска, будет восстановлена текущая.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            updater = self.ctx.make_updater()
            folder = prepared.app_dir
            updater.launch_installer(prepared, os.getpid(), self.ctx.update_result_path,
                                     runtime.health_command(folder), runtime.launch_command(),
                                     helper=runtime.helper_exe(folder))
        except EcpError as e:
            self.status.fail(str(e))
            return
        self._prepared = None
        self.status.info("Установка запущена, приложение закрывается…")
        self._quit()
