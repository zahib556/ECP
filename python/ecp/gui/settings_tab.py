"""Вкладка «Настройки»: просмотр и изменение файла конфигурации."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import config as cfgmod
from .. import service
from ..config import Config
from ..context import AppContext
from ..errors import EcpError
from .widgets import GRAY, StatusLabel, title_label


def _algorithm_box(name: str) -> QComboBox:
    box = QComboBox()
    box.addItems(list(cfgmod.SUPPORTED_ALGORITHMS[name]))
    return box


class SettingsTab(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label("Настройки", "Файл конфигурации: группы «Логирование» и «Криптографические алгоритмы»"))
        self.path_label = QLabel()
        self.path_label.setStyleSheet(f"color:{GRAY};")
        self.path_label.setWordWrap(True)
        layout.addWidget(self.path_label)

        form = QFormLayout()
        row = QHBoxLayout()
        self.log_path = QLineEdit()
        choose = QPushButton("Выбрать…")
        choose.clicked.connect(self._choose_log_path)
        row.addWidget(self.log_path, 1)
        row.addWidget(choose)
        holder = QWidget()
        holder.setLayout(row)
        row.setContentsMargins(0, 0, 0, 0)
        self.log_format = QComboBox()
        self.log_format.addItems(list(cfgmod.LOG_FORMATS))
        self.cleanup = QLineEdit()
        self.cleanup.setPlaceholderText("например 30d или 12h")
        self.max_size = QLineEdit()
        self.max_size.setPlaceholderText("например 100MB")
        self.encryption = _algorithm_box("encryption")
        self.hashing = _algorithm_box("hashing")
        self.signature = _algorithm_box("digital_signature")
        form.addRow("Путь к файлу журнала (log_path)", holder)
        form.addRow("Формат журнала (log_format)", self.log_format)
        form.addRow("Срок хранения (cleanup_period)", self.cleanup)
        form.addRow("Максимальный размер файла (max_file_size)", self.max_size)
        form.addRow("Шифрование (encryption)", self.encryption)
        form.addRow("Хэширование (hashing)", self.hashing)
        form.addRow("Электронная подпись (digital_signature)", self.signature)
        layout.addLayout(form)

        note = QLabel("Допускаются только алгоритмы белорусских стандартов, реализованные в программе.")
        note.setStyleSheet(f"color:{GRAY};")
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QHBoxLayout()
        for caption, handler in (("Сохранить", self.save), ("Сбросить к умолчаниям", self.reset),
                                 ("Экспорт…", self.export), ("Импорт…", self.import_)):
            button = QPushButton(caption)
            button.clicked.connect(handler)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.status = StatusLabel()
        layout.addWidget(self.status)
        layout.addStretch(1)
        self.refresh()

    # ------------------------------------------------------------ данные
    def refresh(self) -> None:
        cfg = self.ctx.config
        self.path_label.setText(f"Файл: {self.ctx.config_path}")
        self.log_path.setText(cfg.logging.log_path)
        self.log_format.setCurrentText(cfg.logging.log_format)
        self.cleanup.setText(cfg.logging.cleanup_period)
        self.max_size.setText(cfg.logging.max_file_size)
        self.encryption.setCurrentText(cfg.crypto.encryption)
        self.hashing.setCurrentText(cfg.crypto.hashing)
        self.signature.setCurrentText(cfg.crypto.digital_signature)

    def collect(self) -> Config:
        cfg = Config()
        cfg.logging.log_path = self.log_path.text().strip()
        cfg.logging.log_format = self.log_format.currentText()
        cfg.logging.cleanup_period = self.cleanup.text().strip()
        cfg.logging.max_file_size = self.max_size.text().strip()
        cfg.crypto.encryption = self.encryption.currentText()
        cfg.crypto.hashing = self.hashing.currentText()
        cfg.crypto.digital_signature = self.signature.currentText()
        return cfg

    # ------------------------------------------------------------ действия
    def _choose_log_path(self) -> None:
        start = self.log_path.text().strip() or str(Path(self.ctx.config.logging.log_path))
        path, _ = QFileDialog.getSaveFileName(
            self, "Файл журнала", start, "Журнал (*.log);;Все файлы (*)", "",
            QFileDialog.Option.DontConfirmOverwrite)
        if path:
            self.log_path.setText(path)

    def _run(self, action, ok_text: str, same_text: str = "Изменений нет") -> None:
        try:
            changed = action()
        except EcpError as e:
            self.status.fail(str(e))
            return
        self.refresh()
        self.status.ok(ok_text) if changed else self.status.info(same_text)

    def save(self) -> None:
        self._run(lambda: self.ctx.save_config(self.collect()), "✓ Настройки сохранены")

    def reset(self) -> None:
        answer = QMessageBox.question(self, "Сброс настроек", "Вернуть все настройки к значениям по умолчанию?")
        if answer != QMessageBox.StandardButton.Yes:
            service.audit_cancel("ecp.config", "Отмена сброса конфигурации", action="modify",
                                 obj=self.ctx.config_path)
            return
        self._run(self.ctx.reset_config, "✓ Настройки сброшены к значениям по умолчанию")

    def export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт конфигурации", "config-backup.ini",
                                              "Конфигурация (*.ini);;Все файлы (*)")
        if not path:
            service.audit_cancel("ecp.config", "Отмена экспорта конфигурации", action="copy")
            return
        try:
            self.ctx.export_config(Path(path))
        except EcpError as e:
            self.status.fail(str(e))
            return
        self.status.ok(f"✓ Конфигурация экспортирована: {Path(path).name}")

    def import_(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Импорт конфигурации", "",
                                              "Конфигурация (*.ini);;Все файлы (*)")
        if not path:
            service.audit_cancel("ecp.config", "Отмена импорта конфигурации", action="copy")
            return
        self._run(lambda: self.ctx.import_config(Path(path)), f"✓ Конфигурация импортирована: {Path(path).name}",
                  "Импортированные значения совпадают с текущими")
