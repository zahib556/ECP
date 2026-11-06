"""Общие виджеты интерфейса."""
from __future__ import annotations

from typing import Optional

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..errors import EcpError

GREEN = "#0a7d33"
RED = "#b3261e"
GRAY = "#666666"


def mono_font() -> QFont:
    font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    font.setPointSize(10)
    return font


class FilePicker(QWidget):
    """Подпись + поле пути + кнопка «Выбрать…»."""

    def __init__(self, title: str, hint: str, mode: str = "open", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._mode = mode
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        caption = QLabel(f"<b>{title}</b>  <span style='color:{GRAY}'>{hint}</span>")
        row = QHBoxLayout()
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Каталог не выбран" if mode == "dir" else "Файл не выбран")
        button = QPushButton("Выбрать…")
        button.clicked.connect(self._choose)
        row.addWidget(self.edit, 1)
        row.addWidget(button)
        layout.addWidget(caption)
        layout.addLayout(row)

    def _choose(self) -> None:
        start = self.edit.text().strip()
        if self._mode == "dir":
            path = QFileDialog.getExistingDirectory(self, "Выберите каталог", start)
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", start, "Все файлы (*)")
        if path:
            self.edit.setText(path)

    def path(self) -> str:
        return self.edit.text().strip()

    def require(self, what: str) -> str:
        value = self.path()
        if not value:
            raise EcpError(f"Ошибка: не выбран {what}")
        return value


class StatusLabel(QLabel):
    def __init__(self) -> None:
        super().__init__("")
        self.setWordWrap(True)

    def ok(self, text: str) -> None:
        self.setStyleSheet(f"color:{GREEN}; font-weight:600; font-size:14px;")
        self.setText(text)

    def fail(self, text: str) -> None:
        self.setStyleSheet(f"color:{RED}; font-weight:600; font-size:14px;")
        self.setText(text)

    def info(self, text: str) -> None:
        self.setStyleSheet(f"color:{GRAY};")
        self.setText(text)


def make_details() -> QPlainTextEdit:
    box = QPlainTextEdit()
    box.setReadOnly(True)
    box.setFont(mono_font())
    box.setMinimumHeight(150)
    return box


def title_label(text: str, subtitle: str) -> QLabel:
    label = QLabel(f"<span style='font-size:16px;font-weight:700'>{text}</span><br>"
                   f"<span style='color:{GRAY}'>{subtitle}</span>")
    label.setWordWrap(True)
    return label
