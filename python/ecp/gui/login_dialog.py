"""Экран входа и регистрации (отдельное окно). Вся логика - в AppContext, здесь только интерфейс."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..auth import passwords
from ..context import AppContext
from ..errors import EcpError
from .widgets import GRAY, GREEN, RED

_STRENGTH_COLORS = (RED, RED, "#b36b00", GREEN, GREEN)


def _password_edit() -> QLineEdit:
    edit = QLineEdit()
    edit.setEchoMode(QLineEdit.EchoMode.Password)
    return edit


def _error_label() -> QLabel:
    label = QLabel("")
    label.setWordWrap(True)
    label.setStyleSheet(f"color:{RED}")
    return label


def _message_for(error: Exception) -> str:
    """Ошибки пользователя показываем как есть, прочие - общим текстом (приложение не падает)."""
    if isinstance(error, EcpError):
        return str(error)
    return "Ошибка: непредвиденный сбой при обращении к службе входа"


class ResetDeviceDialog(QDialog):
    """Сброс привязки устройства по одноразовому коду, выданному при регистрации."""

    def __init__(self, ctx: AppContext, login: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Сброс привязки устройства")
        form = QFormLayout()
        self.login = QLineEdit(login)
        self.password = _password_edit()
        self.code = QLineEdit()
        self.code.setPlaceholderText("XXXX-XXXX-XXXX")
        form.addRow("Логин", self.login)
        form.addRow("Пароль", self.password)
        form.addRow("Код сброса", self.code)
        self.error = _error_label()
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Сбросить")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Отмена")
        buttons.accepted.connect(self.submit)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def submit(self) -> None:
        try:
            new_code = self.ctx.reset_device(self.login.text(), self.password.text(), self.code.text())
        except Exception as e:  # noqa: BLE001 - любая ошибка показывается сообщением
            self.error.setText(_message_for(e))
            self.password.clear()
            return
        QMessageBox.information(
            self, "Привязка сброшена",
            "Привязка к устройству снята, при следующем входе будет запомнено текущее устройство.\n\n"
            f"Новый одноразовый код сброса (показывается один раз, сохраните его):\n{new_code}")
        self.accept()


class LoginDialog(QDialog):
    """Вкладки «Вход» и «Регистрация». exec() == Accepted, только если вход выполнен."""

    def __init__(self, ctx: AppContext, message: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Вход в систему")
        self.setModal(True)
        self.setMinimumWidth(380)
        self.notice = QLabel(message)
        self.notice.setWordWrap(True)
        self.notice.setStyleSheet(f"color:{GRAY}")
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_login(), "Вход")
        self.tabs.addTab(self._build_register(), "Регистрация")
        layout = QVBoxLayout(self)
        layout.addWidget(self.notice)
        layout.addWidget(self.tabs)

    # ---------------------------------------------------------------- вкладка «Вход»
    def _build_login(self) -> QWidget:
        page = QWidget()
        form = QFormLayout()
        self.login_name = QLineEdit()
        self.login_password = _password_edit()
        form.addRow("Логин", self.login_name)
        form.addRow("Пароль", self.login_password)
        self.login_error = _error_label()
        self.login_button = QPushButton("Войти")
        self.login_button.setDefault(True)
        self.login_button.clicked.connect(self.do_login)
        self.login_password.returnPressed.connect(self.do_login)
        reset = QPushButton("Сбросить привязку устройства…")
        reset.setFlat(True)
        reset.clicked.connect(self.do_reset)
        row = QHBoxLayout()
        row.addWidget(reset)
        row.addStretch(1)
        row.addWidget(self.login_button)
        layout = QVBoxLayout(page)
        layout.addLayout(form)
        layout.addWidget(self.login_error)
        layout.addLayout(row)
        return page

    def do_login(self) -> None:
        try:
            self.ctx.login(self.login_name.text(), self.login_password.text())
        except Exception as e:  # noqa: BLE001 - неверный пароль, блокировка, чужое устройство, сбой БД
            self.login_error.setText(_message_for(e))
            self.login_password.clear()
            self.login_password.setFocus()
            return
        self.login_password.clear()
        self.accept()

    def do_reset(self) -> None:
        if ResetDeviceDialog(self.ctx, self.login_name.text(), self).exec() == QDialog.DialogCode.Accepted:
            self.login_error.setText("")

    # ---------------------------------------------------------------- вкладка «Регистрация»
    def _build_register(self) -> QWidget:
        page = QWidget()
        form = QFormLayout()
        self.reg_name = QLineEdit()
        self.reg_name.setPlaceholderText("3–32 символа: латиница, цифры, _ . -")
        self.reg_password = _password_edit()
        self.reg_confirm = _password_edit()
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(8)
        self.strength_label = QLabel("")
        form.addRow("Логин", self.reg_name)
        form.addRow("Пароль", self.reg_password)
        form.addRow("Сложность", self.strength_bar)
        form.addRow("", self.strength_label)
        form.addRow("Подтверждение", self.reg_confirm)
        self.reg_password.textChanged.connect(self.update_strength)
        self.reg_confirm.returnPressed.connect(self.do_register)
        self.reg_error = _error_label()
        button = QPushButton("Зарегистрироваться")
        button.clicked.connect(self.do_register)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(button)
        layout = QVBoxLayout(page)
        layout.addLayout(form)
        layout.addWidget(self.reg_error)
        layout.addLayout(row)
        self.update_strength("")
        return page

    def update_strength(self, text: str) -> None:
        score, label = passwords.strength(text)
        self.strength_bar.setValue(score)
        color = _STRENGTH_COLORS[score]
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk{{background:{color}}}")
        self.strength_label.setText(label if text else "")
        self.strength_label.setStyleSheet(f"color:{color}")

    def do_register(self) -> None:
        login = self.reg_name.text()
        try:
            code = self.ctx.register(login, self.reg_password.text(), self.reg_confirm.text())
        except Exception as e:  # noqa: BLE001
            self.reg_error.setText(_message_for(e))
            return
        self.reg_password.clear()
        self.reg_confirm.clear()
        self.reg_error.setText("")
        QMessageBox.information(
            self, "Регистрация выполнена",
            "Одноразовый код сброса привязки устройства (показывается один раз, сохраните его):\n\n"
            f"{code}\n\nТеперь войдите под своим логином.")
        self.login_name.setText(login.strip())
        self.login_error.setText("")
        self.tabs.setCurrentIndex(0)
        self.login_password.setFocus()
