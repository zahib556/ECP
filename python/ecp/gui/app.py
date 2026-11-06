"""Окно приложения по макету GUI.html: вкладки «Подписание», «Проверка», «Ключи»,
«Штамп времени» и служебная вкладка «О программе».

Запуск:  python -m ecp.gui
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, List, Optional

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import service
from ..context import AppContext
from ..errors import EcpError
from .log_tab import LogTab
from .login_dialog import LoginDialog
from .update_tab import UpdateTab
from .settings_tab import SettingsTab
from .widgets import GRAY, GREEN, RED, FilePicker, StatusLabel, make_details, mono_font, title_label

APP_TITLE = "Средство выработки и проверки ЭЦП"
STANDARD = "СТБ 34.101.45-2013"

# ---------------------------------------------------------------- вкладки
class SignTab(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label("Выработка ЭЦП", f"{STANDARD}, п. 7.1.3 · хэширование belt-hash · l = 128"))
        self.message = FilePicker("Сообщение X", "любой файл")
        self.key = FilePicker("Личный ключ d", "private.key · 32 байта")
        layout.addWidget(self.message)
        layout.addWidget(self.key)

        self.extended = QCheckBox("Расширенная ЭЦП CAdES-B-B (СТБ 34.101.80)")
        self.extended.toggled.connect(self._on_extended)
        self.owner = QLineEdit()
        self.owner.setPlaceholderText("Имя владельца ключа (для сертификата)")
        self.owner.setVisible(False)
        self.timestamp = QCheckBox("Штамп времени (СТБ 34.101.82, профиль B-T): локальная служба")
        self.timestamp.setEnabled(False)
        self.timestamp.setToolTip("Доступно вместе с расширенной ЭЦП")
        layout.addWidget(self.extended)
        layout.addWidget(self.owner)
        layout.addWidget(self.timestamp)

        self.button = QPushButton("Подписать")
        self.button.clicked.connect(self.run)
        self.status = StatusLabel()
        self.details = make_details()
        layout.addWidget(self.button)
        layout.addWidget(self.status)
        layout.addWidget(self.details, 1)

    def _on_extended(self, checked: bool) -> None:
        self.owner.setVisible(checked)
        self.timestamp.setEnabled(checked)
        if not checked:
            self.timestamp.setChecked(False)

    def run(self) -> None:
        try:
            message = self.message.require("файл сообщения")
            key = self.key.require("файл личного ключа")
            if self.extended.isChecked():
                self._run_cades(message, key)
                return
            default = str(Path(message).with_name("signature.bin"))
            out, _ = QFileDialog.getSaveFileName(
                self, "Сохранить подпись", default, "Подпись (*.bin);;Все файлы (*)"
            )
            if not out:
                service.audit_cancel("ecp.sign", f"Отмена: не выбран файл для сохранения подписи «{Path(message).name}»",
                                     obj=message)
                return
            result = service.sign_file(message, key, out)
        except EcpError as e:
            self.status.fail(str(e))
            self.details.clear()
            return
        self.status.ok(f"✓ Подпись создана: {Path(out).name}")
        self.details.setPlainText(
            f"Длина подписи: {len(result.signature)} байт (3l)\n\n"
            f"Хэш belt-hash:\n{service.format_hex(result.message_hash)}\n\n"
            f"Подпись S = S0 ‖ S1:\n{service.format_hex(result.signature)}"
        )

    def _run_cades(self, message: str, key: str) -> None:
        owner = self.owner.text().strip()
        if not owner:
            raise EcpError("Ошибка: укажите имя владельца ключа")
        stamped = self.timestamp.isChecked()
        default = str(Path(message).with_name("signature.p7s"))
        out, _ = QFileDialog.getSaveFileName(
            self, "Сохранить расширенную подпись", default, "CAdES (*.p7s);;Все файлы (*)"
        )
        if not out:
            service.audit_cancel("ecp.cades", f"Отмена: не выбран файл для сохранения расширенной подписи «{Path(message).name}»",
                                 obj=message)
            return
        result = service.sign_cades_file(message, key, out, owner,
                                         tsa_dir=self.ctx.config_path.parent if stamped else None)
        profile = "CAdES-B-T" if result.timestamped else "CAdES-B-B"
        self.status.ok(f"✓ Расширенная ЭЦП создана: {Path(out).name}")
        lines = [
            f"Формат: {profile} (отделённая подпись), СТБ 34.101.80 и СТБ 34.101.23",
            f"Владелец: {result.signer}",
            f"Время подписания: {result.signing_time:%d.%m.%Y %H:%M:%S} UTC",
        ]
        if result.timestamped and result.stamp_time:
            lines.append(f"Штамп времени (СТБ 34.101.82): {result.stamp_time:%d.%m.%Y %H:%M:%S} UTC, локальная служба")
        lines += [
            f"Серийный номер сертификата: {result.cert_serial:X}",
            f"Размер контейнера: {len(result.cms)} байт",
            "",
            f"Хэш belt-hash:\n{service.format_hex(result.message_hash)}",
        ]
        self.details.setPlainText("\n".join(lines))


class VerifyTab(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label(
            "Проверка ЭЦП", f"{STANDARD}, п. 7.1.4 · ограничения |S| = 3l, S₁ < q, R ≠ O"))
        self.message = FilePicker("Сообщение X", "любой файл")
        self.signature = FilePicker("Подпись S", "signature.bin (48 байт) или signature.p7s (CAdES)")
        self.key = FilePicker("Открытый ключ Q", "public.key · 64 байта; для CAdES можно не указывать")
        for picker in (self.message, self.signature, self.key):
            layout.addWidget(picker)
        self.corrupt = QCheckBox("Демо: повреждённая подпись (изменить один бит)")
        layout.addWidget(self.corrupt)
        self.button = QPushButton("Проверить подпись")
        self.button.clicked.connect(self.run)
        self.status = StatusLabel()
        self.details = make_details()
        layout.addWidget(self.button)
        layout.addWidget(self.status)
        layout.addWidget(self.details, 1)

    def run(self) -> None:
        try:
            message = self.message.require("файл сообщения")
            sig_path = self.signature.require("файл подписи")
            key_path = self.key.path()
            head = service.read_file(sig_path, "файл подписи")
            if service.is_cades_data(head):
                self._run_cades(message, sig_path, key_path)
                return
            result = service.verify_files(
                message, sig_path, self.key.require("файл открытого ключа"),
                corrupt=self.corrupt.isChecked(),
            )
        except EcpError as e:
            self.status.fail(str(e))
            self.details.clear()
            return
        if result.ok:
            self.status.ok("ДА — подпись верна")
        else:
            self.status.fail("НЕТ — подпись неверна")
        note = "\n\nПодпись намеренно повреждена (демонстрация)." if result.corrupted_demo else ""
        self.details.setPlainText(f"Хэш belt-hash:\n{service.format_hex(result.message_hash)}{note}")

    def _run_cades(self, message: str, sig_path: str, key_path: str) -> None:
        result = service.verify_cades_file(message, sig_path, key_path or None,
                                           tsa_dir=self.ctx.config_path.parent)
        if result.ok:
            self.status.ok("ДА — расширенная подпись верна")
        else:
            self.status.fail("НЕТ — расширенная подпись неверна")
        lines = [f"{'✓' if c.ok else '✗'} {c.name}" + (f" — {c.detail}" if c.detail else "")
                 for c in result.checks]
        head = []
        if result.signer:
            head.append(f"Владелец: {result.signer}")
        if result.signing_time:
            head.append(f"Время подписания (заявлено подписантом): {result.signing_time:%d.%m.%Y %H:%M:%S} UTC")
        stamp = result.timestamp
        if stamp is not None and stamp.gen_time:
            head.append(f"Штамп времени (СТБ 34.101.82): {stamp.gen_time:%d.%m.%Y %H:%M:%S} UTC"
                        + (f", служба «{stamp.tsa_name}»" if stamp.tsa_name else ""))
        if result.ok and not key_path:
            head.append("Ключ взят из сертификата в подписи: доверие к нему нужно подтвердить отдельно.")
        head += result.notes
        self.details.setPlainText("\n".join(head + [""] + lines))


class KeysTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label(
            "Генерация ключей", f"Пара (d, Q) на кривой bign-curve256v1 · {STANDARD}, п. 6.2.2"))
        self.folder = FilePicker("Каталог для ключей", "будут созданы private.key и public.key", mode="dir")
        layout.addWidget(self.folder)
        self.button = QPushButton("Сгенерировать пару ключей")
        self.button.clicked.connect(self.run)
        self.status = StatusLabel()
        self.details = make_details()
        warning = QLabel("Личный ключ сохраняется в открытом виде. Храните файл private.key "
                         "в защищённом месте. Защита паролем (СТБ 34.101.78) будет добавлена.")
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color:{GRAY};")
        layout.addWidget(self.button)
        layout.addWidget(self.status)
        layout.addWidget(self.details, 1)
        layout.addWidget(warning)

    def run(self) -> None:
        try:
            result = service.generate_keys(self.folder.require("каталог для ключей"))
        except EcpError as e:
            self.status.fail(str(e))
            self.details.clear()
            return
        self.status.ok(f"✓ Ключи сохранены в каталог {result.private_path.parent}")
        self.details.setPlainText(
            f"private.key — личный ключ d, {len(result.private_key)} байта\n"
            f"public.key  — открытый ключ Q, {len(result.public_key)} байта\n"
            f"Проверка соответствия Q = d·G: {'пройдена' if result.consistent else 'НЕ ПРОЙДЕНА'}\n\n"
            f"Открытый ключ Q = x ‖ y:\n{service.format_hex(result.public_key)}"
        )


class TimestampTab(QWidget):
    """Протокол постановки штампа времени (СТБ 34.101.82): запрос -> служба -> проверка ответа."""

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label(
            "Штамп времени",
            "СТБ 34.101.82 · запрос TimeStampReq, ответ TimeStampResp · хэширование belt-hash · локальная служба"))
        self.data = FilePicker("Данные", "любой файл, существование которого нужно удостоверить")
        self.request = FilePicker("Запрос", "файл .tsq")
        self.response = FilePicker("Ответ службы", "файл .tsr")
        layout.addWidget(self.data)
        make = QPushButton("1. Сформировать запрос (.tsq)")
        make.clicked.connect(self.make_request)
        layout.addWidget(make)
        layout.addWidget(self.request)
        issue = QPushButton("2. Выпустить штамп локальной службой (.tsr)")
        issue.clicked.connect(self.issue_stamp)
        layout.addWidget(issue)
        layout.addWidget(self.response)
        verify = QPushButton("3. Проверить штамп времени")
        verify.clicked.connect(self.verify_stamp)
        layout.addWidget(verify)
        self.status = StatusLabel()
        self.details = make_details()
        layout.addWidget(self.status)
        layout.addWidget(self.details, 1)

    def _fail(self, error: EcpError) -> None:
        self.status.fail(str(error))
        self.details.clear()

    def make_request(self) -> None:
        try:
            data = self.data.require("файл данных")
            out, _ = QFileDialog.getSaveFileName(
                self, "Сохранить запрос", str(Path(data).with_suffix(".tsq")), "Запрос (*.tsq);;Все файлы (*)")
            if not out:
                service.audit_cancel("ecp.tsp", "Отмена: не выбран файл для сохранения запроса штампа времени", obj=data)
                return
            result = service.create_tsq(data, out)
        except EcpError as e:
            self._fail(e)
            return
        self.request.edit.setText(out)
        self.status.ok(f"✓ Запрос сформирован: {Path(out).name}")
        self.details.setPlainText(
            f"Хэш данных (belt-hash):\n{service.format_hex(result.imprint)}\n\n"
            f"nonce: {result.nonce:016X}\ncertReq: TRUE (сертификат службы будет включён в штамп)\n"
            f"Размер запроса: {len(result.request)} байт")

    def issue_stamp(self) -> None:
        try:
            request = self.request.require("файл запроса")
            out, _ = QFileDialog.getSaveFileName(
                self, "Сохранить ответ службы", str(Path(request).with_suffix(".tsr")), "Ответ (*.tsr);;Все файлы (*)")
            if not out:
                service.audit_cancel("ecp.tsa", "Отмена: не выбран файл для сохранения ответа службы", obj=request)
                return
            result = service.issue_tsr(request, out, self.ctx.config_path.parent)
        except EcpError as e:
            self._fail(e)
            return
        self.response.edit.setText(out)
        if result.gen_time is not None:
            self.status.ok(f"✓ Штамп выпущен: {Path(out).name}")
            self.details.setPlainText(
                f"Статус: {result.status_text}\n"
                f"Серийный номер: {result.serial:X}\n"
                f"Время штампа: {result.gen_time:%d.%m.%Y %H:%M:%S} UTC\n"
                f"Размер ответа: {len(result.response)} байт")
        else:
            self.status.fail(f"НЕТ — запрос отклонён: {result.status_text}")
            self.details.setPlainText(f"Причина: {result.reason}")

    def verify_stamp(self) -> None:
        try:
            result = service.verify_tsr(
                self.data.require("файл данных"),
                self.response.require("файл ответа"),
                self.request.path() or None,
                self.ctx.config_path.parent,
            )
        except EcpError as e:
            self._fail(e)
            return
        if result.ok:
            self.status.ok("ДА — штамп времени верен")
        else:
            self.status.fail("НЕТ — штамп времени неверен")
        head = [f"Время штампа: {result.gen_time:%d.%m.%Y %H:%M:%S} UTC (точность ±{result.accuracy:g} с)",
                f"Серийный номер: {result.serial:X}", f"Политика: {result.policy}"]
        if result.tsa_name:
            head.append(f"Служба: {result.tsa_name}")
        lines = [f"{'✓' if c.ok else '✗'} {c.name}" + (f" — {c.detail}" if c.detail else "") for c in result.checks]
        self.details.setPlainText("\n".join(head + [""] + lines))


class AboutTab(QWidget):
    def __init__(self, on_selftest: Callable[[], None]) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title_label(APP_TITLE, f"{STANDARD} · СТБ 34.101.27, уровень 1"))
        self.build = QLabel()
        self.build.setWordWrap(True)
        self.build.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.build)
        self.status = StatusLabel()
        self.report = make_details()
        buttons = QHBoxLayout()
        selftest = QPushButton("Выполнить самотестирование")
        selftest.clicked.connect(on_selftest)
        integrity = QPushButton("Проверить целостность и подлинность ПО")
        integrity.clicked.connect(self.show_integrity)
        buttons.addWidget(selftest)
        buttons.addWidget(integrity)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.report, 1)
        self.refresh_build_info()

    def refresh_build_info(self) -> None:
        info = service.build_info()
        if info.status == "absent":
            date = "не определена (режим разработки, релиз не подписан)"
        elif info.authentic:
            date = f"{info.build_date} (подтверждена ЭЦП разработчика)"
        else:
            date = f"{info.build_date} (НЕ подтверждена: нарушены целостность или подпись)"
        lines = [f"<b>Версия ПО:</b> {info.version}", f"<b>Дата сборки:</b> {date}",
                 f"<b>Версия криптоядра:</b> {info.core_version}"]
        if info.fingerprint:
            grouped = " ".join(info.fingerprint[i:i + 8] for i in range(0, 64, 8)).upper()
            lines.append(f"<b>Отпечаток ключа разработчика (belt-hash):</b><br><tt>{grouped}</tt>")
        self.build.setText("<br>".join(lines))

    def show_results(self, results: List[service.TestResult]) -> None:
        lines = []
        for r in results:
            mark = "✓" if r.ok else "✗"
            lines.append(f"{mark} {r.name}" + (f"\n    {r.detail}" if r.detail else ""))
        self.report.setPlainText("\n".join(lines))
        if all(r.ok for r in results):
            self.status.ok("Самотестирование пройдено")
        else:
            self.status.fail("Самотестирование НЕ пройдено: средство заблокировано")
        self.refresh_build_info()

    def show_integrity(self) -> None:
        try:
            rep = service.check_integrity()
        except Exception as e:  # noqa: BLE001
            self.status.fail(f"Ошибка: не удалось выполнить проверку: {e}")
            return
        if rep.status == "absent":
            self.status.info("Эталон не создан (режим разработки): python tools/build_release.py sign")
            sums = service.program_checksums()
            self.report.setPlainText("Контрольные характеристики файлов (belt-hash):\n"
                                     + "\n".join(f"{name}\n    {digest}" for name, digest in sums.items()))
            return
        lines = []
        lines.append(f"{'✓' if rep.authentic else '✗'} Подлинность: ЭЦП разработчика (bign-with-hbelt)")
        lines += [f"    {p}" for p in rep.auth_problems]
        lines += [f"✗ {p}" for p in rep.problems]
        lines.append("")
        lines.append("Целостность файлов (belt-hash):")
        for f in rep.files:
            lines.append(f"  {'✓' if f.ok else '✗'} {f.name}" + (f" — {f.detail}" if f.detail else ""))
        self.report.setPlainText("\n".join(lines))
        if rep.status == "ok":
            self.status.ok("Целостность и подлинность ПО подтверждены")
        else:
            self.status.fail("Целостность или подлинность ПО НЕ подтверждены")
        self.refresh_build_info()


class MainWindow(QMainWindow):
    CRYPTO_TABS = 4  # рабочие вкладки с криптооперациями; при сбое самотестирования блокируются
    LOG_INDEX = 4
    ABOUT_INDEX = 7

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(f"{APP_TITLE} — {STANDARD}")
        self.resize(900, 760)
        self.tabs = QTabWidget()
        self.about = AboutTab(self.run_selftest)
        self.log_tab = LogTab(ctx)
        self.tabs.addTab(SignTab(ctx), "Подписание")
        self.tabs.addTab(VerifyTab(ctx), "Проверка")
        self.tabs.addTab(KeysTab(), "Ключи")
        self.tabs.addTab(TimestampTab(ctx), "Штамп времени")
        self.tabs.addTab(self.log_tab, "Журнал")
        self.tabs.addTab(SettingsTab(ctx), "Настройки")
        self.tabs.addTab(UpdateTab(ctx, QApplication.quit), "Обновление ПО")
        self.tabs.addTab(self.about, "О программе")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.setCentralWidget(self.tabs)
        self._build_session_bar()
        self._login_open = False
        # истёк токен -> автоматический переход на экран входа (вызов откладывается до цикла событий)
        ctx.on_session_lost = lambda message: QTimer.singleShot(0, lambda: self.require_login(message))
        self._session_timer = QTimer(self)
        self._session_timer.timeout.connect(self._poll_session)
        self._session_timer.start(15_000)
        self.run_selftest(startup=True)
        self._warn_startup()

    # ---------------------------------------------------------------- вход и выход
    def _build_session_bar(self) -> None:
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 0, 6, 0)
        self.user_label = QLabel("")
        self.logout_button = QPushButton("Выйти")
        self.logout_button.clicked.connect(self.logout)
        row.addWidget(self.user_label)
        row.addWidget(self.logout_button)
        self.tabs.setCornerWidget(bar, Qt.Corner.TopRightCorner)
        bar.setVisible(self.ctx.auth_required)

    def _refresh_session_bar(self) -> None:
        self.user_label.setText(f"Пользователь: {self.ctx.session.login}" if self.ctx.logged_in else "")

    def require_login(self, message: str = "") -> bool:
        """Показывает экран входа. При отказе от входа приложение закрывается."""
        if not self.ctx.auth_required or self.ctx.logged_in or self._login_open:
            return True
        self._login_open = True
        self.tabs.setEnabled(False)
        try:
            accepted = LoginDialog(self.ctx, message, self).exec() == LoginDialog.DialogCode.Accepted
        finally:
            self._login_open = False
        self.tabs.setEnabled(True)
        self._refresh_session_bar()
        if not accepted:
            self.close()
        return accepted

    def logout(self) -> None:
        self.ctx.logout()
        self._refresh_session_bar()
        self.require_login("Вы вышли из системы.")

    def _poll_session(self) -> None:
        if self.ctx.logged_in:
            try:
                self.ctx.check_session()
            except EcpError:
                pass  # переход на экран входа запускается через on_session_lost

    def _on_tab_changed(self, index: int) -> None:
        if index == self.LOG_INDEX:
            self.log_tab.reload()

    def _warn_startup(self) -> None:
        notes = []
        if self.ctx.problems:
            notes.append("Конфигурация:\n- " + "\n- ".join(self.ctx.problems))
        if self.ctx.audit.last_error:
            notes.append("Журнал: " + self.ctx.audit.last_error)
        if notes:
            QMessageBox.warning(self, APP_TITLE, "\n\n".join(notes))

    def run_selftest(self, startup: bool = False) -> None:
        results = service.self_test()
        ok = all(r.ok for r in results)
        self.about.show_results(results)
        for index in range(self.CRYPTO_TABS):
            self.tabs.setTabEnabled(index, ok)
        if not ok:
            self.tabs.setCurrentIndex(self.ABOUT_INDEX)
            if startup:
                QMessageBox.critical(
                    self, APP_TITLE,
                    "Самотестирование не пройдено. Криптографические операции заблокированы.\n"
                    "Подробности — на вкладке «О программе».",
                )
        elif startup:
            self.tabs.setCurrentIndex(0)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    try:
        ctx = AppContext.start(require_auth=True)
    except EcpError as e:  # база пользователей недоступна: понятное сообщение вместо падения
        QMessageBox.critical(None, APP_TITLE, str(e))
        return 1
    app.aboutToQuit.connect(ctx.shutdown)
    window = MainWindow(ctx)
    if not window.require_login():  # до входа главное окно не показывается
        ctx.shutdown()
        return 0
    window.show()
    return app.exec()
