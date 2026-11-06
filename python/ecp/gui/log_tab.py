"""Вкладка «Журнал»: просмотр файла журнала, цветовая разметка по правилам задания,
фильтры и анализ событий."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import audit, logview
from ..audit import FIELDS, AuditEvent
from ..context import AppContext
from .widgets import StatusLabel, make_details, title_label

MAX_ROWS = 5000  # показываются последние записи, чтобы окно не зависало на больших журналах


def _combo(items: List[Tuple[str, str]]) -> QComboBox:
    box = QComboBox()
    for text, value in items:
        box.addItem(text, value)
    return box


class LogTab(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.override_path: Optional[Path] = None
        self.events: List[AuditEvent] = []

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.addWidget(title_label("Журнал событий безопасности", "Цвет строки задаётся полями level, status и action"))

        chips = []
        for key in logview.CATEGORIES:
            bg, fg = logview.COLORS[key]
            chips.append(f"<span style='background:{bg};color:{fg};'>&nbsp;{logview.LABELS[key]}&nbsp;</span>")
        legend = QLabel("&nbsp;&nbsp;".join(chips))
        legend.setWordWrap(True)
        layout.addWidget(legend)

        filters = QHBoxLayout()
        self.level = _combo([("level: все", "")] + [(x, x) for x in audit.LEVELS])
        self.status = _combo([("status: все", ""), ("success", "success"), ("failure", "failure"),
                              ("cancelled", "cancelled")])
        self.action = _combo([("action: все", "")] + [(x, x) for x in audit.ACTIONS])
        self.category = _combo([("цвет: все", "")] + [(logview.LABELS[k].split(" (")[0], k) for k in logview.CATEGORIES])
        self.text = QLineEdit()
        self.text.setPlaceholderText("Поиск по тексту…")
        for widget in (self.level, self.status, self.action, self.category):
            widget.currentIndexChanged.connect(self.apply_filters)
            filters.addWidget(widget)
        self.text.textChanged.connect(self.apply_filters)
        filters.addWidget(self.text, 1)
        layout.addLayout(filters)

        buttons = QHBoxLayout()
        for caption, handler in (("Обновить", self.reload), ("Открыть другой файл…", self.open_other),
                                 ("Сбросить фильтры", self.reset_filters)):
            button = QPushButton(caption)
            button.clicked.connect(handler)
            buttons.addWidget(button)
        layout.addLayout(buttons)

        self.info = StatusLabel()
        layout.addWidget(self.info)

        self.table = QTableWidget(0, len(FIELDS))
        self.table.setHorizontalHeaderLabels(FIELDS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table, 1)

        self.summary = make_details()
        self.summary.setMaximumHeight(170)
        layout.addWidget(self.summary)

    # ------------------------------------------------------------ данные
    def current_path(self) -> Path:
        return self.override_path or self.ctx.audit.path

    def reload(self) -> None:
        path = self.current_path()
        if not path.exists():
            self.events = []
            self.info.info(f"Файл журнала ещё не создан: {path}")
            self.apply_filters()
            return
        try:
            events, bad = audit.read_events(path, limit=MAX_ROWS)
        except OSError as e:
            self.info.fail(f"Ошибка: не удалось прочитать журнал «{path.name}»: {e.strerror or e}")
            return
        self.events = events
        note = f"Файл: {path} · записей: {len(events)}"
        if len(events) == MAX_ROWS:
            note += f" (показаны последние {MAX_ROWS})"
        if bad:
            note += f" · нераспознанных строк: {bad}"
        self.info.info(note)
        self.ctx.audit.log("ecp.logview", f"Просмотр журнала «{path.name}»", action="access", obj=str(path))
        self.apply_filters()

    def open_other(self) -> None:
        start = str(self.current_path().parent)
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть файл журнала", start,
            "Журналы (*.log *.json *.csv *.cef *.txt);;Все файлы (*)")
        if not path:
            return
        self.override_path = Path(path)
        self.reload()

    def reset_filters(self) -> None:
        for widget in (self.level, self.status, self.action, self.category):
            widget.setCurrentIndex(0)
        self.text.clear()

    # ------------------------------------------------------------ отображение
    def apply_filters(self) -> None:
        shown = logview.filter_events(
            self.events,
            level=self.level.currentData() or "",
            status=self.status.currentData() or "",
            action=self.action.currentData() or "",
            category=self.category.currentData() or "",
            text=self.text.text(),
        )
        self._render(shown)
        self._summarize(len(shown))

    def _render(self, events: List[AuditEvent]) -> None:
        rows = list(reversed(events))  # новые записи сверху
        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(len(rows))
        for r, ev in enumerate(rows):
            colors = logview.COLORS.get(logview.classify(ev))
            for c, name in enumerate(FIELDS):
                item = QTableWidgetItem(getattr(ev, name))
                item.setToolTip(ev.description)
                if colors:
                    item.setBackground(QBrush(QColor(colors[0])))
                    item.setForeground(QBrush(QColor(colors[1])))
                self.table.setItem(r, c, item)
        self.table.resizeColumnsToContents()
        self.table.setUpdatesEnabled(True)

    def _summarize(self, shown: int) -> None:
        s = logview.analyze(self.events)
        lines = [f"Записей в журнале: {s.total} (после фильтров показано: {shown})"]
        if s.total:
            lines.append(f"Период: {s.first} — {s.last}")
            for key in logview.CATEGORIES:
                if key in s.by_category:
                    lines.append(f"  {logview.LABELS[key]}: {s.by_category[key]}")
            if "other" in s.by_category:
                lines.append(f"  Без цветовой категории: {s.by_category['other']}")
            top = ", ".join(f"{name} ({n})" for name, n in list(s.by_source.items())[:5])
            lines.append(f"Источники: {top}")
            lines.append("")
            if s.alerts:
                lines.append("Обнаружено:")
                lines += [f"  • {a}" for a in s.alerts]
            else:
                lines.append("Подозрительных ситуаций не обнаружено.")
        self.summary.setPlainText("\n".join(lines))
