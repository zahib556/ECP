"""Анализ журнала и правила цветового выделения (без зависимости от GUI)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .audit import AuditEvent

# Порядок = приоритет: запись попадает в первую подходящую категорию.
CATEGORIES = ["critical", "failure", "delete", "modify", "success", "info"]
LABELS: Dict[str, str] = {
    "critical": "Критическая ошибка (level = critical)",
    "failure": "Неуспешная операция (status = failure)",
    "delete": "Удаление данных (action = delete)",
    "modify": "Изменение данных (action = modify)",
    "success": "Успешная операция (status = success)",
    "info": "Информационное событие (level = info)",
}
# (фон, текст) - цвета заданы явно, чтобы читались и в светлой, и в тёмной теме
COLORS: Dict[str, tuple] = {
    "critical": ("#7f1d1d", "#ffffff"),   # тёмно-красный
    "failure": ("#f87171", "#000000"),    # красный
    "delete": ("#fdba74", "#000000"),     # оранжевый
    "modify": ("#fde047", "#000000"),     # жёлтый
    "success": ("#86efac", "#000000"),    # зелёный
    "info": ("#93c5fd", "#000000"),       # синий
}


def classify(ev: AuditEvent) -> str:
    """Категория цвета по критериям задания; пустая строка - без выделения."""
    if ev.level == "critical":
        return "critical"
    if ev.status == "failure":
        return "failure"
    if ev.action == "delete":
        return "delete"
    if ev.action == "modify":
        return "modify"
    if ev.status == "success":
        return "success"
    if ev.level == "info":
        return "info"
    return ""


def filter_events(
    events: Iterable[AuditEvent],
    level: str = "",
    status: str = "",
    action: str = "",
    category: str = "",
    text: str = "",
) -> List[AuditEvent]:
    needle = text.strip().lower()
    result = []
    for ev in events:
        if level and ev.level != level:
            continue
        if status and ev.status != status:
            continue
        if action and ev.action != action:
            continue
        if category and classify(ev) != category:
            continue
        if needle and needle not in " ".join(ev.values()).lower():
            continue
        result.append(ev)
    return result


@dataclass
class Summary:
    total: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    by_source: Dict[str, int] = field(default_factory=dict)
    first: str = ""
    last: str = ""
    alerts: List[str] = field(default_factory=list)


def analyze(events: List[AuditEvent]) -> Summary:
    """Сводка и простые правила выявления подозрительных ситуаций."""
    s = Summary(total=len(events))
    if not events:
        return s
    cats = Counter(classify(e) or "other" for e in events)
    s.by_category = {c: cats[c] for c in CATEGORIES if cats[c]}
    if cats["other"]:
        s.by_category["other"] = cats["other"]
    s.by_source = dict(Counter(e.source_name for e in events).most_common())
    s.first, s.last = events[0].event_datetime, events[-1].event_datetime

    critical = cats["critical"]
    if critical:
        s.alerts.append(f"Критические события: {critical}")
    failures = [e for e in events if e.status == "failure"]
    if failures:
        s.alerts.append(f"Неуспешных операций: {len(failures)} из {len(events)}")
    run = best = 0
    for e in events:  # серия неуспешных проверок подряд
        if e.source_name == "ecp.verify" and e.status == "failure":
            run += 1
            best = max(best, run)
        elif e.source_name == "ecp.verify":
            run = 0
    if best >= 3:
        s.alerts.append(f"Серия неуспешных проверок подписи подряд: {best}")
    outside = [e for e in events if e.source_name == "ecp.config" and e.level == "warning" and e.action == "modify"]
    if outside:
        s.alerts.append(f"Конфигурация изменена вне приложения: {len(outside)} раз(а)")
    selftest = [e for e in events if e.source_name == "ecp.selftest" and e.status == "failure"]
    if selftest:
        s.alerts.append(f"Сбои самотестирования или проверки целостности: {len(selftest)}")
    deleted = cats["delete"]
    if deleted:
        s.alerts.append(f"Операции удаления (очистка журнала): {deleted}")
    return s
