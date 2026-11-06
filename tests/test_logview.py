"""Цветовые категории и анализ журнала."""
from ecp.audit import AuditEvent
from ecp import logview


def ev(**kw):
    base = dict(event_datetime="2026-10-14 10:00:00.000", source_name="ecp.x", level="info",
                status="", action="access", description="d")
    base.update(kw)
    return AuditEvent(**base)


def test_classify_each_category():
    assert logview.classify(ev(level="critical", status="failure")) == "critical"
    assert logview.classify(ev(status="failure")) == "failure"
    assert logview.classify(ev(action="delete", status="success")) == "delete"
    assert logview.classify(ev(action="modify", status="success")) == "modify"
    assert logview.classify(ev(status="success")) == "success"
    assert logview.classify(ev(status="")) == "info"
    assert logview.classify(ev(level="warning", status="cancelled")) == ""


def test_priority_order():
    # неудавшееся изменение - красное, а не жёлтое
    assert logview.classify(ev(action="modify", status="failure")) == "failure"
    # критическое важнее неуспешного
    assert logview.classify(ev(level="critical", status="failure", action="delete")) == "critical"
    assert logview.CATEGORIES[0] == "critical" and logview.CATEGORIES[-1] == "info"


def test_every_category_has_color_and_label():
    for c in logview.CATEGORIES:
        bg, fg = logview.COLORS[c]
        assert bg.startswith("#") and fg.startswith("#")
        assert logview.LABELS[c]


def test_filter_events():
    events = [ev(status="success", description="Подпись"), ev(status="failure", level="error",
              description="Ошибка чтения"), ev(action="delete", status="success", description="Очистка")]
    assert len(logview.filter_events(events, status="failure")) == 1
    assert len(logview.filter_events(events, level="error")) == 1
    assert len(logview.filter_events(events, action="delete")) == 1
    assert len(logview.filter_events(events, category="success")) == 1
    assert len(logview.filter_events(events, text="ПОДПИСЬ")) == 1
    assert len(logview.filter_events(events)) == 3


def test_analyze_empty():
    s = logview.analyze([])
    assert s.total == 0 and s.alerts == []


def test_analyze_counts_and_alerts():
    events = [ev(status="success"), ev(level="critical", status="failure", source_name="ecp.selftest")]
    events += [ev(status="failure", source_name="ecp.verify") for _ in range(3)]
    events += [ev(source_name="ecp.config", level="warning", action="modify", status="success"),
               ev(action="delete", status="success")]
    s = logview.analyze(events)
    assert s.total == 7
    assert s.by_category["critical"] == 1 and s.by_category["failure"] == 3
    joined = "\n".join(s.alerts)
    assert "Критические" in joined and "Серия неуспешных проверок" in joined
    assert "вне приложения" in joined and "удаления" in joined and "самотестирования" in joined


def test_verify_failure_series_resets():
    events = [ev(status="failure", source_name="ecp.verify"), ev(status="failure", source_name="ecp.verify"),
              ev(status="success", source_name="ecp.verify"), ev(status="failure", source_name="ecp.verify")]
    assert not any("Серия" in a for a in logview.analyze(events).alerts)
