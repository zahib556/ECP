"""Демонстрационный журнал со всеми категориями цвета - для проверки вкладки «Журнал» и отчёта.

    python tools/make_demo_log.py                 # demo_security.log в формате JSON
    python tools/make_demo_log.py --format CEF --out demo.cef

Открыть: вкладка «Журнал» -> «Открыть другой файл…».
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from ecp.audit import AuditLog  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Создать демонстрационный журнал")
    parser.add_argument("--format", default="JSON", choices=["JSON", "CSV", "CEF"])
    parser.add_argument("--out", default="demo_security.log")
    args = parser.parse_args()
    out = Path(args.out)
    if out.exists():
        out.unlink()

    now = [datetime.now().replace(microsecond=0) - timedelta(minutes=30)]
    log = AuditLog(out, args.format, user="demo", host_ip="192.168.1.15", clock=lambda: now[0])

    def step(seconds: float = 7) -> None:
        now[0] += timedelta(seconds=seconds)

    log.info("ecp.app", "Запуск приложения, версия 0.2.0"); step()
    log.log("ecp.config", "Создан файл конфигурации со значениями по умолчанию", action="create", obj="config.ini"); step()
    log.log("ecp.selftest", "Самотестирование пройдено (10 проверок)", action="execute"); step()
    log.log("ecp.keys", "Сгенерирована пара ключей, сохранена в каталог «keys»", action="create", obj="keys"); step()
    log.log("ecp.files", "Чтение сообщение «report.pdf»", action="access", obj="report.pdf"); step(1)
    log.log("ecp.sign", "Выработана ЭЦП файла «report.pdf»: signature.bin (48 байт)", action="create", obj="signature.bin"); step()
    log.log("ecp.verify", "Проверка ЭЦП файла «report.pdf»: ДА — подпись верна", action="access", obj="report.pdf"); step()
    log.log("ecp.sign", "Отмена: не выбран файл для сохранения подписи «report.pdf»", status="cancelled", action="create", obj="report.pdf"); step()
    log.log("ecp.files", "Чтение сообщение «missing.txt»: файл не найден", level="error", status="failure", action="access", obj="missing.txt"); step()
    log.log("ecp.verify", "Проверка ЭЦП файла «report.pdf»: НЕТ — подпись неверна", level="warning", status="failure", action="access", obj="report.pdf"); step()
    log.log("ecp.config", "Изменена конфигурация: logging.log_format: «JSON» → «CSV»", action="modify", obj="config.ini"); step()
    log.log("ecp.config", "Файл конфигурации изменён вне приложения (хэш не совпал с прошлым запуском)", level="warning", action="modify", obj="config.ini"); step()
    log.log("ecp.audit", "Журнал перемещён в архив «security.20261014-100000.log»: достигнут предел размера 1MB", action="move", obj="security.20261014-100000.log"); step()
    log.log("ecp.audit", "Удалён архив журнала «security.20260901-090000.log»: истёк срок хранения", action="delete", obj="security.20260901-090000.log"); step()
    log.log("ecp.selftest", "Не пройдено: Целостность файлов программы (belt-hash) — service.py: хэш не совпал", level="critical", status="failure", action="execute"); step()
    log.info("ecp.app", "Завершение работы приложения")
    print(f"Создан {out} ({args.format}), записей: 16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
