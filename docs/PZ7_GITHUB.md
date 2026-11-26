# ПЗ-7: SAST/SCA готовыми инструментами — что сделать на GitHub и в терминале

По согласованию вместо собственного анализатора проект проверяется open-source инструментами
(Bandit, Semgrep, pip-audit, cargo-audit). Номера Issues условные: **#S1…#S6**, подставьте реальные.

## 1. Issues (часть 2.4) — создайте и добавьте на доску (+ Add item)

| № | Title | Описание / критерии готовности | Колонка к сдаче |
|---|---|---|---|
| #S1 | Выбор и обоснование инструментов SAST/SCA | Таблица в `SECURITY_REPORT.md`, раздел 1 | Done |
| #S2 | SAST: Bandit и Semgrep, конфигурация | `bandit.yaml`, `.semgrepignore`, `requirements-security.txt` | Done |
| #S3 | SCA: pip-audit и cargo-audit | `tools/run_security.ps1`, `Cargo.lock` в репозитории | Review |
| #S4 | CI: workflow `security` в GitHub Actions | `.github/workflows/security.yml`, зелёный/красный прогон, артефакты отчётов | In Progress |
| #S5 | Разбор находок: исправить или обосновать | таблицы 3.1 и 3.2 в записке заполнены | Backlog |
| #S6 | Записка и демонстрация | `SECURITY_REPORT.md` без строк «ЗАПОЛНИТЬ», вывод инструментов | Backlog |

Для скриншота доски переведите карточки по колонкам так, как в таблице (≥ 5 Issues в разных колонках).

## 2. Ветка и установка (части 2.3, 2.5)

    cd путь\к\проекту
    git pull
    git status                                  # дерево чистое
    git checkout -b security/13-sast-sca        # 13 -> номер вашего Issue
    # распакуйте ecp_step13.zip поверх проекта; .gitignore будет заменён (новые строки дописаны в конец)
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements-security.txt
    pip freeze | findstr /i "bandit pip-audit"  # версии впишите в requirements-security.txt и SECURITY_REPORT.md

Если в проекте ещё нет `Cargo.lock`: `cargo generate-lockfile`, затем закоммитьте его (для cargo-audit он обязателен;
в `.gitignore` он не исключён).

## 3. Прогон и скриншоты (демонстрация, часть 2.5)

    .\tools\run_security.ps1

Скрипт кладёт отчёты в `security-reports\` (каталог в `.gitignore`, в историю не попадёт):
`bandit.txt` / `bandit.json` и `pip-audit.txt` / `pip-audit.json`. Для сдачи нужен скриншот или текст вывода и
фрагмент JSON с находками.

Semgrep и cargo-audit запускаются в GitHub Actions:

1. Отправьте ветку (раздел 5) — workflow запустится на Pull Request, либо Actions -> security -> Run workflow.
2. После прогона скачайте артефакты `sast-reports` и `sca-reports` (внизу страницы прогона).
3. Если шаг «Порог…» упал, это не ошибка настройки: найдены High у Bandit или уязвимые зависимости. Отчёт всё равно
   выгружен, шаги сканирования идут с `continue-on-error`.

Если Semgrep не отработал (нет доступа к реестру правил, сбой установки) — приложите лог шага и не заполняйте
его строки выдуманными числами.

## 4. Что вероятно найдётся (прогноз по коду, не результат — проверьте запуском)

| Инструмент | Что ожидается | Где | Что делать |
|---|---|---|---|
| Bandit | `B404` (import subprocess), `B603` (вызов без shell), оба Low | `update/installer.py`, `update/updater.py`, `tools/build_update.py` | аргументы формирует программа, пользовательской строки нет -> `# nosec B603 - причина` |
| Bandit | `B101` (assert), Low | `auth/service.py` (2 места), `cades.py` | заменить на явную проверку с исключением либо принять риск: assert стоит как подсказка типизации |
| Bandit | `B110` (try/except/pass), Low | `auth/device.py` | осознанно: отпечаток устройства не должен ронять приложение; `# nosec B110` с причиной или логирование |
| Bandit | `B607`/`B602` | не ожидаются: `shell=True` и вызовов по короткому имени в коде нет | — |
| Bandit | `B608` (SQL) | не ожидается: запросы параметризованные | если сработает — разобрать |
| cargo-audit | возможное предупреждение по `pyo3 0.23` | `Cargo.toml` | по памяти: RUSTSEC-2025-0020, исправлено в 0.24.1; **подтвердит только запуск**. Если подтвердится — поднять версию `pyo3`, `maturin develop`, прогнать `pytest` |
| pip-audit | зависит от версий `PySide6` / `cryptography` на момент запуска | окружение | обновить пакет до исправленной версии, повторить прогон |

Это гипотезы, а не результаты: в отчёт попадают только числа из реального вывода.

## 5. Коммиты: по одному на Issue, каждый «зелёный»

    git add bandit.yaml .semgrepignore requirements-security.txt .gitignore
    git commit -m "chore: add Bandit and Semgrep config Closes #S2"

    git add tools/run_security.ps1 Cargo.lock
    git commit -m "chore: add local SCA script, lock Rust dependencies Closes #S3"

    git add .github/workflows/security.yml
    git commit -m "ci: add security workflow (SAST + SCA) Closes #S4"

После разбора находок (Issue #S5) — отдельные коммиты исправлений и подавлений:

    git add python/
    git commit -m "fix: address SAST/SCA findings Closes #S5"
    git add SECURITY_REPORT.md docs/
    git commit -m "docs: security report Closes #S1 Closes #S6"

Если правились файлы в `python/ecp/`, после этого заново выполните `python tools/build_release.py sign`
(контрольные хэши файлов программы изменились) и `pytest`.

## 6. Push, Pull Request, слияние

    git push -u origin security/13-sast-sca

PR, поле описания: `Closes #S1, Closes #S2, Closes #S3, Closes #S4, Closes #S5, Closes #S6`.
Дождитесь прогона `security` в PR, смержите (Merge pull request), затем:

    git checkout main
    git pull
    git log --oneline --graph --all            # вывод — в сдачу

## 7. Что сдавать — проверьте

- ссылка на публичный репозиторий;
- скриншот доски: ≥ 5 Issues в разных колонках;
- `git log --oneline --graph --all` (≥ 3 коммита, слитая ветка);
- `.gitignore`: `git ls-files | findstr /i "security-reports .venv-audit bandit.json pip-audit.json"` — пусто;
- вывод Bandit и pip-audit (скриншот или текст), фрагмент JSON с находками, артефакты Semgrep и cargo-audit из Actions;
- `SECURITY_REPORT.md` без строк «ЗАПОЛНИТЬ», с версиями инструментов и датой прогона;
- скриншот страницы Actions с запуском `security`.
