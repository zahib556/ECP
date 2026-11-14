# ПЗ-6: что сделать на GitHub и в терминале

Номера задач ниже условные: **#N1…#N5** — Issues по видам тестирования, **#B1…#B7** — Issues с метками `bug`.
Подставьте реальные номера, которые назначит GitHub.

## 1. Issues (часть 2.1) — создайте и добавьте на доску (+ Add item)

| № | Title | Description / критерии готовности |
|---|---|---|
| #N1 | Функциональные позитивные тесты | Тесты корректных данных для asn1, x509, версий, паролей, токенов, конфигурации, манифеста, SBOM, пакета, журнала, входа. Готово: `tests/test_functional_positive.py`, `pytest` без ошибок |
| #N2 | Функциональные негативные тесты | Пустые/неверные/недопустимые данные, Zip Slip, подделка токена. Готово: `tests/test_functional_negative.py`, все PASS |
| #N3 | Тесты краевых значений | Границы чисел, строк, коллекций, времени и дат (граница, ниже, выше). Готово: `tests/test_boundary.py` |
| #N4 | Фаззинг-тесты | Фаззер `fuzz/`, property-based тесты, ≥ 60 с на цель, триаж падений, регрессионные тесты. Готово: `fuzz/`, `tests/test_fuzz_*.py`, `tests/test_regressions.py` |
| #N5 | Отчёт о тестировании | `TESTING_REPORT.md` по структуре из задания, с покрытием и выводом pytest |

Дефекты (метка `bug`, приложите вход и трассировку из `fuzz/crashes/*.txt`, если запускали фаззер у себя):

| № | Title | Минимальный вход |
|---|---|---|
| #B1 | asn1.oid: бесконечный цикл при отрицательной дуге | `asn1.oid("1.2.-3")` |
| #B2 | Версии, SHA-256 и device_id принимают `\n` и цифры других алфавитов | `"1.0.0\n"` |
| #B3 | sbom.check: AttributeError при metadata.component не объекте | `{"metadata":{"component":[1]}}` |
| #B4 | tokens.decode: UnicodeEncodeError на не-ASCII токене | токен с `\ufffd` |
| #B5 | staging.extract: библиотечные исключения вместо PackageError на битом ZIP | ZIP с испорченной CRC-32 |
| #B6 | verify_password: UnicodeEncodeError на записи с не-ASCII | `pbkdf2_sha256$200000$é` |
| #B7 | parse_period: OverflowError на огромном числе, config.ini роняет загрузку | `99999999999d` |

Подробности по каждому — в разделе 4 `TESTING_REPORT.md`.

## 2. Ветка и установка инструментов (части 1.1–1.3)

    cd путь\к\проекту
    git pull
    git status                                  # дерево чистое
    git checkout -b test/12-software-testing    # 12 -> номер вашего Issue
    # распакуйте ecp_step12.zip поверх проекта (замените файлы), затем:
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt
    maturin develop
    pip freeze | findstr /i "pytest hypothesis"  # впишите версии в requirements-dev.txt и TESTING_REPORT.md

## 3. Прогон и скриншоты (часть 3.3, 5.3, 7)

    pytest -v > pytest_output.txt               # вывод со статусами PASS/FAIL
    pytest --cov=ecp --cov-report=term-missing  # строку TOTAL — в раздел 5 отчёта
    python fuzz/run_fuzz.py --target all --time 60   # вывод с числом входов и падений - в отчёт/скриншот

`pytest_output.txt` в репозиторий не коммитьте (или приложите к сдаче отдельно).

## 4. Коммиты (часть 6.1): по одному на вид тестов, каждый коммит «зелёный»

    git add .gitignore requirements-dev.txt pyproject.toml tests/helpers.py tests/test_functional_positive.py
    git commit -m "test: add positive functional tests Closes #N1"

    git add python/ README.md
    git commit -m "fix: input validation defects BUG-1..BUG-7 Closes #B1 Closes #B2 Closes #B3 Closes #B4 Closes #B5 Closes #B6 Closes #B7"

    git add tests/test_functional_negative.py
    git commit -m "test: add negative functional tests Closes #N2"

    git add tests/test_boundary.py
    git commit -m "test: add boundary value tests Closes #N3"

    git add fuzz/ tests/test_fuzz_properties.py tests/test_fuzz_smoke.py tests/test_regressions.py
    git commit -m "test: add fuzzing, property-based and regression tests Closes #N4"

    git add TESTING_REPORT.md docs/
    git commit -m "docs: testing report Closes #N5"

Исправления идут отдельным коммитом **до** негативных тестов, чтобы каждый коммит проходил тесты. Если хотите показать
«красный -> зелёный», закоммитьте сначала `tests/test_functional_negative.py` и `tests/test_regressions.py` (они упадут),
затем `fix:`; для сдачи так тоже допустимо.

## 5. Push, Pull Request, слияние (часть 6.2)

    git push -u origin test/12-software-testing

PR, поле описания: `Closes #N1, Closes #N2, Closes #N3, Closes #N4, Closes #N5, Closes #B1, Closes #B2, Closes #B3, Closes #B4, Closes #B5, Closes #B6, Closes #B7`.
Смержите PR (Merge pull request), затем:

    git checkout main
    git pull
    git log --oneline --graph --all            # вывод — в сдачу

## 6. Что сдавать (часть 8) — проверьте

- ссылка на публичный репозиторий (`tests/`, `fuzz/`);
- скриншот доски: ≥ 5 Issues в разных колонках (Todo / In progress / Done);
- `git log --oneline --graph --all` (≥ 4 коммита, слитая ветка);
- `TESTING_REPORT.md` (с версиями, покрытием; строки «ЗАПОЛНИТЬ» убрать);
- вывод `pytest -v`;
- вывод фаззера ≥ 60 с;
- `.gitignore`: проверьте `git ls-files | findstr /i "pycache .pytest_cache crash- .hypothesis"` — пусто.

Если `__pycache__` когда-либо попал в историю: `git rm -r --cached --ignore-unmatch **/__pycache__`.

После исправлений в `python/ecp/` при выпуске релиза заново выполните `python tools/build_release.py sign`
(контрольные хэши файлов программы изменились).
