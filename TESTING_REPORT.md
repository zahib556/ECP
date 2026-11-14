# Отчёт о тестировании

## 1. Объект тестирования

Тестировались модули, принимающие **внешние данные** (файлы, строки, ввод пользователя) и потому наиболее
подверженные ошибкам обработки. Все они написаны на Python и не требуют Rust-ядра (`_core`).

| Модуль | Функция | Входные данные | Ожидаемый результат |
|---|---|---|---|
| `asn1` | `parse`, `parse_all`, `as_*` | корректный DER | дерево элементов |
| `asn1` | `parse`, `oid` | обрезанный DER, неверная длина, OID `1.2.-3` | `Asn1Error` |
| `x509` | `parse_certificate` | сертификат bign / мусор | `CertInfo` / `EcpError` |
| `update.versions` | `parse`, `is_valid` | `1.2.3` / `1.0.0\n`, `01.0.0`, `1.0` | кортеж / `ValueError` |
| `update.release` | `validate`, `load_json` | корректный манифест / неверные поля | `UpdateManifest` / `ManifestError` |
| `update.sbom` | `check`, `generate` | CycloneDX 1.5 / повреждённый SBOM | словарь версий / `SbomMismatch` |
| `update.staging` | `extract` | ZIP / Zip Slip, «бомба», битый архив | число файлов / `PackageError` |
| `auth.passwords` | `hash_password`, `verify_password`, `policy_problems`, `strength` | пароли, записи хэшей | `True`/`False`, список замечаний |
| `auth.tokens` | `encode`, `decode` | JWT HS256 / подделка, просрочка | claims / `TokenError` |
| `auth.service` | `register`, `login`, `me`, `logout` | логины, пароли, device_id | сессия / `AuthError` |
| `config` | `parse_period`, `parse_size`, `check_param`, `load` | `30d`, `100MB` / неверные значения | значение / `ValueError`, замечание |
| `audit` | `parse_line` (JSON, CSV, CEF) | строки журнала | `AuditEvent` или `None` |
| `logview` | `classify`, `analyze` | события журнала | категория, сводка и предупреждения |

## 2. Методика

| Вид | Файл | Инструмент |
|---|---|---|
| Функциональные позитивные | `tests/test_functional_positive.py` | pytest |
| Функциональные негативные | `tests/test_functional_negative.py` | pytest (`parametrize`) |
| Краевые значения | `tests/test_boundary.py` | pytest (`parametrize`) |
| Property-based | `tests/test_fuzz_properties.py` | hypothesis |
| Фаззинг | `fuzz/run_fuzz.py`, `fuzz/targets.py` | собственный мутационный фаззер (стандартная библиотека) |
| Регрессия | `tests/test_regressions.py` | pytest |


Версии инструментов:

    pytest==8.3   pytest-cov==5.0   hypothesis==6.100  

## 3. Результаты

### 3.1. Функциональные тесты

| Группа | Файл | Тип | Функций | Случаев | Результат |
|---|---|---|---|---|---|
| ASN.1, X.509, версии, пароли, токены, конфигурация, манифест, SBOM, пакет, журнал, вход | `test_functional_positive.py` | позитивный | 17 | 19 | PASS |
| те же модули, недопустимые данные | `test_functional_negative.py` | негативный | 29 | 172 | PASS |

Примеры позитивных: `test_asn1_sequence_roundtrip`, `test_x509_parse_certificate_fields`, `test_password_hash_and_verify`,
`test_package_extracts_and_skips_service_files`, `test_auth_register_login_me_logout`. Примеры негативных:
`test_asn1_rejects_malformed_der`, `test_asn1_oid_rejects_invalid_identifiers`, `test_package_rejects_zip_slip_and_absolute_paths`,
`test_login_rejects`, `test_sbom_rejects_invalid`, `test_token_rejects_malformed`.

### 3.2. Краевые значения (`test_boundary.py`, 25 функций, 99 случаев, PASS)

| Параметр | Допустимо | Проверены значения |
|---|---|---|
| Длина логина | 3…32 | 0, 1, 2, **3**, 4, 31, **32**, 33 |
| Длина пароля | 8…128 | 0, 6, 7, **8**, 9, 127, **128**, 129 |
| Срок очистки журнала | 1h…3650d | 0h, **1h**, 87599h, **87600h**, 87601h; 0d, **1d**, **3650d**, 3651d |
| Размер файла журнала | 1KB…10GB | 0KB, **1KB**, **10240MB**, 10241MB, 11GB |
| Итерации PBKDF2 | ≥ 200 000 | 199 999, **200 000**, 200 001 |
| Размер пакета в манифесте | 1…4 GiB | -1, 0, **1**, 2, **MAX**, MAX+1 |
| `min_supported` | ≤ версии | 1.2.2, **1.2.3**, 1.2.4 |
| Длина токена | ≤ 4096 | 2, 4095, **4096**, 4097, 100 000 (всегда `TokenError`) |
| Длина элемента ASN.1 | — | 126, 127, 128, 255, 256, 65 535, 65 536 |
| Лимит распаковки | `limit` | 99, **100**, 101 (данные 100 байт) |
| Блокировка входа | 5 ошибок / 5 мин | 4 и 5 ошибок; 4:59 и 5:00 после блокировки |
| Срок сессии | 30 мин | 29:59 и 30:00, переход через полночь |
| Год в `time_choice` | UTCTime 1950…2049 | 1949, **1950**, **2049**, 2050 |
| Дата в манифесте | календарь | 31.12 23:59:59, 01.01 00:00:00, 29.02 (високосный и нет), 24:00:00, :60, месяц 00 и 13 |

### 3.3. Фаззинг

Запуск: `python fuzz/run_fuzz.py --target all --time 60 --seed 1`. Python 3.12.3, 13 целей по 60 с
(всего 13 минут).

| Цель | Входов | Входов/с | Исходов | Падений |
|---|---|---|---|---|
| asn1_parse (разбор DER, все `as_*`) | 955 183 | 15 920 | 6 | 0 |
| asn1_oid (кодирование OID, свойство обратимости) | 1 256 859 | 20 948 | 3 | 0 |
| asn1_roundtrip (INTEGER, OCTET STRING, время) | 4 451 519 | 74 192 | 1 | 0 |
| x509 (`parse_certificate`) | 799 161 | 13 319 | 4 | 0 |
| audit_line (JSON/CSV/CEF) | 4 274 405 | 71 240 | 1 | 0 |
| config (INI-файл) | 164 217 | 2 737 | 1 | 0 |
| manifest (JSON манифеста) | 1 129 949 | 18 832 | 11 | 0 |
| sbom (CycloneDX) | 773 669 | 12 894 | 12 | 0 |
| package_zip (распаковка) | 171 111 | 2 852 | 7 | 0 |
| token (JWT) | 1 271 414 | 21 190 | 6 | 0 |
| semver | 13 343 859 | 222 397 | 1 | 0 |
| ids (SHA-256, device_id) | 16 525 622 | 275 427 | 1 | 0 |
| password_policy | 6 683 112 | 111 385 | 1 | 0 |
| **Всего** | **51 800 080** | | | **0** |

**До исправлений** первый короткий прогон (6–12 с на цель) дал: зависание `asn1_oid` (вход `00 02 03`),
13 различных падений `package_zip`, по одному в `token`, `semver`, `ids`. Каждое воспроизведено, сведено к минимальному входу и закрыто регрессионным тестом.

Property-based (hypothesis, `test_fuzz_properties.py`): 14 свойств, PASS. Короткий прогон фаззера
в составе pytest (`test_fuzz_smoke.py`): 13 целей по 2 с, PASS.

## 4. Найденные дефекты

Исходный код падал на всех 13 регрессионных тестах `test_regressions.py`; после исправления все проходят.

| ID | Issue | Где | Описание | Минимальный вход | Найден | Серьёзность | Статус |
|---|---|---|---|---|---|---|---|
| BUG-1 | #B1 | `asn1.oid` | Отрицательная дуга ведёт к **бесконечному циклу** и росту памяти (`-1 >> 7 == -1`); `1.-5` молча кодируется как `1.35` | `asn1.oid("1.2.-3")` | фаззинг | средняя (отказ в обслуживании) | исправлен |
| BUG-2 | #B2 | `versions`, `version`, `release`, `device` | Регулярные выражения с `$` принимают хвостовой `\n`, а `\d` — цифры других алфавитов: `"1.0.0\n"`, `"0.2٣0.30"`, SHA-256 и `device_id` с `\n` считаются корректными | `"1.0.0\n"` | фаззинг | низкая–средняя | исправлен (`fullmatch`, `[0-9]`) |
| BUG-3 | #B3 | `sbom.check` | `metadata.component` не объект -> `AttributeError` вместо `SbomMismatch`, обновление падает, а не отклоняется со статусом `sbom_mismatch` | `{"metadata":{"component":[1]}}` | ручная проверка, негативный тест | средняя | исправлен |
| BUG-4 | #B4 | `tokens.decode` | Токен с не-ASCII символом -> `UnicodeEncodeError` вместо `TokenError` (данные приходят от клиента) | токен с `\ufffd` | фаззинг | средняя | исправлен |
| BUG-5 | #B5 | `staging.extract` | Повреждённый ZIP: `BadZipFile` (CRC, имя в заголовке, перекрытие), `NotImplementedError` (метод сжатия, шифрование), `RuntimeError`, `zlib.error`, `OSError` не приводятся к `PackageError` | ZIP с испорченной CRC-32 | фаззинг | средняя | исправлен |
| BUG-6 | #B6 | `passwords.verify_password` | Запись хэша с не-ASCII символом -> `UnicodeEncodeError` вместо `False` (после 200 000 итераций PBKDF2) | `pbkdf2_sha256$200000$é` | негативный тест | низкая | исправлен |
| BUG-7 | #B7 | `config.parse_period` | Огромное число (`99999999999d`) -> `OverflowError` вместо `ValueError`; **файл `config.ini` с таким значением ронял загрузку конфигурации** | `99999999999d` | негативный тест | средняя | исправлен |

Файлы с исправлениями: `asn1.py`, `update/versions.py`, `version.py`, `update/release.py`, `auth/device.py`, `update/sbom.py`,
`auth/tokens.py`, `update/staging.py`, `auth/passwords.py`, `config.py`.


## 5. Покрытие



================================================== tests coverage ===================================================
 coverage: platform win32, python 3.9.13-final-0

Name                             Stmts   Miss  Cover   Missing
--------------------------------------------------------------
python\ecp\__init__.py               3      0   100%
python\ecp\__main__.py              37     11    70%   16-19, 23, 37-40, 42-43, 49
python\ecp\asn1.py                 167      2    99%   102, 151
python\ecp\audit.py                311      9    97%   66-67, 78-79, 215, 427-428, 469-470
python\ecp\auth\__init__.py          3      0   100%
python\ecp\auth\device.py           43     11    74%   32-42
python\ecp\auth\passwords.py        59      0   100%
python\ecp\auth\service.py         228      8    96%   103, 125, 159, 257-258, 265, 294-295
python\ecp\auth\session.py          20      0   100%
python\ecp\auth\store.py            90      2    98%   139, 165
python\ecp\auth\tokens.py           44      2    95%   57-58
python\ecp\cades.py                201     25    88%   166, 174, 203-204, 216-217, 219, 227-228, 230, 240-241, 256-257, 267-268, 279-280, 298-300, 302, 306-308
python\ecp\config.py               209      9    96%   35-37, 41, 143, 215-216, 290-291
python\ecp\context.py              240     25    90%   59-60, 92-93, 137-138, 145, 160, 178-182, 188-189, 219-222, 245-248, 286-287, 326-327
python\ecp\cryptoif.py              14      0   100%
python\ecp\curve.py                 18      1    94%   23
python\ecp\errors.py                 1      0   100%
python\ecp\gui\__init__.py           0      0   100%
python\ecp\gui\__main__.py           2      2     0%   1-3
python\ecp\gui\app.py              420    420     0%   6-551
python\ecp\gui\log_tab.py          132    132     0%   3-182
python\ecp\gui\login_dialog.py     160    160     0%   2-208
python\ecp\gui\settings_tab.py     123    123     0%   2-161
python\ecp\gui\update_tab.py        92     92     0%   3-138
python\ecp\gui\widgets.py           66     66     0%   2-100
python\ecp\logview.py               81      1    99%   91
python\ecp\manifest.py             108      2    98%   132-133
python\ecp\service.py              434     38    91%   102, 107-108, 122-125, 181-183, 241-242, 252, 298, 300, 329-330, 357-358, 374-375, 458, 570-571, 582, 607-608, 616, 624, 643-654
python\ecp\tsp.py                  272     25    91%   100, 132-133, 150, 173, 201-202, 241, 249, 273-276, 295-296, 306-307, 309, 323-324, 345-346, 351-352, 379
python\ecp\update\__init__.py        3      0   100%
python\ecp\update\installer.py     105     53    50%   35, 57, 59, 80-87, 92-109, 113-117, 121-144, 148
python\ecp\update\pubkey.py          1      0   100%
python\ecp\update\release.py       129      6    95%   129-130, 137-138, 162-163
python\ecp\update\runtime.py        22     11    50%   12, 17-19, 23, 28-30, 34, 38-39
python\ecp\update\sbom.py           67      0   100%
python\ecp\update\source.py         40      3    92%   34, 36-37
python\ecp\update\staging.py        77      5    94%   55, 80, 82-83, 92
python\ecp\update\updater.py       153     14    91%   65-68, 150, 159-161, 174, 201-203, 212-213
python\ecp\update\versions.py       11      0   100%
python\ecp\version.py                9      0   100%
python\ecp\x509.py                  98      3    97%   165, 168-169
--------------------------------------------------------------
TOTAL                             4293   1261    71%
========================================== 655 passed in 62.45s (0:01:02) ===========================================


