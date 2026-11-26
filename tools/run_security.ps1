# Локальный прогон SAST/SCA на Windows (ПЗ-7). Запуск из корня проекта:
#     .\tools\run_security.ps1
# Отчёты кладутся в security-reports\ (каталог в .gitignore).
# Semgrep и cargo-audit здесь не запускаются: Semgrep не работает на Windows нативно -
# их результаты берутся из GitHub Actions (артефакты sast-reports и sca-reports).

$ErrorActionPreference = "Continue"
$out = "security-reports"
New-Item -ItemType Directory -Force $out | Out-Null

python -m pip install -r requirements-security.txt
python -m pip freeze | Select-String -Pattern "bandit|pip-audit" | Out-File "$out\tool-versions.txt" -Encoding ascii

Write-Host "=== SAST: Bandit ==="
bandit -r python tools main.py -c bandit.yaml -f json -o "$out\bandit.json"
bandit -r python tools main.py -c bandit.yaml -f txt  -o "$out\bandit.txt"
Get-Content "$out\bandit.txt"
Write-Host "Bandit, код возврата: $LASTEXITCODE (0 - чисто, 1 - есть находки)"

Write-Host "=== SCA: pip-audit ==="
# Отдельное окружение только с рабочими зависимостями, чтобы в отчёт не попали pytest, bandit и т.п.
python -m venv .venv-audit
& .\.venv-audit\Scripts\python.exe -m pip install --quiet PySide6 cryptography
# Windows PowerShell 5 по умолчанию пишет UTF-16, pip-audit его не прочтёт: нужен ascii
& .\.venv-audit\Scripts\python.exe -m pip freeze | Out-File "$out\requirements-runtime.txt" -Encoding ascii
pip-audit -r "$out\requirements-runtime.txt" --no-deps --disable-pip -f json -o "$out\pip-audit.json"
pip-audit -r "$out\requirements-runtime.txt" --no-deps --disable-pip | Tee-Object "$out\pip-audit.txt"
Write-Host "pip-audit, код возврата: $LASTEXITCODE (0 - чисто, 1 - есть уязвимости)"
