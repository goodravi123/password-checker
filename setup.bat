@echo off
cd /d "%~dp0"
echo Password Checker — setup
echo.

where py >nul 2>&1
if %errorlevel%==0 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)

if not exist ".venv\Scripts\python.exe" (
    echo [FOUT] Kon .venv niet aanmaken. Installeer Python 3.10+ van python.org
    pause
    exit /b 1
)

echo Dependencies installeren...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt

echo.
echo Klaar. Start de app met run.bat
pause
