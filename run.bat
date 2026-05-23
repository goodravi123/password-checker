@echo off
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else if exist "venv\Scripts\python.exe" (
    set "PY=venv\Scripts\python.exe"
) else (
    echo [INFO] Geen .venv gevonden — gebruik systeem-python.
    echo        Run eerst setup.bat om een venv aan te maken.
    set "PY=python"
)

"%PY%" app.py
if errorlevel 1 pause
