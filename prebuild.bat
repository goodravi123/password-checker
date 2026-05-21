@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" app.py --build-index lists
".venv\Scripts\python.exe" app.py --build-index hashes
pause
