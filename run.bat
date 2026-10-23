@echo off
REM Starts FinSecure (API + dashboard) and opens the browser.
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
if not exist .venv ( echo Run setup.bat first. & pause & exit /b 1 )
call .venv\Scripts\activate.bat
start "" http://127.0.0.1:8000
python run.py serve %*
pause
