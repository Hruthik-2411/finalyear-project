@echo off
REM Starts FinSecure with the offline mock LLM - use this if there is no internet at the venue.
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
call .venv\Scripts\activate.bat
start "" http://127.0.0.1:8000
python run.py serve --provider mock
pause
