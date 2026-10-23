@echo off
REM ===== FinSecure one-time setup (Windows) =====
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer from python.org and tick "Add python.exe to PATH".
  pause & exit /b 1
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
  echo Python 3.10 or newer is required.
  python --version
  pause & exit /b 1
)

if not exist .venv (
  echo [1/4] Creating virtual environment .venv ...
  python -m venv .venv
)
call .venv\Scripts\activate.bat

echo [2/4] Installing Python packages (takes a few minutes the first time) ...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt
if errorlevel 1 ( echo Package install failed. & pause & exit /b 1 )

if not exist .env (
  copy .env.example .env >nul
  echo [3/4] Created .env - open it in Notepad and paste your GROQ_API_KEY.
) else (
  echo [3/4] .env already exists.
)

echo [4/4] Creating database, seed data and agent certificates ...
python run.py setup

echo.
echo Setup complete.
echo   1. Put your Groq key in .env   (notepad .env)
echo   2. Start OPA:                   start_opa.bat   (needs Docker Desktop running)
echo   3. Start FinSecure:             run.bat
pause
