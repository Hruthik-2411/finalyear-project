@echo off
REM Evaluation with the provider from config.yaml (Groq by default).
REM   run_eval.bat            quick sample (14 benign tasks + 40 attacks + 6 scenarios, baseline and secured)
REM   run_eval.bat --full     everything (380 attack runs per configuration - slow on the Groq free tier)
REM   run_eval.bat --ablation adds "without X" / "only X" configurations
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
call .venv\Scripts\activate.bat
python run.py eval %*
echo Results are in the results\ folder and on the Results page of the dashboard.
pause
