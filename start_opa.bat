@echo off
REM Starts the Open Policy Agent server in Docker (Docker Desktop must be running).
cd /d "%~dp0"
docker compose up -d
if errorlevel 1 (
  echo Could not start OPA. Is Docker Desktop running?
  echo FinSecure still works without it - it falls back to the built-in policy evaluator.
  pause & exit /b 1
)
echo OPA is running on http://localhost:8181   (stop it with: docker compose down)
timeout /t 3 >nul
