#!/usr/bin/env bash
# macOS / Linux equivalent of setup.bat
set -e
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
python run.py setup
echo "Done. Put your key in .env, then: docker compose up -d && python run.py serve"
