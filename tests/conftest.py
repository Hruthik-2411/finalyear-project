"""Test setup: offline mock LLM and a separate test database (never touches data/finsecure.db)."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["FINSECURE_PROVIDER"] = "mock"
os.environ["FINSECURE_MODE"] = "secured"
os.environ.setdefault("FINSECURE_DB", str(Path(tempfile.gettempdir()) / "finsecure_test.db"))
