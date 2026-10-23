"""Configuration: config.yaml + .env, with runtime overrides (mode, provider, modules)."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"
DATA_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)

try:  # .env is optional
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except Exception:  # pragma: no cover
    pass

_CONFIG: dict[str, Any] | None = None


def _load() -> dict[str, Any]:
    with open(ROOT / "config.yaml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # environment overrides (handy for scripts / tests)
    if os.getenv("FINSECURE_PROVIDER"):
        cfg["llm"]["provider"] = os.environ["FINSECURE_PROVIDER"]
    if os.getenv("FINSECURE_MODE"):
        cfg["security"]["mode"] = os.environ["FINSECURE_MODE"]
    if os.getenv("FINSECURE_DB"):
        cfg["db_path"] = os.environ["FINSECURE_DB"]
    cfg.setdefault("db_path", str(DATA_DIR / "finsecure.db"))
    return cfg


def get_config() -> dict[str, Any]:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = _load()
    return _CONFIG


def reload_config() -> dict[str, Any]:
    global _CONFIG
    _CONFIG = _load()
    return _CONFIG


def snapshot() -> dict[str, Any]:
    return copy.deepcopy(get_config())


def groq_api_key() -> str | None:
    key = os.getenv("GROQ_API_KEY", "").strip()
    return key or None


def abs_path(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else ROOT / path
