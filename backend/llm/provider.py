"""LLM providers: Groq (cloud), Ollama (local) and Mock (offline, deterministic).

Every agent call goes through `LLM.complete_json(purpose, system, user, ctx)` and gets
a parsed JSON object back. `ctx` carries the structured inputs; real LLMs ignore it
(they read the prompt), the mock reads it instead of parsing prose.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

import requests

from backend.config import get_config, groq_api_key


class LLMError(Exception):
    pass


def _parse_json(text: str) -> dict:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    raise LLMError(f"model did not return JSON: {text[:200]}")


class _Stats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls = 0
        self.tokens = 0
        self.by_purpose: dict[str, int] = {}

    def add(self, purpose: str, tokens: int = 0) -> None:
        with self.lock:
            self.calls += 1
            self.tokens += tokens
            self.by_purpose[purpose] = self.by_purpose.get(purpose, 0) + 1

    def snapshot(self) -> dict:
        with self.lock:
            return {"calls": self.calls, "tokens": self.tokens, "by_purpose": dict(self.by_purpose)}


STATS = _Stats()


class GroqProvider:
    name = "groq"

    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg["llm"]
        self.key = groq_api_key()
        if not self.key:
            raise LLMError("GROQ_API_KEY is not set. Put it in the .env file (see .env.example).")

    def _post(self, payload: dict) -> dict:
        delay = 2.0
        last = None
        for _ in range(int(self.cfg.get("max_retries", 4)) + 1):
            try:
                r = requests.post(self.cfg["groq_url"], json=payload, timeout=self.cfg.get("timeout_s", 60),
                                  headers={"Authorization": f"Bearer {self.key}"})
            except requests.RequestException as e:  # network problem
                last = str(e)
                time.sleep(delay)
                delay *= 2
                continue
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}: {r.text[:200]}"
                retry_after = r.headers.get("retry-after")
                time.sleep(float(retry_after) if retry_after and retry_after.replace(".", "").isdigit() else delay)
                delay = min(delay * 2, 30)
                continue
            if r.status_code >= 400:
                raise LLMError(f"Groq HTTP {r.status_code}: {r.text[:300]}")
            return r.json()
        raise LLMError(f"Groq failed after retries: {last}")

    def chat(self, system: str, user: str, json_mode: bool = True, model: str | None = None) -> tuple[str, int]:
        prompt_user = user
        if json_mode and "json" not in prompt_user.lower():
            prompt_user = prompt_user + "\n\nReturn ONLY a valid JSON object."
        payload: dict[str, Any] = {
            "model": model or self.cfg["groq_model"],
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt_user}],
            "temperature": self.cfg.get("temperature", 0),
            "seed": self.cfg.get("seed", 42),
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        data = self._post(payload)
        text = data["choices"][0]["message"]["content"]
        return text, int(data.get("usage", {}).get("total_tokens", 0))

    def classify(self, text: str, model: str) -> float | None:
        """Llama Prompt Guard 2 on Groq: returns probability the text is a prompt attack."""
        data = self._post({"model": model, "messages": [{"role": "user", "content": text}], "temperature": 0})
        out = str(data["choices"][0]["message"]["content"]).strip()
        try:
            return max(0.0, min(1.0, float(out)))
        except ValueError:
            low = out.lower()
            m = re.search(r"([01](?:\.\d+)?)", out)
            if "malicious" in low or "injection" in low or "jailbreak" in low:
                return float(m.group(1)) if m else 0.95
            if "benign" in low or "safe" in low:
                return float(m.group(1)) if m and float(m.group(1)) < 0.5 else 0.05
            return float(m.group(1)) if m else None


class OllamaProvider:
    name = "ollama"

    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg["llm"]

    def available(self) -> bool:
        try:
            return requests.get(self.cfg["ollama_url"] + "/api/tags", timeout=2).ok
        except requests.RequestException:
            return False

    def chat(self, system: str, user: str, json_mode: bool = True, model: str | None = None) -> tuple[str, int]:
        payload = {"model": model or self.cfg["ollama_model"], "stream": False,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                   "options": {"temperature": self.cfg.get("temperature", 0), "seed": self.cfg.get("seed", 42)}}
        if json_mode:
            payload["format"] = "json"
        try:
            r = requests.post(self.cfg["ollama_url"] + "/api/chat", json=payload,
                              timeout=max(120, self.cfg.get("timeout_s", 60)))
        except requests.RequestException as e:
            raise LLMError(f"Ollama not reachable at {self.cfg['ollama_url']}: {e}")
        if not r.ok:
            raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        return data["message"]["content"], int(data.get("eval_count", 0)) + int(data.get("prompt_eval_count", 0))


class LLM:
    """Facade used by agents and the Prompt Shield."""

    def __init__(self, provider: str | None = None) -> None:
        cfg = get_config()
        self.provider_name = provider or cfg["llm"]["provider"]
        self._groq = None
        self._ollama = None
        if self.provider_name == "groq":
            self._groq = GroqProvider(cfg)
            if cfg["llm"].get("fallback_to_ollama"):
                self._ollama = OllamaProvider(cfg)
        elif self.provider_name == "ollama":
            self._ollama = OllamaProvider(cfg)
        elif self.provider_name == "mock":
            raise LLMError("MockLLM has been deleted. Only real LLM (Groq) is enabled.")
        else:
            raise LLMError(f"unknown provider {self.provider_name}")

    @property
    def is_mock(self) -> bool:
        return False

    def complete_json(self, purpose: str, system: str, user: str, ctx: dict | None = None) -> dict:
        attempts = [p for p in (self._groq, self._ollama) if p is not None]
        last_err = None
        for p in attempts:
            if p is self._ollama and self._groq is not None and not self._ollama.available():
                continue
            for k in range(2):
                try:
                    text, tokens = p.chat(system, user if k == 0 else user + "\n\nReturn ONLY one valid JSON object.")
                    STATS.add(purpose, tokens)
                    return _parse_json(text)
                except LLMError as e:
                    last_err = e
                    if "did not return JSON" not in str(e):
                        break
        raise LLMError(str(last_err))

    def prompt_guard(self, text: str) -> float | None:
        cfg = get_config()
        if self._groq is None or not cfg["shield"].get("use_prompt_guard", True):
            return None
        try:
            STATS.add("prompt_guard")
            return self._groq.classify(text, cfg["shield"]["prompt_guard_model"])
        except LLMError:
            return None


_LLM: LLM | None = None
_LLM_LOCK = threading.Lock()


def get_llm(refresh: bool = False) -> LLM:
    global _LLM
    with _LLM_LOCK:
        if _LLM is None or refresh or _LLM.provider_name != get_config()["llm"]["provider"]:
            _LLM = LLM()
        return _LLM
