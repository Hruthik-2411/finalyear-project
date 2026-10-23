"""Module 3 - Prompt Shield.

Scans untrusted content (tool results such as memos, uploaded documents, policies, case
notes) and inter-agent messages for prompt injection, BEFORE an agent sees it.
  Stage 1: Llama Prompt Guard 2 86M (via Groq) on ~512-token chunks, plus a fast local
           heuristic scorer. The higher score wins.
  Stage 2: only for medium scores, an LLM judge with a fixed rubric decides.
High risk -> the text is redacted. Medium -> delivered but the chain is marked "tainted",
so any Tier-2 action in that chain is escalated to a human.
Spotlighting wraps all untrusted text in markers the agents are told never to obey.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

from backend.common import sha256
from backend.config import get_config

REDACTED = "[REDACTED by Prompt Shield: suspected prompt injection]"
OPEN, CLOSE = "<<UNTRUSTED_DATA>>", "<</UNTRUSTED_DATA>>"

# (pattern, weight) - combined as 1 - prod(1 - w)
PATTERNS: list[tuple[re.Pattern, float]] = [(re.compile(p, re.I), w) for p, w in [
    (r"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules)", 0.9),
    (r"disregard (?:the |all )?(?:previous|above|prior|system)", 0.85),
    (r"\b(?:system|admin|compliance) (?:notice|override|instruction|message)\b", 0.6),
    (r"^\s*(?:system|assistant)\s*:", 0.6),
    (r"\bimportant(?: !+|:| instructions?)", 0.45),
    (r"\byou (?:must|are required to|need to) (?:now )?(?:transfer|send|change|update|approve|unfreeze|freeze|add|delete|escalate)", 0.75),
    (r"\b(?:before|after) (?:finishing|you finish|completing|answering)\b", 0.45),
    (r"\btransfer\s+(?:₹|rs\.?|inr)?\s*[\d,]+.*\bto\s+ACC-\d{4}", 0.25),
    (r"\b(?:change|update) the (?:email|phone)", 0.25),
    (r"\bunfreeze\b", 0.2),
    (r"\bapprove (?:the )?loan\b|\bapprove LN-\d{3}", 0.25),
    (r"\badd a case note\b.*\b(?:email|phone|contact)", 0.35),
    (r"\b(?:do not|don't) (?:tell|inform|mention|report|log)\b", 0.6),
    (r"\bauthori[sz]ed by (?:the )?(?:compliance|security|management|head office)", 0.4),
    (r"\bnew instructions?\b|\bupdated instructions?\b", 0.6),
    (r"\bas an ai\b|\blanguage model\b|\bagent[s]?\b.*\bmust\b", 0.4),
    (r"<\|.*?\|>|\[/?INST\]|###\s*(?:instruction|system)", 0.7),
    (r"\bexfiltrat|\bsend .* to .*@", 0.5),
]]


def heuristic_score(text: str) -> float:
    if not text:
        return 0.0
    p = 1.0
    for pat, w in PATTERNS:
        if pat.search(text):
            p *= (1 - w)
    return round(1 - p, 4)


@dataclass
class ShieldResult:
    score: float
    level: str        # low | medium | high
    source: str       # heuristic | prompt_guard | judge
    detail: str = ""


class PromptShield:
    def __init__(self, llm=None) -> None:
        self.llm = llm
        self._cache: dict[str, ShieldResult] = {}
        self._lock = threading.Lock()

    def _level(self, s: float) -> str:
        cfg = get_config()["shield"]
        return "high" if s >= cfg["high_threshold"] else "medium" if s >= cfg["low_threshold"] else "low"

    def scan(self, text: str) -> ShieldResult:
        text = text or ""
        key = sha256(text)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        cfg = get_config()["shield"]
        h = heuristic_score(text)
        score, source, detail = h, "heuristic", f"heuristic={h:.2f}"
        if self.llm is not None and not self.llm.is_mock and text.strip():
            n = int(cfg.get("chunk_chars", 1500))
            pg_scores = [self.llm.prompt_guard(text[i:i + n]) for i in range(0, len(text), n)]
            pg_scores = [x for x in pg_scores if x is not None]
            if pg_scores:
                pg = max(pg_scores)
                detail += f", prompt_guard={pg:.2f}"
                if pg > score:
                    score, source = pg, "prompt_guard"
        level = self._level(score)
        if level == "medium" and cfg.get("use_llm_judge", True) and self.llm is not None:
            from backend.llm.prompts import judge_prompt

            try:
                sys, user = judge_prompt(text)
                j = self.llm.complete_json("judge", sys, user, {"text": text})
                conf = float(j.get("confidence", 0.5))
                if j.get("injection"):
                    score = max(score, cfg["high_threshold"], conf)
                else:
                    score = min(score, cfg["low_threshold"] - 0.01) if conf >= 0.7 else score
                source, detail = "judge", detail + f", judge={j.get('injection')}({conf:.2f}): {str(j.get('reason', ''))[:80]}"
            except Exception as e:  # judge failure: keep stage-1 score
                detail += f", judge failed: {e}"[:120]
        res = ShieldResult(round(min(score, 1.0), 4), self._level(score), source, detail)
        with self._lock:
            self._cache[key] = res
        return res

    def reset_cache(self) -> None:
        with self._lock:
            self._cache.clear()


def spotlight(text: str) -> str:
    return f"{OPEN}{text}{CLOSE}"
