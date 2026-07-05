"""
OpenRouter Free-Model Auto-Switcher
====================================
Keeps evaluation runs alive on OpenRouter's free tier by rotating to the
next free model whenever the current one is exhausted (rate-limited,
out of quota, or upstream-unavailable).

How it works
------------
1. The candidate list is fetched live from GET /api/v1/models and filtered
   to genuinely free chat models (":free" suffix and zero prompt/completion
   pricing). If the endpoint is unreachable, the static list in
   config.FREE_LLM_PROVIDERS["OpenRouter (Free)"]["models"] is the fallback.
2. ``completion_with_rotation()`` wraps ``litellm.completion``. On an
   exhaustion-class error it marks the model dead for this process,
   advances to the next candidate, and retries. Anything that is *not* an
   exhaustion error (bad request, auth, malformed prompt) is raised
   immediately — rotating would not fix it.
3. Every switch is recorded in ``ROTATION_LOG`` and the currently active
   model is written back to ``settings.llm.api_model`` so run metadata
   (research/real_eval.py) records the model that actually produced the
   output.

Honest limits (do not oversell this in write-ups)
-------------------------------------------------
Rotation defeats *per-model* exhaustion: a model that is rate-limited,
temporarily out of upstream capacity, or removed. OpenRouter also applies
*account-level* free-tier caps (documented as ~20 requests/min and a daily
request budget). If the account-level cap is hit, no amount of model
switching helps; the wrapper then raises ``AllModelsExhausted`` so callers
fail loudly instead of silently returning error text that could
contaminate results.
"""
from __future__ import annotations

import os
import time
import json
from typing import Any

import structlog

log = structlog.get_logger()

OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

# Substrings that identify an exhaustion-class error worth rotating on.
_EXHAUSTION_MARKERS = (
    "429", "rate limit", "rate-limit", "ratelimit", "quota",
    "insufficient", "exhausted", "overloaded", "capacity",
    "502", "503", "unavailable", "no endpoints", "timed out", "timeout",
    "402", "payment", "free-models-per-day", "temporarily",
)

# Markers that mean the account-level free budget is gone (rotation useless).
_ACCOUNT_LEVEL_MARKERS = ("free-models-per-day", "daily limit", "per-day")

ROTATION_LOG: list[dict[str, Any]] = []


class AllModelsExhausted(RuntimeError):
    """Raised when every candidate free model failed with an exhaustion error."""


def _is_exhaustion(err: Exception) -> bool:
    s = f"{type(err).__name__}: {err}".lower()
    return any(m in s for m in _EXHAUSTION_MARKERS)


def _is_account_level(err: Exception) -> bool:
    s = str(err).lower()
    return any(m in s for m in _ACCOUNT_LEVEL_MARKERS)


def fetch_free_models(timeout: float = 10.0) -> list[str]:
    """Live list of free chat models from OpenRouter, preferred order.

    Preference: the configured default first, then larger-context free
    models first (a rough proxy for capability), static fallback on error.
    """
    from config import FREE_LLM_PROVIDERS, settings

    static = list(FREE_LLM_PROVIDERS.get("OpenRouter (Free)", {}).get("models", []))
    preferred_first = settings.llm.api_model if str(settings.llm.api_model).endswith(":free") else None

    models: list[str] = []
    try:
        import urllib.request
        req = urllib.request.Request(
            OPENROUTER_MODELS_URL, headers={"User-Agent": "cti-shield/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        for m in data.get("data", []):
            mid = m.get("id", "")
            pricing = m.get("pricing", {}) or {}
            if not mid.endswith(":free"):
                continue
            try:
                free = float(pricing.get("prompt", 1)) == 0.0 and \
                       float(pricing.get("completion", 1)) == 0.0
            except (TypeError, ValueError):
                free = False
            if free:
                models.append((mid, int(m.get("context_length") or 0)))
        models.sort(key=lambda t: -t[1])
        models = [mid for mid, _ in models]
        log.info("openrouter_free_models_fetched", count=len(models))
    except Exception as e:  # network-restricted or API change → static list
        log.warning("openrouter_model_list_unavailable", error=str(e))
        models = []

    if not models:
        models = static
    # De-duplicate while keeping order; put the configured default first.
    ordered: list[str] = []
    if preferred_first and preferred_first in models:
        ordered.append(preferred_first)
    for mid in models + [m for m in static if m not in models]:
        if mid not in ordered:
            ordered.append(mid)
    return ordered


class OpenRouterRotator:
    """Process-wide rotation state over the free-model candidate list."""

    def __init__(self) -> None:
        self._candidates: list[str] | None = None
        self._dead: set[str] = set()
        self._idx = 0

    @property
    def candidates(self) -> list[str]:
        if self._candidates is None:
            self._candidates = fetch_free_models()
        return self._candidates

    @property
    def current(self) -> str:
        cands = self.candidates
        # skip dead entries
        while self._idx < len(cands) and cands[self._idx] in self._dead:
            self._idx += 1
        if self._idx >= len(cands):
            raise AllModelsExhausted(
                f"All {len(cands)} free OpenRouter models exhausted this process; "
                f"log: {[e['model'] for e in ROTATION_LOG]}")
        return cands[self._idx]

    def mark_exhausted(self, model: str, reason: str) -> None:
        self._dead.add(model)
        ROTATION_LOG.append({
            "model": model, "reason": reason[:300],
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        log.warning("free_model_exhausted_rotating", model=model, reason=reason[:160])

    def models_used(self) -> list[str]:
        """Every model that produced at least one successful call."""
        return list(dict.fromkeys(_SUCCESSFUL_MODELS))


_rotator: OpenRouterRotator | None = None
_SUCCESSFUL_MODELS: list[str] = []


def get_rotator() -> OpenRouterRotator:
    global _rotator
    if _rotator is None:
        _rotator = OpenRouterRotator()
    return _rotator


def reset_rotator() -> None:
    global _rotator
    _rotator = None
    ROTATION_LOG.clear()
    _SUCCESSFUL_MODELS.clear()


def completion_with_rotation(llm_kwargs: dict[str, Any], **call_kwargs: Any):
    """litellm.completion with automatic free-model failover.

    ``llm_kwargs`` comes from LLMEngine._get_litellm_kwargs(); its ``model``
    is replaced per attempt. Non-exhaustion errors raise immediately.
    """
    import litellm
    from config import settings

    rot = get_rotator()
    prefix = "openrouter/"
    last_err: Exception | None = None

    while True:
        model = rot.current  # raises AllModelsExhausted when list is drained
        attempt_kwargs = dict(llm_kwargs)
        attempt_kwargs["model"] = model if model.startswith(prefix) else prefix + model
        try:
            resp = litellm.completion(**attempt_kwargs, **call_kwargs)
            # Success: record it and keep settings in sync for run metadata.
            if model not in _SUCCESSFUL_MODELS:
                _SUCCESSFUL_MODELS.append(model)
            settings.llm.api_model = model
            return resp
        except Exception as e:
            last_err = e
            if _is_account_level(e):
                # Account-wide daily budget — switching models cannot help.
                raise AllModelsExhausted(
                    f"OpenRouter account-level free budget exhausted: {e}") from e
            if _is_exhaustion(e):
                rot.mark_exhausted(model, str(e))
                continue
            raise  # genuine error (auth, bad request, …) — do not mask it


def strict_mode() -> bool:
    """When CTI_STRICT_LLM is set, engine callers must re-raise API failures
    instead of returning error text — error strings scored by the guard
    would silently contaminate evaluation results."""
    return os.getenv("CTI_STRICT_LLM", "").lower() in ("1", "true", "yes")
