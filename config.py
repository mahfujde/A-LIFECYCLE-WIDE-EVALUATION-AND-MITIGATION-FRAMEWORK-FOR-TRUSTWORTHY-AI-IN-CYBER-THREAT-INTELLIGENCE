"""
CTI-Shield Configuration
========================
All settings, thresholds, API key references, and paths.
Nothing is hard-coded — everything reads from environment variables
with safe defaults so the app works out-of-the-box in Demo mode.
"""

from __future__ import annotations

import os, sys
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# ── Configure structlog to use stdlib logging (not PrintLogger) ──────
# PrintLogger uses print() to stdout which fails under Streamlit with
# OSError: [Errno 5] when the stdout fd is unavailable.  Routing through
# Python's stdlib logging module writes to stderr and handles I/O errors
# gracefully.  This MUST run before any structlog.get_logger() call.
import logging
import structlog

logging.basicConfig(
    format="%(message)s",
    stream=sys.stderr,
    level=logging.INFO,
)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)


# ── Paths ────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OSINT_DIR = DATA_DIR / "osint_reports"
FAISS_DIR = DATA_DIR / "faiss_index"
MITRE_JSON = DATA_DIR / "mitre_attack.json"
LOG_DIR = BASE_DIR / "logs"

# Ensure directories exist
for d in (DATA_DIR, OSINT_DIR, FAISS_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)


# ── Enums ────────────────────────────────────────────────────────────
class LLMMode(str, Enum):
    """Five operating modes for the LLM engine."""
    DEMO = "demo"       # No API key, deterministic mock answers (relaxed thresholds)
    LOCAL = "local"     # Downloaded local HF model — no internet needed (strict thresholds)
    OLLAMA = "ollama"   # Local Ollama models (Qwen 3, LLaMA 3, etc.) — strict thresholds
    API = "api"         # Cloud LLM via litellm (strict thresholds)
    FULL = "full"       # API + local model side-by-side (strict thresholds)


class SeverityLevel(str, Enum):
    """Human-readable threat severity scale."""
    EVERYDAY = "Everyday Risk"
    MODERATE = "Moderate Concern"
    SERIOUS = "Serious Threat"
    EMERGENCY = "Emergency"


class RetrievalMode(str, Enum):
    """Retrieval strategy for the RAG pipeline (supports ablation studies)."""
    NONE = "none"               # No retrieval — LLM receives raw input only
    VECTOR_ONLY = "vector_only" # FAISS vector similarity search only
    KG_ONLY = "kg_only"         # Knowledge Graph semantic search only
    HYBRID = "hybrid"           # KG + Vector with Reciprocal Rank Fusion


# ── Free LLM API Providers ──────────────────────────────────────────
# Source: https://github.com/cheahjs/free-llm-api-resources
# Each provider entry contains base_url, env_var for API key,
# litellm model prefix, and available free models.
FREE_LLM_PROVIDERS: dict[str, dict] = {
    "OpenRouter (Free)": {
        "base_url": "https://openrouter.ai/api/v1",
        "env_var": "OPENROUTER_API_KEY",
        "prefix": "openrouter/",
        "signup_url": "https://openrouter.ai",
        "limits": "20 req/min, 50 req/day",
        "models": [
            "google/gemma-3-27b-it:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "nousresearch/hermes-3-llama-3.1-405b:free",
            "google/gemma-3-12b-it:free",
            "qwen/qwen3-coder:free",
            "nvidia/nemotron-3-super-120b-a12b:free",
            "openai/gpt-oss-120b:free",
            "minimax/minimax-m2.5:free",
            "google/gemma-4-31b-it:free",
        ],
    },
    "Google AI Studio": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "env_var": "GEMINI_API_KEY",
        "prefix": "gemini/",
        "signup_url": "https://aistudio.google.com",
        "limits": "Free tier (generous)",
        "models": [
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
        ],
    },
    "Groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "env_var": "GROQ_API_KEY",
        "prefix": "groq/",
        "signup_url": "https://console.groq.com",
        "limits": "Rate limited per model",
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "gemma2-9b-it",
            "mixtral-8x7b-32768",
            "deepseek-r1-distill-llama-70b",
        ],
    },
    "Cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "env_var": "CEREBRAS_API_KEY",
        "prefix": "cerebras/",
        "signup_url": "https://cloud.cerebras.ai",
        "limits": "Free tier available",
        "models": [
            "llama-3.3-70b",
            "llama-3.1-8b",
            "deepseek-r1-distill-llama-70b",
        ],
    },
    "Cohere": {
        "base_url": "https://api.cohere.com/v2",
        "env_var": "COHERE_API_KEY",
        "prefix": "cohere/",
        "signup_url": "https://dashboard.cohere.com",
        "limits": "20 req/min, 1000 req/month",
        "models": [
            "command-a-03-2025",
            "command-r-plus-08-2024",
            "command-r-08-2024",
            "command-r7b-12-2024",
        ],
    },
    "GitHub Models": {
        "base_url": "https://models.inference.ai.azure.com",
        "env_var": "GITHUB_TOKEN",
        "prefix": "github/",
        "signup_url": "https://github.com/marketplace/models",
        "limits": "Depends on Copilot tier",
        "models": [
            "gpt-4o",
            "gpt-4o-mini",
            "DeepSeek-R1",
            "Meta-Llama-3.1-405B-Instruct",
            "Mistral-Small-3.1",
            "Phi-4",
        ],
    },
    "Mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "env_var": "MISTRAL_API_KEY",
        "prefix": "mistral/",
        "signup_url": "https://console.mistral.ai",
        "limits": "1 req/s, 500K tokens/min",
        "models": [
            "mistral-small-latest",
            "mistral-medium-latest",
            "open-mistral-nemo",
            "codestral-latest",
        ],
    },
    "HuggingFace": {
        "base_url": "https://api-inference.huggingface.co/v1",
        "env_var": "HF_TOKEN",
        "prefix": "huggingface/",
        "signup_url": "https://huggingface.co",
        "limits": "$0.10/month free credits",
        "models": [
            "meta-llama/Llama-3.3-70B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
            "mistralai/Mistral-Small-24B-Instruct-2501",
            "google/gemma-2-9b-it",
        ],
    },
    "NVIDIA NIM": {
        "base_url": "https://integrate.api.nvidia.com/v1",
        "env_var": "NVIDIA_API_KEY",
        "prefix": "nvidia_nim/",
        "signup_url": "https://build.nvidia.com",
        "limits": "40 req/min",
        "models": [
            "meta/llama-3.3-70b-instruct",
            "google/gemma-2-27b-it",
            "mistralai/mistral-small-24b-instruct-2501",
        ],
    },
    "SambaNova": {
        "base_url": "https://api.sambanova.ai/v1",
        "env_var": "SAMBANOVA_API_KEY",
        "prefix": "sambanova/",
        "signup_url": "https://cloud.sambanova.ai",
        "limits": "Free tier available",
        "models": [
            "Meta-Llama-3.3-70B-Instruct",
            "DeepSeek-R1-Distill-Llama-70B",
            "Qwen2.5-72B-Instruct",
        ],
    },
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "env_var": "OPENAI_API_KEY",
        "prefix": "",
        "signup_url": "https://platform.openai.com",
        "limits": "Pay-per-use",
        "models": [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
        ],
    },
    "Anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "env_var": "ANTHROPIC_API_KEY",
        "prefix": "anthropic/",
        "signup_url": "https://console.anthropic.com",
        "limits": "Pay-per-use",
        "models": [
            "claude-sonnet-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-haiku-20240307",
        ],
    },
}


# ── API Keys (from environment) ─────────────────────────────────────
OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY")
OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")
VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
OTX_API_KEY: Optional[str] = os.getenv("OTX_API_KEY")
MISP_API_KEY: Optional[str] = os.getenv("MISP_API_KEY")
MISP_URL: Optional[str] = os.getenv("MISP_URL")
THEHIVE_API_KEY: Optional[str] = os.getenv("THEHIVE_API_KEY")
THEHIVE_URL: Optional[str] = os.getenv("THEHIVE_URL")


# ── LLM Settings ────────────────────────────────────────────────────
def detect_ollama_models(base_url: str = "http://localhost:11434") -> list[dict]:
    """Probe Ollama API to discover locally installed models.

    Returns a list of dicts with keys: name, size, family.
    Prefers Qwen3 > Qwen2.5 > LLaMA > others for CTI work.
    """
    import urllib.request, json as _json
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = _json.loads(resp.read())
            models = []
            for m in data.get("models", []):
                name = m.get("name", "")
                size_bytes = m.get("size", 0)
                family = m.get("details", {}).get("family", "unknown")
                models.append({"name": name, "size": size_bytes, "family": family})
            return models
    except Exception:
        return []


def select_best_ollama_model(base_url: str = "http://localhost:11434") -> str:
    """Select the best available Ollama model for CTI analysis.

    Priority order: qwen3 > qwen2.5 > llama3 > mistral > deepseek > any other.
    Falls back to 'qwen3:latest' if no models detected (user may install later).
    """
    models = detect_ollama_models(base_url)
    if not models:
        return os.getenv("OLLAMA_MODEL", "qwen3:latest")

    # Priority ranking for CTI tasks
    priority = ["qwen3", "qwen2.5", "llama3", "llama4", "mistral", "deepseek", "gemma"]
    names = [m["name"] for m in models]

    for pref in priority:
        for name in names:
            if pref in name.lower():
                return name

    # Return the first available model
    return names[0] if names else "qwen3:latest"


@dataclass
class LLMConfig:
    """Configuration for the LLM engine."""
    mode: LLMMode = LLMMode.DEMO
    api_model: str = os.getenv("CTI_API_MODEL", "gpt-4o")
    api_provider: str = ""           # Provider name from FREE_LLM_PROVIDERS
    api_base_url: str = ""           # Custom base URL for the provider
    local_model: str = "ollama/llama3"
    local_hf_model: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"  # Downloaded HF model for LOCAL mode
    local_hf_loaded: bool = False    # Whether the local HF model is loaded
    ollama_model: str = ""           # Auto-detected from Ollama; override via OLLAMA_MODEL env var
    ollama_detected_models: list = field(default_factory=list)  # All detected Ollama models
    temperature: float = 0.1
    max_tokens: int = 4096
    max_retries: int = 3
    timeout_seconds: int = 60
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    def __post_init__(self) -> None:
        # Auto-detect Ollama models on the local machine
        if not self.ollama_model or self.ollama_model == "":
            env_model = os.getenv("OLLAMA_MODEL", "")
            if env_model:
                self.ollama_model = env_model
            else:
                self.ollama_model = select_best_ollama_model(self.ollama_base_url)

        # Store detected models for UI display
        self.ollama_detected_models = detect_ollama_models(self.ollama_base_url)

        # Auto-detect mode based on available API keys
        if self.mode == LLMMode.DEMO:
            if OPENAI_API_KEY or ANTHROPIC_API_KEY or GROQ_API_KEY or OPENROUTER_API_KEY:
                self.mode = LLMMode.API

        # When running in API mode without an explicit model override, pick a
        # sensible default + provider for whichever key is present.
        if self.mode == LLMMode.API and not os.getenv("CTI_API_MODEL"):
            if ANTHROPIC_API_KEY and not OPENAI_API_KEY and not OPENROUTER_API_KEY:
                # Explicit "anthropic/" prefix forces litellm to route to the
                # Anthropic provider even for model IDs newer than its registry.
                self.api_model = "anthropic/claude-opus-4-8"
            elif OPENROUTER_API_KEY and not OPENAI_API_KEY:
                # OpenRouter: cloud aggregator. Default to a strong free model;
                # _get_litellm_kwargs applies the "openrouter/" prefix + base_url.
                self.api_provider = "OpenRouter (Free)"
                self.api_model = "nvidia/nemotron-3-super-120b-a12b:free"
        # Honor an explicit provider override regardless of model default.
        if not self.api_provider and OPENROUTER_API_KEY and not (OPENAI_API_KEY or ANTHROPIC_API_KEY):
            self.api_provider = "OpenRouter (Free)"


# ── RAG Settings ─────────────────────────────────────────────────────
@dataclass
class RAGConfig:
    """Configuration for retrieval-augmented generation."""
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    index_type: str = "IndexFlatIP"   # Inner product similarity
    top_k: int = 5
    mmr_lambda: float = 0.7           # Diversity parameter (0 = full diversity, 1 = full relevance)
    chunk_size: int = 512
    chunk_overlap: int = 64
    cache_ttl_seconds: int = 3600     # 1 hour
    refresh_interval_hours: int = 24  # Auto-refresh FAISS from feeds
    retrieval_mode: RetrievalMode = RetrievalMode.HYBRID  # Default to hybrid for best results
    rrf_k: int = 60                   # Reciprocal Rank Fusion constant


# ── Guardrail Thresholds ────────────────────────────────────────────
@dataclass
class GuardrailConfig:
    """Thresholds for hallucination detection and STIX validation."""
    token_overlap_threshold: float = 0.4     # Minimum token overlap ratio
    nli_entailment_threshold: float = 0.7    # Minimum NLI entailment score
    stix_compliance_minimum: float = 0.9     # 90% field compliance required
    max_retries: int = 3
    escalation_enabled: bool = True          # Flag for human analyst review
    nli_model: str = "cross-encoder/nli-deberta-v3-small"


# ── Feed Sources ─────────────────────────────────────────────────────
@dataclass
class FeedConfig:
    """OSINT feed URLs and settings."""
    taxii_discovery: str = "https://cti-taxii.mitre.org/taxii2/"
    taxii_collection: str = "enterprise-attack"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/"
    malware_bazaar_url: str = "https://mb-api.abuse.ch/api/v1/"
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    rss_feeds: list[str] = field(default_factory=lambda: [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://krebsonsecurity.com/feed/",
        "https://www.darkreading.com/rss.xml",
    ])
    update_interval_hours: int = 24


# ── Personal Shield Settings ────────────────────────────────────────
@dataclass
class PersonalShieldConfig:
    """Settings for the personal protection advisor."""
    hygiene_check_interval_hours: int = 24
    max_score: int = 100
    risk_categories: list[str] = field(default_factory=lambda: [
        "password_strength",
        "mfa_enabled",
        "software_updates",
        "email_phishing_awareness",
        "network_security",
        "data_backup",
        "social_engineering_awareness",
        "browser_security",
        "device_encryption",
        "privacy_settings",
    ])
    family_mode: bool = False


# ── Master Configuration ────────────────────────────────────────────
@dataclass
class AppConfig:
    """Top-level configuration aggregating all sub-configs."""
    app_name: str = "CTI-Shield"
    version: str = "2.0.0"
    debug: bool = os.getenv("CTI_SHIELD_DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("CTI_SHIELD_LOG_LEVEL", "INFO")
    llm: LLMConfig = field(default_factory=LLMConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    guardrail: GuardrailConfig = field(default_factory=GuardrailConfig)
    feed: FeedConfig = field(default_factory=FeedConfig)
    personal_shield: PersonalShieldConfig = field(default_factory=PersonalShieldConfig)


# Singleton instance used throughout the app
settings = AppConfig()
