"""
LLM Engine — Multi-LLM Dispatch
=================================
Five modes: DEMO (mock), LOCAL (downloaded HF model), OLLAMA (local server),
API (cloud LLMs), FULL (API + local side-by-side).

Ollama mode auto-detects installed models (Qwen3, LLaMA, etc.).
Qwen3 thinking tokens (<think>...</think>) are stripped automatically.
"""
from __future__ import annotations
import json, time, uuid, re
from datetime import datetime, timezone
from typing import Any, Optional
import structlog
from config import settings, LLMMode

logger = structlog.get_logger(__name__)

# ── Local HF Model Singleton ────────────────────────────────────────
_local_pipeline = None
_local_tokenizer = None

def _load_local_model():
    """Download and load the local HF model. Cached after first download."""
    global _local_pipeline, _local_tokenizer
    if _local_pipeline is not None:
        return _local_pipeline, _local_tokenizer
    
    model_name = settings.llm.local_hf_model
    logger.info("loading_local_model", model=model_name)
    
    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
        import torch
        
        tokenizer = AutoTokenizer.from_pretrained(
            model_name, trust_remote_code=True
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_name, 
            torch_dtype=torch.float32,  # CPU-friendly
            device_map="auto" if torch.cuda.is_available() else None,
            trust_remote_code=True,
        )
        
        pipe = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            max_new_tokens=512,
            temperature=0.3,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id if tokenizer.eos_token_id is not None else 0,  # type: ignore[union-attr]
        )
        
        _local_pipeline = pipe
        _local_tokenizer = tokenizer
        settings.llm.local_hf_loaded = True
        logger.info("local_model_loaded", model=model_name)
        return pipe, tokenizer
        
    except Exception as e:
        logger.error("local_model_load_failed", error=str(e))
        raise RuntimeError(f"Failed to load local model '{model_name}': {e}")


# ── Demo Mode Mock Responses ────────────────────────────────────────
DEMO_RESPONSES: dict[str, dict[str, Any]] = {
    "threat_analysis": {
        "summary": "This threat report describes a sophisticated spear-phishing campaign targeting financial institutions. The attack uses malicious Excel documents with embedded macros that download a second-stage payload from a command-and-control server.",
        "threat_actor": {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": "APT-DEMO-01",
            "description": "A sophisticated threat actor targeting financial institutions via spear-phishing.",
            "threat_actor_types": ["crime-syndicate"],
            "sophistication": "advanced",
            "resource_level": "organization",
            "primary_motivation": "financial-gain",
        },
        "ttps": [
            {"id": "T1566.001", "name": "Spear-phishing Attachment", "tactic": "Initial Access"},
            {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
            {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
        ],
        "severity": "Serious Threat",
        "iocs": {
            "domains": ["evil-c2.example.com"],
            "ips": ["198.51.100.42"],
            "hashes": ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"],
        },
    },
    "risk_assessment": {
        "risk_level": "Medium",
        "score": 65,
        "explanation": "This threat primarily targets corporate environments. Home users are at lower risk but should still update their software and be cautious of unexpected email attachments.",
        "actions": [
            "Update your antivirus software immediately",
            "Don't open unexpected email attachments",
            "Enable two-factor authentication on financial accounts",
            "Check your bank statements for unusual activity",
        ],
    },
    "daily_briefing": {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "threats": [
            {"title": "New Phishing Campaign", "severity": "Moderate", "summary": "A new wave of phishing emails impersonating banks."},
            {"title": "Critical Browser Update", "severity": "High", "summary": "Chrome and Firefox patches for zero-day vulnerability."},
            {"title": "Ransomware Alert", "severity": "High", "summary": "New ransomware variant targeting small businesses."},
        ],
        "tip_of_the_day": "Always verify sender email addresses before clicking links.",
    },
}

def _make_demo_stix_objects() -> list[dict[str, Any]]:
    """Generate demo STIX objects for the demo mode."""
    now = datetime.now(timezone.utc).isoformat()
    ta_id = f"threat-actor--{uuid.uuid4()}"
    mal_id = f"malware--{uuid.uuid4()}"
    ap_id = f"attack-pattern--{uuid.uuid4()}"
    return [
        {
            "type": "threat-actor", "spec_version": "2.1", "id": ta_id,
            "created": now, "modified": now, "name": "APT-DEMO-01",
            "description": "Demo threat actor", "threat_actor_types": ["crime-syndicate"],
        },
        {
            "type": "malware", "spec_version": "2.1", "id": mal_id,
            "created": now, "modified": now, "name": "DemoRAT",
            "description": "Demo remote access trojan", "malware_types": ["remote-access-trojan"],
            "is_family": True,
        },
        {
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": now, "modified": now, "name": "Spear Phishing",
            "description": "Targeted phishing with malicious attachments",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        },
        {
            "type": "relationship", "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}", "created": now, "modified": now,
            "relationship_type": "uses", "source_ref": ta_id, "target_ref": mal_id,
        },
    ]

# ── LLM Engine Class ────────────────────────────────────────────────
class LLMEngine:
    """Multi-mode LLM engine for CTI analysis."""

    def __init__(self) -> None:
        self.mode = settings.llm.mode
        self.metrics: list[dict[str, Any]] = []
        self._last_model: str = ""

    def analyse_threat(self, text: str, context: str = "") -> dict[str, Any]:
        """Analyse a threat report and return structured output."""
        start = time.time()
        if self.mode == LLMMode.DEMO:
            result = self._demo_analyse(text, context)
        elif self.mode == LLMMode.LOCAL:
            result = self._local_hf_analyse(text, context)
        elif self.mode == LLMMode.OLLAMA:
            result = self._ollama_analyse(text, context)
        elif self.mode == LLMMode.API:
            result = self._api_analyse(text, context)
        else:
            result = self._full_analyse(text, context)
        result["latency_ms"] = round((time.time() - start) * 1000, 1)
        result["mode"] = self.mode.value
        self.metrics.append({"type": "analyse", "latency_ms": result["latency_ms"], "mode": self.mode.value})
        return result

    def generate_response(self, prompt: str, context: str = "") -> str:
        """Generate a free-form response."""
        start = time.time()
        if self.mode == LLMMode.DEMO:
            response = self._demo_generate(prompt)
        elif self.mode == LLMMode.LOCAL:
            response = self._local_hf_generate(prompt, context)
        elif self.mode == LLMMode.OLLAMA:
            response = self._ollama_generate(prompt, context)
        elif self.mode == LLMMode.API:
            response = self._api_generate(prompt, context)
        else:
            response = self._full_generate(prompt, context)
        latency = round((time.time() - start) * 1000, 1)
        self.metrics.append({"type": "generate", "latency_ms": latency, "mode": self.mode.value})
        return response

    def get_stix_objects(self, text: str, context: str = "") -> list[dict[str, Any]]:
        """Generate STIX 2.1 objects from threat text."""
        if self.mode == LLMMode.DEMO:
            return _make_demo_stix_objects()
        if self.mode == LLMMode.API:
            return self._api_get_stix(text, context)
        # OLLAMA / LOCAL / FULL: generate STIX with the same backend the rest of
        # the pipeline uses, instead of always falling back to the cloud API.
        prompt = (
            "Extract STIX 2.1 objects from this threat report. Return ONLY a valid JSON array.\n\n"
            f"Context: {context}\n\nReport: {text}"
        )
        try:
            response = self.generate_response(prompt, "")
            objs = json.loads(response)
            return objs if isinstance(objs, list) else _make_demo_stix_objects()
        except (json.JSONDecodeError, Exception):
            return _make_demo_stix_objects()

    # ── Demo Mode ────────────────────────────────────────────────────
    def _demo_analyse(self, text: str, context: str) -> dict[str, Any]:
        """Context-aware demo analysis that detects threat type from input."""
        text_lower = text.lower()
        
        # Detect phishing / scam / social engineering
        phishing_signals = [
            "payment", "account", "verify", "urgent", "suspended",
            "bank transfer", "acc number", "click here", "litigation",
            "tuition", "invoice", "overdue", "debt", "settlement",
            "proof of payment", "regularized", "disregard this",
        ]
        phishing_score = sum(1 for s in phishing_signals if s in text_lower)
        
        # Detect ransomware
        ransom_signals = ["encrypt", "ransom", "bitcoin", "decrypt", "locked files", "payment demand"]
        ransom_score = sum(1 for s in ransom_signals if s in text_lower)
        
        if phishing_score >= 3:
            analysis = self._demo_phishing_analysis(text)
        elif ransom_score >= 2:
            analysis = self._demo_ransomware_analysis(text)
        else:
            analysis = DEMO_RESPONSES["threat_analysis"]
        
        return {
            "analysis": analysis,
            "stix_objects": _make_demo_stix_objects(),
            "context_used": context[:200] if context else "No context (demo mode)",
        }

    def _demo_phishing_analysis(self, text: str) -> dict[str, Any]:
        """Generate a phishing-specific demo analysis."""
        # Extract IOCs from the text
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}", text)
        accounts = re.findall(r"\b\d{10,16}\b", text)
        
        return {
            "summary": (
                "⚠️ This message shows strong indicators of a PHISHING / SCAM email. "
                "It uses urgency ('litigation department'), financial pressure ('payment overdue'), "
                "and requests a bank transfer to an unverified account. Legitimate institutions "
                "do NOT request payments via personal email with bank account details. "
                "This is a social engineering attack designed to steal your money."
            ),
            "threat_type": "Phishing / Financial Scam",
            "ttps": [
                {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
                {"id": "T1078", "name": "Valid Accounts (Credential Harvest)", "tactic": "Persistence"},
                {"id": "T1534", "name": "Internal Spearphishing", "tactic": "Lateral Movement"},
            ],
            "severity": "Serious Threat",
            "iocs": {
                "emails": emails,
                "accounts": accounts,
            },
            "red_flags": [
                "Requests bank transfer to a personal-style account",
                "Uses urgency and legal threats to pressure action",
                "Generic greeting instead of your actual name",
                "Asks to send 'proof of payment' to an email address",
                "Bank account details provided directly in the email",
                "Unusual bank name or account format",
            ],
        }

    def _demo_ransomware_analysis(self, text: str) -> dict[str, Any]:
        """Generate a ransomware-specific demo analysis."""
        return {
            "summary": (
                "🔴 This appears to be related to a RANSOMWARE attack. "
                "Ransomware encrypts your files and demands payment (often in Bitcoin) "
                "for the decryption key. Do NOT pay the ransom — there is no guarantee "
                "your files will be recovered. Contact law enforcement immediately."
            ),
            "threat_type": "Ransomware",
            "ttps": [
                {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
                {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
            ],
            "severity": "Emergency",
            "red_flags": [
                "Files have been encrypted or renamed",
                "Ransom note demanding cryptocurrency payment",
                "Threat of data publication or deletion",
            ],
        }

    def _demo_generate(self, prompt: str) -> str:
        if "risk" in prompt.lower() or "protect" in prompt.lower():
            return json.dumps(DEMO_RESPONSES["risk_assessment"], indent=2)
        if "brief" in prompt.lower() or "daily" in prompt.lower():
            return json.dumps(DEMO_RESPONSES["daily_briefing"], indent=2)
        return (
            "🛡️ **CTI-Shield Demo Response**\n\n"
            "This is a demonstration response. In API or Full mode, this would be "
            "generated by GPT-4o, Claude, or a local LLM.\n\n"
            f"Your query: {prompt[:200]}\n\n"
            "To enable live AI analysis, set your API key in the .env file and "
            "switch to API mode in the settings."
        )

    # ── Local HF Mode (Downloaded Model) ─────────────────────────────
    def _local_hf_analyse(self, text: str, context: str) -> dict[str, Any]:
        """Analyse using the downloaded local HuggingFace model."""
        try:
            pipe, tokenizer = _load_local_model()
            self._last_model = settings.llm.local_hf_model
            
            system_msg = (
                "You are a cybersecurity threat analyst. Analyse the threat report below. "
                "Identify: 1) Threat type 2) Severity (Everyday Risk/Moderate Concern/Serious Threat/Emergency) "
                "3) TTPs mapped to MITRE ATT&CK 4) Red flags 5) IOCs. Be concise and factual."
            )
            user_msg = f"Threat Report:\n{text[:1500]}"
            
            # Build chat prompt
            if hasattr(tokenizer, 'apply_chat_template'):
                messages = [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ]
                prompt_text = tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
            else:
                prompt_text = f"<|system|>\n{system_msg}\n<|user|>\n{user_msg}\n<|assistant|>\n"
            
            outputs = pipe(
                str(prompt_text),
                max_new_tokens=512,
                temperature=max(0.1, settings.llm.temperature),
                do_sample=True,
                return_full_text=False,
            )
            
            raw_output = outputs[0]["generated_text"].strip()
            
            # Parse the raw LLM output into structured format
            analysis = self._parse_local_output(raw_output, text)
            
            return {
                "analysis": analysis,
                "stix_objects": [],
                "raw_response": raw_output,
                "context_used": context[:200] if context else "",
                "local_model": settings.llm.local_hf_model,
            }
            
        except Exception as e:
            logger.error("local_hf_analyse_failed", error=str(e))
            return {
                "analysis": {"summary": f"Local model error: {e}", "severity": "Unknown"},
                "stix_objects": [],
                "error": str(e),
            }

    def _local_hf_generate(self, prompt: str, context: str = "") -> str:
        """Generate free-form response using local HF model."""
        try:
            pipe, tokenizer = _load_local_model()
            
            full_prompt = f"{context}\n\n{prompt}" if context else prompt
            
            if hasattr(tokenizer, 'apply_chat_template'):
                messages = [{"role": "user", "content": full_prompt[:2000]}]
                prompt_text = tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
            else:
                prompt_text = full_prompt[:2000]
            
            outputs = pipe(
                str(prompt_text),
                max_new_tokens=512,
                temperature=max(0.1, settings.llm.temperature),
                do_sample=True,
                return_full_text=False,
            )
            return outputs[0]["generated_text"].strip()
            
        except Exception as e:
            return f"Local model error: {e}"

    def _parse_local_output(self, raw: str, original_text: str) -> dict[str, Any]:
        """Parse raw LLM output into structured threat analysis."""
        text_lower = original_text.lower()
        
        # Detect severity from LLM output or original text
        raw_lower = raw.lower()
        if any(w in raw_lower for w in ["emergency", "critical", "ransomware", "zero-day"]):
            severity = "Emergency"
        elif any(w in raw_lower for w in ["serious", "high", "severe", "apt", "advanced"]):
            severity = "Serious Threat"
        elif any(w in raw_lower for w in ["moderate", "medium", "suspicious"]):
            severity = "Moderate Concern"
        else:
            severity = "Moderate Concern"
        
        # Extract TTPs from the response
        ttp_matches = re.findall(r'T(\d{4}(?:\.\d{3})?)', raw)
        ttps = []
        from agents.kg_builder import ATTACK_TECHNIQUE_MAP
        for tid in set(ttp_matches):
            full_id = f"T{tid}"
            if full_id in ATTACK_TECHNIQUE_MAP:
                ttps.append({
                    "id": full_id,
                    "name": ATTACK_TECHNIQUE_MAP[full_id],
                    "tactic": "See ATT&CK",
                })
        
        # Extract IOCs from original text
        iocs = {}
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', original_text)
        if ips: iocs["ips"] = list(set(ips))
        domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn)\b', original_text.lower())
        if domains: iocs["domains"] = list(set(domains))
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', original_text)
        if cves: iocs["cves"] = list(set(cves))
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}", original_text)
        if emails: iocs["emails"] = list(set(emails))
        
        # Extract red flags from the LLM output
        red_flags = []
        for line in raw.split("\n"):
            line = line.strip()
            if line.startswith(("-", "*", "•")) and len(line) > 10:
                flag = line.lstrip("-*• ").strip()
                if flag and len(flag) < 200:
                    red_flags.append(flag)
        
        return {
            "summary": raw[:500] if raw else "Analysis generated by local model.",
            "severity": severity,
            "ttps": ttps if ttps else [
                {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
            ],
            "iocs": iocs,
            "red_flags": red_flags[:6] if red_flags else ["Review the analysis above for detailed findings"],
            "threat_type": "Analysed by Local LLM",
        }

    # ── Ollama Mode (Local Ollama Server: Qwen3, LLaMA, etc.) ────────
    @staticmethod
    def _strip_thinking_tokens(text: str) -> str:
        """Strip Qwen3 <think>...</think> reasoning tokens from output.

        Qwen3 produces internal reasoning wrapped in <think> blocks.
        These are useful for debugging but should not appear in CTI reports.
        """
        import re as _re
        # Remove <think>...</think> blocks (including multiline)
        cleaned = _re.sub(r'<think>.*?</think>', '', text, flags=_re.DOTALL)
        return cleaned.strip()

    def _ollama_analyse(self, text: str, context: str) -> dict[str, Any]:
        """Analyse using a local model served by Ollama."""
        try:
            import litellm
            model_name = f"ollama/{settings.llm.ollama_model}"
            self._last_model = model_name

            system_prompt = (
                "You are a cybersecurity threat analyst. Analyse the threat report below. "
                "Identify: 1) Threat type 2) Severity (Everyday Risk/Moderate Concern/Serious Threat/Emergency) "
                "3) TTPs mapped to MITRE ATT&CK (use T-codes like T1566.001) "
                "4) Red flags 5) IOCs (IPs, domains, hashes, CVEs). Be concise and factual. "
                "Return structured analysis."
            )
            user_prompt = f"Context:\n{context[:500]}\n\nThreat Report:\n{text[:2000]}"

            response = litellm.completion(  # type: ignore[operator]
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                api_base=settings.llm.ollama_base_url,
                temperature=settings.llm.temperature,
                max_tokens=settings.llm.max_tokens,
                timeout=settings.llm.timeout_seconds,
            )
            raw_output = response.choices[0].message.content.strip()  # type: ignore[union-attr]
            raw_output = self._strip_thinking_tokens(raw_output)
            analysis = self._parse_local_output(raw_output, text)

            return {
                "analysis": analysis,
                "stix_objects": [],
                "raw_response": raw_output,
                "context_used": context[:200] if context else "",
                "ollama_model": settings.llm.ollama_model,
            }

        except Exception as e:
            logger.error("ollama_analyse_failed", error=str(e), model=settings.llm.ollama_model)
            return {
                "analysis": {
                    "summary": f"Ollama model error: {e}. Make sure Ollama is running (open /Applications/Ollama.app)",
                    "severity": "Unknown",
                },
                "stix_objects": [],
                "error": str(e),
            }

    def _ollama_generate(self, prompt: str, context: str = "") -> str:
        """Generate free-form response using Ollama."""
        try:
            import litellm
            model_name = f"ollama/{settings.llm.ollama_model}"
            full_prompt = f"{context}\n\n{prompt}" if context else prompt

            response = litellm.completion(  # type: ignore[operator]
                model=model_name,
                messages=[{"role": "user", "content": full_prompt[:3000]}],
                api_base=settings.llm.ollama_base_url,
                temperature=settings.llm.temperature,
                max_tokens=settings.llm.max_tokens,
            )
            return self._strip_thinking_tokens(
                response.choices[0].message.content.strip()  # type: ignore[union-attr]
            )

        except Exception as e:
            return f"Ollama model error: {e}. Make sure Ollama is running."

    # ── API Mode ─────────────────────────────────────────────────────
    def _get_litellm_kwargs(self) -> dict[str, Any]:
        """Build litellm call kwargs based on the selected provider."""
        from config import FREE_LLM_PROVIDERS
        import os

        kwargs: dict[str, Any] = {}
        provider_name = settings.llm.api_provider
        model = settings.llm.api_model

        if provider_name and provider_name in FREE_LLM_PROVIDERS:
            provider = FREE_LLM_PROVIDERS[provider_name]
            base_url = provider.get("base_url", "")
            prefix = provider.get("prefix", "")
            env_var = provider.get("env_var", "")

            # Set model with litellm prefix
            if prefix and not model.startswith(prefix):
                kwargs["model"] = f"{prefix}{model}"
            else:
                kwargs["model"] = model

            # Set base URL
            if base_url:
                kwargs["api_base"] = base_url

            # Set API key from env var
            if env_var:
                api_key = os.getenv(env_var, "")
                if api_key:
                    kwargs["api_key"] = api_key
        else:
            kwargs["model"] = model

            # Use custom base URL if set directly
            if settings.llm.api_base_url:
                kwargs["api_base"] = settings.llm.api_base_url

        return kwargs

    def _api_analyse(self, text: str, context: str) -> dict[str, Any]:
        system_prompt = (
            "You are a Cyber Threat Intelligence analyst. Analyse the following threat report "
            "and produce: 1) A summary, 2) Identified TTPs mapped to MITRE ATT&CK, "
            "3) STIX 2.1 objects in JSON, 4) Severity assessment. "
            "Use ONLY the provided context for factual claims."
        )
        user_prompt = f"Context:\n{context}\n\nThreat Report:\n{text}"
        try:
            response = self._completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=settings.llm.temperature,
                max_tokens=settings.llm.max_tokens,
                timeout=settings.llm.timeout_seconds,
                num_retries=settings.llm.max_retries,
            )
            content = response.choices[0].message.content  # type: ignore[union-attr]
            return {"analysis": content, "stix_objects": [], "raw_response": content}
        except Exception as e:
            logger.error("API call failed", error=str(e))
            from cti_shield.model_rotator import strict_mode
            if strict_mode():
                raise
            return {"analysis": f"API Error: {e}", "stix_objects": [], "error": str(e)}

    def _completion(self, **call_kwargs):
        """Single choke point for hosted-API calls.

        On the OpenRouter free tier this routes through the free-model
        auto-switcher (cti_shield/model_rotator.py): when the active model
        is rate-limited or out of free quota, the call transparently moves
        to the next free model and the run continues. Other providers call
        litellm directly, unchanged.
        """
        import litellm
        llm_kwargs = self._get_litellm_kwargs()
        self._last_model = llm_kwargs.get("model", "unknown")
        if settings.llm.api_provider == "OpenRouter (Free)":
            from cti_shield.model_rotator import completion_with_rotation
            resp = completion_with_rotation(llm_kwargs, **call_kwargs)
            self._last_model = f"openrouter/{settings.llm.api_model}"
            return resp
        return litellm.completion(**llm_kwargs, **call_kwargs)  # type: ignore[operator]

    def _api_generate(self, prompt: str, context: str) -> str:
        try:
            messages = [{"role": "user", "content": f"Context:\n{context}\n\n{prompt}" if context else prompt}]
            response = self._completion(
                messages=messages,
                temperature=settings.llm.temperature, max_tokens=settings.llm.max_tokens,
                timeout=settings.llm.timeout_seconds, num_retries=settings.llm.max_retries,
            )
            return response.choices[0].message.content  # type: ignore[union-attr]
        except Exception as e:
            from cti_shield.model_rotator import strict_mode
            if strict_mode():
                raise
            return f"API Error: {e}"

    def _api_get_stix(self, text: str, context: str) -> list[dict[str, Any]]:
        prompt = (
            "Extract STIX 2.1 objects from this threat report. Return ONLY valid JSON array.\n\n"
            f"Context: {context}\n\nReport: {text}"
        )
        response = self._api_generate(prompt, "")
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return _make_demo_stix_objects()

    # ── Full Mode ────────────────────────────────────────────────────
    def _full_analyse(self, text: str, context: str) -> dict[str, Any]:
        api_result = self._api_analyse(text, context)
        local_result = self._local_analyse(text, context)
        return {
            "api_result": api_result,
            "local_result": local_result,
            "comparison": self._compare_results(api_result, local_result),
        }

    def _full_generate(self, prompt: str, context: str) -> str:
        api_resp = self._api_generate(prompt, context)
        local_resp = self._local_generate(prompt, context)
        return f"## Cloud Model\n{api_resp}\n\n## Local Model\n{local_resp}"

    def _local_analyse(self, text: str, context: str) -> dict[str, Any]:
        try:
            import litellm
            response = litellm.completion(  # type: ignore[operator]
                model=settings.llm.local_model,
                messages=[{"role": "user", "content": f"Analyse: {text[:2000]}"}],
                api_base=settings.llm.ollama_base_url,
                temperature=settings.llm.temperature,
            )
            return {"analysis": response.choices[0].message.content}  # type: ignore[union-attr]
        except Exception as e:
            return {"analysis": f"Local model error: {e}", "error": str(e)}

    def _local_generate(self, prompt: str, context: str) -> str:
        try:
            import litellm
            response = litellm.completion(  # type: ignore[operator]
                model=settings.llm.local_model,
                messages=[{"role": "user", "content": prompt}],
                api_base=settings.llm.ollama_base_url,
            )
            return response.choices[0].message.content  # type: ignore[union-attr]
        except Exception as e:
            return f"Local model error: {e}"

    def _compare_results(self, api: dict, local: dict) -> dict[str, Any]:
        return {
            "consistency_note": "Cross-model comparison available in Full mode",
            "api_available": "error" not in api,
            "local_available": "error" not in local,
        }

# Singleton
_engine: LLMEngine | None = None

def get_engine() -> LLMEngine:
    global _engine
    if _engine is None:
        _engine = LLMEngine()
    return _engine

def reset_engine() -> None:
    """Reset the engine singleton so it picks up new settings."""
    global _engine
    _engine = None

