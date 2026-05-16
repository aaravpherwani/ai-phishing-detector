"""
ai_reasoning.py
Gemini-powered reasoning layer. Only called for high-risk or ambiguous messages.
All logic lives in the backend — the frontend just displays the result.
"""

import os
import json
import hashlib
from functools import lru_cache

try:
    import streamlit as st
    GEMINI_API_KEY = (
        st.secrets.get("GEMINI_API_KEY")
        or os.getenv("GEMINI_API_KEY")
    )
except Exception:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# In-memory cache: hash(prompt + model_version) → result dict
_ai_cache: dict = {}
_CACHE_VERSION = "v11"

# Threshold: only invoke AI when combined rule score exceeds this
AI_INVOKE_THRESHOLD = 2


def should_invoke_ai(keyword_score: int, url_score: float) -> bool:
    """Return True if the message is risky or ambiguous enough to warrant AI."""
    return (keyword_score + url_score) >= AI_INVOKE_THRESHOLD


def _build_prompt(
    text: str,
    keyword_score: int,
    url_score: float,
    vt_results: list[dict],
    url_analyses: list[dict],
) -> str:
    # Compact URL flags — only include triggered ones
    url_lines = []
    for u in url_analyses:
        flags = []
        if u["uses_ip"]:          flags.append("IP-URL")
        if u["is_shortened"]:     flags.append("shortener")
        if u["suspicious_tld"]:   flags.append(f"bad-TLD{u['tld']}")
        if u["many_subdomains"]:  flags.append(f"{u['subdomain_count']}-subdomains")
        if u["brand_spoof"]:      flags.append(f"{u['brand_spoof']}-spoof")
        if u["is_http"]:          flags.append("http-only")
        if flags:
            url_lines.append(f"{u['domain']}: {', '.join(flags)}")

    vt_lines = []
    for i, vt in enumerate(vt_results):
        domain = url_analyses[i]["domain"] if i < len(url_analyses) else f"url{i+1}"
        if not vt.get("error"):
            if vt["malicious"] or vt["suspicious"]:
                vt_lines.append(f"{domain}: {vt['malicious']}mal {vt['suspicious']}sus")

    context_parts = [f"keyword_risk={keyword_score} url_risk={url_score:.1f}"]
    if url_lines:  context_parts.append("urls: " + "; ".join(url_lines))
    if vt_lines:   context_parts.append("vt: " + "; ".join(vt_lines))
    context = " | ".join(context_parts)

    prompt = f"""You are a cybersecurity analyst. Analyze this message for phishing or scams.

MESSAGE: {text[:500]}

SCORES: {context}

Respond with a single JSON object. No other text.
Fields:
- verdict: "PHISHING", "SUSPICIOUS", or "SAFE"
- confidence: number 0.0 to 1.0
- primary_threat: string under 4 words, or null
- key_indicators: array of exactly 2 strings, each under 5 words
- reasoning: one sentence under 25 words explaining the verdict in plain English"""

    return prompt


MODELS = [
    "gemini-2.5-flash",       # primary — 10 RPM free tier
    "gemini-2.5-flash-lite",  # fallback — 15 RPM, highest free throughput
]


def _call_gemini(prompt: str) -> dict | None:
    """
    Uses google-genai SDK with response_schema for guaranteed structured output.
    The SDK automatically filters Gemini 2.5 thought parts before parsing.
    Falls back through MODELS list on 429/503/404.
    """
    if not GEMINI_API_KEY:
        return None

    try:
        from google import genai as google_genai
        from google.genai import types
    except ImportError:
        return {"error": "missing_sdk"}

    client = google_genai.Client(api_key=GEMINI_API_KEY)

    response_schema = {
        "type": "OBJECT",
        "properties": {
            "verdict":        {"type": "STRING"},
            "confidence":     {"type": "NUMBER"},
            "primary_threat": {"type": "STRING"},
            "key_indicators": {"type": "ARRAY", "items": {"type": "STRING"}},
            "reasoning":      {"type": "STRING"},
        },
        "required": ["verdict", "confidence", "key_indicators", "reasoning"],
    }

    for model in MODELS:
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=600,
                    response_mime_type="application/json",
                    response_schema=response_schema,
                ),
            )

            raw = response.text.strip() if response.text else ""
            raw = raw.replace("```json", "").replace("```", "").strip()

            parsed = None
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                # Try extracting just the outermost JSON object
                brace_s = raw.find("{")
                brace_e = raw.rfind("}") + 1
                if brace_s != -1 and brace_e > brace_s:
                    try:
                        parsed = json.loads(raw[brace_s:brace_e])
                    except json.JSONDecodeError:
                        pass
                # Last resort: truncated JSON — try to recover verdict at least
                if not parsed and '"verdict"' in raw:
                    try:
                        v = raw.split('"verdict"')[1].split('"')[1]
                        parsed = {
                            "verdict": v,
                            "confidence": 0.8,
                            "reasoning": "Analysis complete (response truncated).",
                            "key_indicators": [],
                            "primary_threat": None,
                        }
                    except Exception:
                        pass

            if parsed and isinstance(parsed, dict):
                parsed["model"] = model
                return parsed

            return {
                "verdict": None, "reasoning": raw[:200],
                "key_indicators": [], "primary_threat": None,
                "confidence": None, "model": model,
                "error": "json_parse_failed",
            }

        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err.lower() or "503" in err:
                continue
            if "404" in err:
                continue
            return {"error": err[:100]}

    return {"error": "rate_limited"}


def get_ai_reasoning(
    text: str,
    keyword_score: int,
    url_score: float,
    vt_results: list[dict],
    url_analyses: list[dict],
) -> dict:
    """
    Main entry point. Returns a result dict:
    {
        "used": bool,           # whether AI was actually called
        "reasoning": str,       # human-readable explanation
        "verdict": str | None,
        "confidence": float | None,
        "primary_threat": str | None,
        "key_indicators": list[str],
        "error": str | None,
    }
    """
    if not should_invoke_ai(keyword_score, url_score):
        return {
            "used": False,
            "reasoning": None,
            "verdict": None,
            "confidence": None,
            "primary_threat": None,
            "key_indicators": [],
            "error": None,
        }

    if not GEMINI_API_KEY:
        return {
            "used": False,
            "reasoning": None,
            "verdict": None,
            "confidence": None,
            "primary_threat": None,
            "key_indicators": [],
            "error": "no_key",
        }

    prompt = _build_prompt(text, keyword_score, url_score, vt_results, url_analyses)

    # Cache by prompt hash
    cache_key = hashlib.md5(f"{_CACHE_VERSION}:{prompt}".encode()).hexdigest()
    if cache_key in _ai_cache:
        cached = _ai_cache[cache_key].copy()
        cached["used"] = True
        cached["cached"] = True
        return cached

    result = _call_gemini(prompt)

    if result is None:
        return {
            "used": False,
            "reasoning": None,
            "verdict": None,
            "confidence": None,
            "primary_threat": None,
            "key_indicators": [],
            "error": "no_key",
        }

    if "error" in result and result["error"] in ("rate_limited", "http_429"):
        return {
            "used": False,
            "reasoning": None,
            "verdict": None,
            "confidence": None,
            "primary_threat": None,
            "key_indicators": [],
            "error": "rate_limited",
        }

    output = {
        "used": True,
        "cached": False,
        "reasoning": result.get("reasoning"),
        "verdict": result.get("verdict"),
        "confidence": result.get("confidence"),
        "primary_threat": result.get("primary_threat"),
        "key_indicators": result.get("key_indicators", []),
        "model": result.get("model", "gemini"),
        "error": result.get("error") if "error" in result else None,
    }

    # If JSON failed but we have raw text as reasoning, clear the error
    # so the UI shows what it got rather than a failure message
    if output["error"] == "json_parse_failed" and output.get("reasoning"):
        r = output["reasoning"].strip()
        if not (r.startswith("{") or r.startswith("[")):
            output["error"] = None  # treat as partial success

    # Drop reasoning that looks cut off (doesn't end with punctuation)
    r = output.get("reasoning")
    if r and not r.rstrip().endswith((".", "!", "?")):
        output["reasoning"] = None

    _ai_cache[cache_key] = output
    return output
