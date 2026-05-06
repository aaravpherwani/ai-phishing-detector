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
_CACHE_VERSION = "v5"

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
    if url_lines:
        context_parts.append("urls: " + "; ".join(url_lines))
    if vt_lines:
        context_parts.append("virustotal: " + "; ".join(vt_lines))
    context = " | ".join(context_parts)

    prompt = f"""Cybersecurity analyst. Analyze this message for phishing/scams.

MESSAGE (first 800 chars): {text[:800]}

SCORES: {context}

Respond with ONLY this JSON (no other text, no markdown):
{{"verdict":"PHISHING"|"SUSPICIOUS"|"SAFE","confidence":0.0-1.0,"primary_threat":"<5 words or null","key_indicators":["<6 words","<6 words"],"reasoning":"<2 sentences max, plain English, non-technical user"}}

Rules: reasoning max 40 words. key_indicators max 2 items. Be decisive."""

    return prompt


MODELS = [
    "gemini-2.5-flash",       # primary — 10 RPM free tier
    "gemini-2.5-flash-lite",  # fallback — 15 RPM, highest free throughput
]


def _call_gemini(prompt: str) -> dict | None:
    """
    Try each model in order. On 429 immediately tries next model (no sleep).
    Returns parsed result dict or None on failure.
    """
    if not GEMINI_API_KEY:
        return None

    import urllib.request
    import urllib.error

    for model in MODELS:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={GEMINI_API_KEY}"
        )
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 300,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

            # Strip markdown fences if model adds them anyway
            raw_text = raw_text.replace("```json", "").replace("```", "").strip()

            # Find outermost JSON object
            brace_start = raw_text.find("{")
            brace_end   = raw_text.rfind("}") + 1
            json_match  = None
            if brace_start != -1 and brace_end > brace_start:
                try:
                    json_match = json.loads(raw_text[brace_start:brace_end])
                except json.JSONDecodeError:
                    pass

            if json_match:
                json_match["model"] = model
                return json_match

            # Fallback: return raw text as reasoning if JSON failed
            return {
                "verdict": None,
                "reasoning": raw_text[:300],
                "key_indicators": [],
                "primary_threat": None,
                "confidence": None,
                "model": model,
                "error": "json_parse_failed",
            }

        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                continue  # rate limited or overloaded → try next model
            if e.code == 404:
                continue  # model not found → try next
            return {"error": f"http_{e.code}"}
        except Exception as e:
            return {"error": str(e)}

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

    _ai_cache[cache_key] = output
    return output
