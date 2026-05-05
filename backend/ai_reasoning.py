"""
ai_reasoning.py
Gemini-powered reasoning layer. Only called for high-risk or ambiguous messages.
All logic lives in the backend — the frontend just displays the result.
"""

import os
import json
import hashlib
import time
from functools import lru_cache

try:
    import streamlit as st
    GEMINI_API_KEY = (
        st.secrets.get("GEMINI_API_KEY")
        or os.getenv("GEMINI_API_KEY")
    )
except Exception:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# In-memory cache: hash(prompt) → result dict
_ai_cache: dict = {}

# Threshold: only invoke AI when combined rule score exceeds this
AI_INVOKE_THRESHOLD = 3


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
    vt_summary = []
    for i, vt in enumerate(vt_results):
        url_label = url_analyses[i]["domain"] if i < len(url_analyses) else f"URL {i+1}"
        if vt.get("error"):
            vt_summary.append(f"- {url_label}: VirusTotal check failed ({vt['error']})")
        else:
            vt_summary.append(
                f"- {url_label}: {vt['malicious']} malicious, "
                f"{vt['suspicious']} suspicious, {vt['harmless']} harmless vendors"
            )

    url_summary = []
    for u in url_analyses:
        flags = []
        if u["uses_ip"]:       flags.append("IP-based URL")
        if u["is_shortened"]:  flags.append("URL shortener")
        if u["suspicious_tld"]: flags.append(f"suspicious TLD ({u['tld']})")
        if u["many_subdomains"]: flags.append(f"{u['subdomain_count']} subdomains")
        if u["brand_spoof"]:   flags.append(f"possible {u['brand_spoof']} spoof")
        if u["is_http"]:       flags.append("non-HTTPS")
        flag_str = ", ".join(flags) if flags else "no major flags"
        url_summary.append(f"- {u['domain']}: {flag_str}")

    prompt = f"""You are a cybersecurity expert analyzing a potentially malicious message.

MESSAGE:
\"\"\"
{text[:2000]}
\"\"\"

AUTOMATED ANALYSIS SCORES:
- Keyword risk score: {keyword_score}/20+ (higher = more phishing language)
- URL risk score: {url_score:.1f}/10

URL ANALYSIS:
{chr(10).join(url_summary) if url_summary else "- No URLs detected"}

VIRUSTOTAL RESULTS:
{chr(10).join(vt_summary) if vt_summary else "- No URLs checked"}

Your task:
1. Write a clear, professional 2-4 sentence paragraph explaining WHY this message is or isn't suspicious. Write for a non-technical user. Do NOT use bullet points.
2. Then provide a JSON block with this exact structure:
{{
  "verdict": "PHISHING" | "SUSPICIOUS" | "SAFE",
  "confidence": 0.0-1.0,
  "primary_threat": "brief threat category or null",
  "key_indicators": ["indicator 1", "indicator 2"],  // max 3, each under 8 words
  "reasoning": "same paragraph as above"
}}

Output the paragraph first, then the JSON block. No other text."""

    return prompt


def _call_gemini(prompt: str) -> dict | None:
    """
    Call Gemini 1.5 Flash via REST API.
    Returns parsed result dict or None on failure.
    """
    if not GEMINI_API_KEY:
        return None

    import urllib.request
    import urllib.error

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    )

    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        code = e.code
        if code == 429:
            return {"error": "rate_limited"}
        if code == 400:
            return {"error": "invalid_request"}
        return {"error": f"http_{code}"}
    except Exception as e:
        return {"error": str(e)}

    try:
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        return {"error": "bad_response"}

    # Extract JSON block from response
    json_match = None
    brace_start = raw_text.rfind("{")
    brace_end = raw_text.rfind("}") + 1
    if brace_start != -1 and brace_end > brace_start:
        try:
            json_match = json.loads(raw_text[brace_start:brace_end])
        except json.JSONDecodeError:
            pass

    # Extract paragraph (text before the JSON block)
    paragraph = raw_text[:brace_start].strip() if brace_start != -1 else raw_text.strip()

    if json_match:
        json_match["reasoning"] = json_match.get("reasoning") or paragraph
        return json_match

    # Fallback: couldn't parse JSON, return raw paragraph
    return {
        "verdict": None,
        "reasoning": paragraph,
        "key_indicators": [],
        "primary_threat": None,
        "confidence": None,
        "error": "json_parse_failed",
    }


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
    cache_key = hashlib.md5(prompt.encode()).hexdigest()
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
        "error": result.get("error") if "error" in result else None,
    }

    _ai_cache[cache_key] = output
    return output
