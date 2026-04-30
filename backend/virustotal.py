import requests
import os
import time
import base64
from dotenv import load_dotenv

load_dotenv()

try:
    import streamlit as st
    VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
except Exception:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"

_cache = {}

def _normalize(url: str):
    return url.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")

def _encode_url(url: str):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_virustotal(url: str):
    """
    Returns a dict:
    {
        "score": 0-10,
        "malicious": int,
        "suspicious": int,
        "harmless": int,
        "error": None or string reason
    }
    """
    if not VIRUSTOTAL_API_KEY:
        return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "no_key"}

    key = _normalize(url)

    if key in _cache:
        return _cache[key]

    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        encoded_url = _encode_url(url)

        post_resp = requests.post(
            VT_URL,
            headers=headers,
            data={"url": url},
            timeout=10
        )

        if post_resp.status_code == 429:
            return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "rate_limited"}

        if post_resp.status_code == 401:
            return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "invalid_key"}

        time.sleep(3)

        resp = requests.get(
            f"{VT_URL}/{encoded_url}",
            headers=headers,
            timeout=10
        )

        if resp.status_code != 200:
            return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": f"http_{resp.status_code}"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        score = (malicious * 2) + suspicious - (harmless * 0.2)
        score = max(0, min(score, 10))

        result = {
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "error": None
        }

        _cache[key] = result
        return result

    except requests.exceptions.Timeout:
        return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "connection_error"}
    except Exception as e:
        return {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": str(e)}
