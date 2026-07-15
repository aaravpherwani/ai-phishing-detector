import base64
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

try:
    import streamlit as st

    VIRUSTOTAL_API_KEY = (
        st.secrets.get("VIRUSTOTAL_API_KEY")
        or os.getenv("VIRUSTOTAL_API_KEY")
    )
except Exception:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"

# Cache reports in memory. Known reports rarely change quickly, while failed or
# queued requests are cached briefly to avoid repeatedly calling VirusTotal.
_cache = {}
CACHE_TTL_SECONDS = {
    "clean": 24 * 60 * 60,
    "mixed": 6 * 60 * 60,
    "malicious": 6 * 60 * 60,
    "queued": 5 * 60,
    "error": 60,
}
MAX_CACHE_ENTRIES = 500


def _empty_result(error=None, status="unavailable"):
    return {
        "score": 0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "error": error,
        "status": status,
        "checked": False,
        "cached": False,
    }


def _normalize(url):
    return (
        url.strip()
        .lower()
        .replace("http://", "")
        .replace("https://", "")
        .rstrip("/")
    )


def _encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _get_cached(key):
    cached_item = _cache.get(key)

    if not cached_item:
        return None

    expires_at, result = cached_item

    if time.time() >= expires_at:
        del _cache[key]
        return None

    cached_result = result.copy()
    cached_result["cached"] = True
    return cached_result


def _store_cached(key, result):
    if len(_cache) >= MAX_CACHE_ENTRIES:
        oldest_key = next(iter(_cache))
        del _cache[oldest_key]

    ttl = CACHE_TTL_SECONDS.get(result.get("status"), CACHE_TTL_SECONDS["error"])
    _cache[key] = (time.time() + ttl, result.copy())


def _result_from_stats(stats):
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))

    # Do not subtract harmless votes from risk: a mixed reputation is still
    # uncertain, not clean. The confidence guardrail handles the contradiction.
    score = min((malicious * 3) + (suspicious * 1.5), 10)

    if malicious > 0 and harmless > 0:
        status = "mixed"
    elif suspicious > 0 and harmless > 0:
        status = "mixed"
    elif malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "mixed"
    else:
        status = "clean"

    return {
        "score": score,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "error": None,
        "status": status,
        "checked": True,
        "cached": False,
    }


def check_virustotal(url):
    """
    Look up an existing VirusTotal report without waiting for a new scan.

    If no report exists, submit the URL once and return immediately with
    status='queued'. A later analysis can retrieve the completed report.
    """
    if not VIRUSTOTAL_API_KEY:
        return _empty_result("no_key")

    key = _normalize(url)
    cached_result = _get_cached(key)

    if cached_result is not None:
        return cached_result

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    encoded_url = _encode_url(url)

    try:
        # Fast path: existing report. This is normally one request and has no
        # fixed sleep or polling delay.
        report_response = requests.get(
            f"{VT_URL}/{encoded_url}",
            headers=headers,
            timeout=6,
        )

        if report_response.status_code == 200:
            data = report_response.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            result = _result_from_stats(stats)
            _store_cached(key, result)
            return result

        if report_response.status_code == 401:
            return _empty_result("invalid_key", "error")

        if report_response.status_code == 429:
            return _empty_result("rate_limited", "error")

        if report_response.status_code != 404:
            return _empty_result(
                f"http_{report_response.status_code}",
                "error",
            )

        # No existing report: submit once, but never block waiting for the
        # analysis to finish. The short queued cache prevents repeat submits.
        submit_response = requests.post(
            VT_URL,
            headers=headers,
            data={"url": url},
            timeout=6,
        )

        if submit_response.status_code in (200, 201):
            result = _empty_result(None, "queued")
            _store_cached(key, result)
            return result

        if submit_response.status_code == 401:
            return _empty_result("invalid_key", "error")

        if submit_response.status_code == 429:
            return _empty_result("rate_limited", "error")

        return _empty_result(f"http_{submit_response.status_code}", "error")

    except requests.exceptions.Timeout:
        return _empty_result("timeout", "error")
    except requests.exceptions.ConnectionError:
        return _empty_result("connection_error", "error")
    except Exception:
        return _empty_result("request_error", "error")
