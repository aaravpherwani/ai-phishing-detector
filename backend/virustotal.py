"""Fast, cached VirusTotal lookups for PhishGuard.

A report is scored from observed vendor votes only:
    score_10 = 10 * (malicious + 0.5 * suspicious) /
               (malicious + suspicious + harmless)

Undetected/timeout vendors are not votes and are excluded from the denominator.
A missing report, queued scan, API failure, and zero-vote report are never
represented as a clean result.
"""
import base64
import json
import os
import sqlite3
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv

load_dotenv()

try:
    import streamlit as st
    VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
except Exception:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"
REQUEST_TIMEOUT = (2.5, 4.0)
MAX_CACHE_ENTRIES = 5000
CACHE_DB_PATH = os.getenv("PHISHGUARD_CACHE_DB", "/tmp/phishguard_vt_cache.sqlite3")

CACHE_TTL_SECONDS = {
    "clean": 24 * 60 * 60,
    "mixed": 4 * 60 * 60,
    "malicious": 4 * 60 * 60,
    "insufficient": 10 * 60,
    "queued": 20,
    "error": 20,
}

_memory_cache = {}
_cache_lock = threading.RLock()
_db_initialized = False


def _empty_result(error=None, status="unavailable"):
    return {
        "score": 0.0,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_votes": 0,
        "analysis_id": None,
        "error": error,
        "status": status,
        "checked": False,
        "cached": False,
    }


def _normalize(url):
    """Canonicalize scheme/host without lowercasing case-sensitive URL paths."""
    value = (url or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        if not host:
            return value
        port = parts.port
        netloc = host
        if port and not ((parts.scheme.lower() == "https" and port == 443) or
                         (parts.scheme.lower() == "http" and port == 80)):
            netloc = f"{host}:{port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    except (TypeError, ValueError):
        return value


def _encode_url(url):
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _connect_db():
    connection = sqlite3.connect(CACHE_DB_PATH, timeout=2.0)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS vt_cache (
            cache_key TEXT PRIMARY KEY,
            expires_at REAL NOT NULL,
            result_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        )"""
    )
    return connection


def _init_db():
    global _db_initialized
    if _db_initialized:
        return
    with _cache_lock:
        if _db_initialized:
            return
        try:
            with _connect_db():
                pass
            _db_initialized = True
        except (OSError, sqlite3.Error):
            # Memory cache remains available on read-only or ephemeral hosts.
            _db_initialized = False


def _get_cached(key):
    now = time.time()
    with _cache_lock:
        item = _memory_cache.get(key)
        if item:
            expires_at, result = item
            if now < expires_at:
                cached = result.copy()
                cached["cached"] = True
                return cached
            _memory_cache.pop(key, None)

    _init_db()
    try:
        with _connect_db() as connection:
            row = connection.execute(
                "SELECT expires_at, result_json FROM vt_cache WHERE cache_key=?",
                (key,),
            ).fetchone()
            if not row:
                return None
            if now >= row[0]:
                connection.execute("DELETE FROM vt_cache WHERE cache_key=?", (key,))
                return None
            result = json.loads(row[1])
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return None

    with _cache_lock:
        _memory_cache[key] = (row[0], result)
    cached = result.copy()
    cached["cached"] = True
    return cached


def _store_cached(key, result):
    ttl = CACHE_TTL_SECONDS.get(result.get("status"), CACHE_TTL_SECONDS["error"])
    expires_at = time.time() + ttl
    clean_result = result.copy()
    clean_result["cached"] = False

    with _cache_lock:
        _memory_cache[key] = (expires_at, clean_result)
        while len(_memory_cache) > MAX_CACHE_ENTRIES:
            _memory_cache.pop(next(iter(_memory_cache)), None)

    _init_db()
    try:
        with _connect_db() as connection:
            connection.execute(
                """INSERT INTO vt_cache(cache_key, expires_at, result_json, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(cache_key) DO UPDATE SET
                       expires_at=excluded.expires_at,
                       result_json=excluded.result_json,
                       updated_at=excluded.updated_at""",
                (key, expires_at, json.dumps(clean_result), time.time()),
            )
            connection.execute(
                """DELETE FROM vt_cache WHERE cache_key IN (
                       SELECT cache_key FROM vt_cache
                       ORDER BY updated_at DESC LIMIT -1 OFFSET ?
                   )""",
                (MAX_CACHE_ENTRIES,),
            )
    except (OSError, sqlite3.Error, TypeError, ValueError):
        # A cache failure must never fail the phishing analysis.
        pass


def _as_count(stats, name):
    try:
        return max(0, int(stats.get(name, 0) or 0))
    except (TypeError, ValueError):
        return 0


def _result_from_stats(stats):
    malicious = _as_count(stats, "malicious")
    suspicious = _as_count(stats, "suspicious")
    harmless = _as_count(stats, "harmless")
    total_votes = malicious + suspicious + harmless

    if total_votes == 0:
        result = _empty_result("insufficient_votes", "insufficient")
        result.update({
            "checked": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_votes": 0,
        })
        return result

    score = round(10.0 * (malicious + 0.5 * suspicious) / total_votes, 2)
    if malicious > 0 or suspicious > 0:
        status = "mixed" if harmless > 0 else "malicious"
    else:
        status = "clean"

    return {
        "score": min(10.0, max(0.0, score)),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_votes": total_votes,
        "error": None,
        "status": status,
        "checked": True,
        "cached": False,
    }


def _poll_analysis(analysis_id, headers):
    """Poll a submitted analysis once; never sleep or busy-wait."""
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            attributes = response.json().get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                return _result_from_stats(attributes.get("stats") or {})
            queued = _empty_result(None, "queued")
            queued["analysis_id"] = analysis_id
            return queued
        if response.status_code == 429:
            return _empty_result("rate_limited", "error")
        return _empty_result(f"http_{response.status_code}", "error")
    except requests.exceptions.Timeout:
        return _empty_result("timeout", "error")
    except requests.exceptions.RequestException:
        return _empty_result("connection_error", "error")


def check_virustotal(url):
    """Return cached reputation, poll a queued scan once, or submit a new scan."""
    if not VIRUSTOTAL_API_KEY:
        return _empty_result("no_key")

    normalized = _normalize(url)
    if not normalized:
        return _empty_result("invalid_url", "error")

    cached_result = _get_cached(normalized)
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    if cached_result is not None:
        if cached_result.get("status") != "queued":
            return cached_result
        analysis_id = cached_result.get("analysis_id")
        if not analysis_id:
            return cached_result
        polled = _poll_analysis(analysis_id, headers)
        _store_cached(normalized, polled)
        return polled
    encoded_url = _encode_url(normalized)

    try:
        response = requests.get(
            f"{VT_URL}/{encoded_url}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 200:
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            result = _result_from_stats(attributes.get("last_analysis_stats") or {})
            _store_cached(normalized, result)
            return result

        if response.status_code == 401:
            return _empty_result("invalid_key", "error")
        if response.status_code == 429:
            return _empty_result("rate_limited", "error")
        if response.status_code not in (404,):
            return _empty_result(f"http_{response.status_code}", "error")

        # Submit once; don't wait for VirusTotal's asynchronous analysis.
        submit = requests.post(
            VT_URL,
            headers=headers,
            data={"url": normalized},
            timeout=REQUEST_TIMEOUT,
        )
        if submit.status_code in (200, 201):
            analysis_id = submit.json().get("data", {}).get("id")
            result = _empty_result(None, "queued")
            result["analysis_id"] = analysis_id
            _store_cached(normalized, result)
            return result
        if submit.status_code == 401:
            return _empty_result("invalid_key", "error")
        if submit.status_code == 429:
            return _empty_result("rate_limited", "error")
        return _empty_result(f"http_{submit.status_code}", "error")

    except requests.exceptions.Timeout:
        return _empty_result("timeout", "error")
    except requests.exceptions.ConnectionError:
        return _empty_result("connection_error", "error")
    except (requests.exceptions.RequestException, ValueError, TypeError):
        return _empty_result("request_error", "error")
