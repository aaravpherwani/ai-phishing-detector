"""
url_analysis.py
Deterministic, zero-AI URL breakdown. Called by both the explainability
dashboard and the AI reasoning layer.
"""

from backend.features import (
    extract_urls,
    normalize_url,
    extract_domain,
    has_ip,
    is_shortened,
    has_suspicious_tld,
    has_many_subdomains,
    has_at_symbol,
    has_hex_encoding,
    has_long_url,
    fake_domain_score,
)
from urllib.parse import urlparse
import re


def get_url_analysis(text: str) -> list[dict]:
    """
    Returns a list of dicts, one per URL found in text.
    Each dict contains structured, deterministic analysis — no AI involved.
    """
    urls = extract_urls(text)
    results = []

    for raw_url in urls:
        norm = normalize_url(raw_url)
        domain = extract_domain(norm)

        # Subdomain count: dots in domain minus 1 (TLD) minus 1 (base domain)
        parts = domain.split(".")
        subdomain_count = max(0, len(parts) - 2)

        # TLD
        tld = "." + parts[-1] if parts else ""

        # Special characters
        special_chars = []
        if "@" in norm:
            special_chars.append("@")
        if has_hex_encoding(norm):
            special_chars.append("% (hex encoding)")
        if "//" in norm.split("://", 1)[-1]:
            special_chars.append("// (double-slash redirect)")
        if "=" in norm:
            special_chars.append("= (query params)")

        # Fake brand score + which brand triggered it
        fds = fake_domain_score(norm)
        brand_spoof = None
        if fds > 0:
            brands = [
                "google", "amazon", "paypal", "apple", "facebook",
                "microsoft", "netflix", "instagram", "twitter", "bank"
            ]
            for b in brands:
                if b in domain:
                    brand_spoof = b
                    break

        results.append({
            "raw_url": raw_url,
            "normalized_url": norm,
            "domain": domain,
            "tld": tld,
            "subdomain_count": subdomain_count,
            "url_length": len(norm),
            "uses_ip": has_ip(norm),
            "is_shortened": is_shortened(norm),
            "suspicious_tld": has_suspicious_tld(norm),
            "many_subdomains": has_many_subdomains(norm),
            "has_at_symbol": has_at_symbol(norm),
            "has_hex_encoding": has_hex_encoding(norm),
            "is_long": has_long_url(norm),
            "special_chars": special_chars,
            "fake_brand_score": fds,
            "brand_spoof": brand_spoof,
            "is_http": raw_url.startswith("http://"),
        })

    return results
