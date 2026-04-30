import re
from urllib.parse import urlparse
from backend.keywords import keyword_risk_score

def extract_urls(text):
    return re.findall(
        r'(https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/[^\s]*)?)',
        text
    )

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    return url

def extract_domain(url):
    try:
        url = normalize_url(url)
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return ""

def has_ip(url):
    return bool(re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url))

def is_shortened(url):
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rebrand.ly",
        "shorte.st", "cutt.ly", "shorturl.at", "rb.gy"
    ]
    return any(s in url for s in shorteners)

def has_suspicious_tld(url):
    suspicious_tlds = [
        ".xyz", ".top", ".club", ".online", ".site", ".info",
        ".biz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work",
        ".click", ".link", ".pw", ".cc", ".ws"
    ]
    domain = extract_domain(url)
    return any(domain.endswith(tld) for tld in suspicious_tlds)

def has_many_subdomains(url):
    domain = extract_domain(url)
    return domain.count(".") >= 3

def has_at_symbol(url):
    return "@" in url

def has_double_slash_redirect(url):
    return "//" in url.split("://", 1)[-1]

def has_hex_encoding(url):
    return "%" in url

def has_long_url(url):
    return len(url) > 100

def fake_domain_score(url):
    domain = extract_domain(url)
    score = 0
    brands = {
        "google": ["g00gle", "goog1e", "gogle", "gooogle", "googgle"],
        "amazon": ["amaz0n", "amzon", "ama-zon", "amazoon", "arnazon"],
        "paypal": ["paypaI", "paypa1", "paypall", "paypa-l", "pay-pal"],
        "apple": ["applle", "app1e", "aple", "appl3"],
        "facebook": ["faceb00k", "facebok", "faceboook", "face-book"],
        "microsoft": ["microsft", "micr0soft", "microsofl", "micro-soft"],
        "netflix": ["netfl1x", "netfix", "net-flix"],
        "instagram": ["1nstagram", "instagran", "instagrarn"],
        "twitter": ["tw1tter", "twiter", "twitterr"],
        "bank": ["b4nk", "ban-k", "bankk"],
    }
    for real_brand, fakes in brands.items():
        for fake in fakes:
            if fake in domain:
                score += 5
        if real_brand in domain:
            parts = domain.replace("www.", "").split(".")
            if parts[0] != real_brand:
                score += 3
    if any(c.isdigit() for c in domain.split(".")[0]):
        score += 1
    if domain.count("-") > 1:
        score += 2
    if len(domain) > 25:
        score += 1
    return score

def url_suspicion_score(text):
    urls = extract_urls(text)
    if not urls:
        return 0
    score = 0
    for url in urls:
        normalized = normalize_url(url)
        if has_ip(normalized): score += 4
        if is_shortened(normalized): score += 2
        if url.startswith("http://"): score += 1
        if has_suspicious_tld(normalized): score += 3
        if has_many_subdomains(normalized): score += 2
        if has_at_symbol(normalized): score += 3
        if has_double_slash_redirect(normalized): score += 2
        if has_hex_encoding(normalized): score += 1
        if has_long_url(normalized): score += 1
        score += fake_domain_score(normalized)
    return score

def extract_features(text):
    return {
        "url_score": url_suspicion_score(text),
        "keyword_score": keyword_risk_score(text)
    }
