import base64
import re
from urllib.parse import parse_qs, unquote, urlparse

from backend.keywords import keyword_risk_score


URL_PATTERN = re.compile(
    r"""(?ix)
    (
        https?://[^\s<>"']+
        |www\.[^\s<>"']+
        |(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
          (?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})
          (?::\d{2,5})?
          (?:/[^\s<>"']*)?
    )
    """
)

PROMPT_INJECTION_PATTERNS = [
    r"\bignore (all |any |the )?(previous|prior|above) instructions\b",
    r"\bdisregard (all |any |the )?(previous|prior|above) instructions\b",
    r"\bsystem message\b",
    r"\bdeveloper message\b",
    r"\byou are now\b",
    r"\bdo not follow\b",
    r"\bpretend you are\b",
    r"\boutput (the )?(system|developer) prompt\b",
    r"\bact as (an? )?unrestricted\b",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".info",
    ".biz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work",
    ".click", ".link", ".pw", ".cc", ".ws",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rebrand.ly",
    "shorte.st", "cutt.ly", "shorturl.at", "rb.gy",
]

REDIRECT_PARAMETER_NAMES = {
    "url", "uri", "target", "dest", "destination", "redirect",
    "redirect_url", "redirect_uri", "next", "continue", "return",
    "returnurl", "goto", "link", "out",
}


def extract_urls(text):
    """Extract normal, scheme-less, punycode, and redirect-style URLs."""
    urls = []

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?)]}\"'")
        if url and url not in urls:
            urls.append(url)

    return urls


def normalize_url(url):
    url = url.strip()

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url

    return url


def extract_domain(url):
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.hostname or "").lower().strip(".")
    except Exception:
        return ""


def has_ip(url):
    domain = extract_domain(url)
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))


def is_shortened(url):
    domain = extract_domain(url)
    return domain in SHORTENERS or any(
        domain.endswith("." + shortener)
        for shortener in SHORTENERS
    )


def has_suspicious_tld(url):
    domain = extract_domain(url)
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def has_many_subdomains(url):
    domain = extract_domain(url)
    return domain.count(".") >= 3


def has_at_symbol(url):
    return "@" in unquote(url)


def has_double_slash_redirect(url):
    path_and_query = normalize_url(url).split("://", 1)[-1]
    return "//" in path_and_query


def has_hex_encoding(url):
    return bool(re.search(r"%[0-9a-fA-F]{2}", url))


def has_long_url(url):
    return len(url) > 100


def has_punycode(url):
    return "xn--" in extract_domain(url)


def has_missing_scheme(url):
    return not re.match(r"^https?://", url, flags=re.IGNORECASE)


def has_redirect_parameter(url):
    try:
        parsed = urlparse(normalize_url(url))
        parameters = parse_qs(parsed.query, keep_blank_values=True)

        for parameter, values in parameters.items():
            if parameter.lower() in REDIRECT_PARAMETER_NAMES:
                if any(
                    "http" in unquote(value).lower()
                    or "www." in unquote(value).lower()
                    for value in values
                ):
                    return True

        decoded_url = unquote(url).lower()
        return any(
            f"{parameter}=" in decoded_url
            for parameter in REDIRECT_PARAMETER_NAMES
        )
    except Exception:
        return False


def has_base64_payload(url):
    """
    Detect long Base64-like chunks that decode to a URL, credential phrase,
    JavaScript, or HTML. Short random-looking tokens are intentionally ignored.
    """
    candidates = re.findall(
        r"(?:[A-Za-z0-9+/]{32,}={0,2})",
        unquote(url),
    )

    for candidate in candidates:
        try:
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(
                padded,
                validate=False,
            ).decode("utf-8", errors="ignore").lower()

            if any(marker in decoded for marker in [
                "http://", "https://", "<script", "<html",
                "password", "verify", "login", "credential",
            ]):
                return True
        except Exception:
            continue

    return False


def fake_domain_score(url):
    domain = extract_domain(url)
    score = 0

    brands = {
        "google": ["g00gle", "goog1e", "gogle", "gooogle", "googgle"],
        "amazon": ["amaz0n", "amzon", "ama-zon", "amazoon", "arnazon"],
        "paypal": ["paypai", "paypa1", "paypall", "paypa-l", "pay-pal"],
        "apple": ["applle", "app1e", "aple", "appl3"],
        "facebook": ["faceb00k", "facebok", "faceboook", "face-book"],
        "microsoft": ["microsft", "micr0soft", "microsofl", "micro-soft"],
        "netflix": ["netfl1x", "netfix", "net-flix"],
        "instagram": ["1nstagram", "instagran", "instagrarn"],
        "twitter": ["tw1tter", "twiter", "twitterr"],
        "bank": ["b4nk", "ban-k", "bankk"],
    }

    for real_brand, fake_variants in brands.items():
        for fake_variant in fake_variants:
            if fake_variant in domain:
                score += 5

        parts = domain.replace("www.", "").split(".")
        if real_brand in domain and parts and parts[0] != real_brand:
            score += 3

    first_label = domain.split(".")[0] if domain else ""

    if any(character.isdigit() for character in first_label):
        score += 1

    if domain.count("-") > 1:
        score += 2

    if len(domain) > 25:
        score += 1

    return score


def adversarial_text_score(text):
    """Score content attempting to manipulate the Gemini security-analysis prompt."""
    text_lower = text.lower()
    matches = sum(
        bool(re.search(pattern, text_lower))
        for pattern in PROMPT_INJECTION_PATTERNS
    )

    if matches == 0:
        return 0

    return min(matches * 3, 10)


def url_suspicion_score(text):
    urls = extract_urls(text)

    if not urls:
        return 0

    score = 0

    for url in urls:
        normalized = normalize_url(url)

        if has_ip(normalized):
            score += 4

        if is_shortened(normalized):
            score += 2

        if has_missing_scheme(url):
            score += 1

        if url.lower().startswith("http://"):
            score += 1

        if has_suspicious_tld(normalized):
            score += 3

        if has_many_subdomains(normalized):
            score += 2

        if has_at_symbol(normalized):
            score += 3

        if has_double_slash_redirect(normalized):
            score += 2

        if has_hex_encoding(normalized):
            score += 2

        if has_base64_payload(normalized):
            score += 4

        if has_punycode(normalized):
            score += 4

        if has_redirect_parameter(normalized):
            score += 3

        if has_long_url(normalized):
            score += 1

        score += fake_domain_score(normalized)

    return min(score, 30)


def extract_features(text):
    """Return model-compatible keyword and URL-risk features."""
    prompt_injection_risk = adversarial_text_score(text)

    return {
        "url_score": url_suspicion_score(text),
        "keyword_score": (
            keyword_risk_score(text)
            + prompt_injection_risk
        ),
    }
