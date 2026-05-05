import os
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

from backend.features import extract_features, extract_urls, extract_domain, normalize_url
from backend.virustotal import check_virustotal
from backend.url_analysis import get_url_analysis
from backend.ai_reasoning import get_ai_reasoning

MODEL_PATH = os.path.join("models", "model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    _test_vec = vectorizer.transform(["test"])
    _test_X = hstack([_test_vec, csr_matrix([[0]]), csr_matrix([[0]])])
    model.predict_proba(_test_X)
except Exception:
    model = None
    vectorizer = None


def generate_rule_explanations(text, keyword_score, url_score, vt_results):
    """Original deterministic explanation bullets — kept as fallback."""
    explanations = []
    text_lower = text.lower()

    if any(w in text_lower for w in ["urgent", "immediately", "act now"]):
        explanations.append("⚠️ Urgency language detected (pressure tactics).")
    if any(w in text_lower for w in ["verify", "password", "account"]):
        explanations.append("🔐 Mentions sensitive account/security actions.")
    if any(w in text_lower for w in ["won", "gift card", "prize"]):
        explanations.append("🎁 Possible scam reward / prize bait detected.")

    urls = extract_urls(text)
    for i, original_url in enumerate(urls):
        normalized_url = normalize_url(original_url)
        domain = extract_domain(normalized_url)
        explanations.append(f"🔗 URL detected: {normalized_url}")
        explanations.append(f"🌐 Domain: {domain}")
        if original_url.startswith("http://"):
            explanations.append("⚠️ Non-secure HTTP link detected.")
        if any(tld in domain for tld in [".xyz", ".top", ".click", ".tk"]):
            explanations.append("⚠️ Suspicious domain extension detected.")
        if i < len(vt_results):
            vt = vt_results[i]
            if vt["error"] == "no_key":
                explanations.append("ℹ️ VirusTotal check skipped (no API key).")
            elif vt["error"] == "rate_limited":
                explanations.append("⏱️ VirusTotal rate limit reached.")
            elif vt["error"] == "invalid_key":
                explanations.append("❌ VirusTotal API key is invalid.")
            elif vt["error"] == "timeout":
                explanations.append("⏱️ VirusTotal check timed out.")
            elif vt["error"]:
                explanations.append(f"⚠️ VirusTotal check failed: {vt['error']}.")
            else:
                if vt["malicious"] > 0:
                    explanations.append(f"🚨 VirusTotal: {vt['malicious']} vendors flagged URL as malicious.")
                elif vt["suspicious"] > 0:
                    explanations.append(f"⚠️ VirusTotal: {vt['suspicious']} vendors flagged URL as suspicious.")
                else:
                    explanations.append(f"✅ VirusTotal: URL clean ({vt['harmless']} vendors confirmed safe).")

    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")
    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")

    return explanations


def predict_message(text: str):
    """
    Returns:
        label         : "PHISHING" | "SAFE"
        confidence    : float
        url_score     : float (capped at 10)
        explanations  : list[str]  (rule-based bullets, fallback)
        url_analyses  : list[dict] (per-URL structured breakdown)
        ai_result     : dict       (AI reasoning, may have used=False)
        scores        : dict       (keyword_score, url_score, vt_score)
    """
    features = extract_features(text)
    keyword_score = features["keyword_score"]
    url_score = features["url_score"]

    # VirusTotal
    urls = extract_urls(text)
    vt_results = []
    total_vt_score = 0
    for url in urls:
        vt = check_virustotal(url)
        vt_results.append(vt)
        if vt["error"] is None:
            total_vt_score += vt["score"]

    total_url_score = url_score + total_vt_score

    # Deterministic URL breakdown
    url_analyses = get_url_analysis(text)

    # Rule-based explanations (always generated, used as fallback)
    rule_explanations = generate_rule_explanations(
        text, keyword_score, total_url_score, vt_results
    )

    # AI reasoning (only if threshold met)
    ai_result = get_ai_reasoning(
        text, keyword_score, total_url_score, vt_results, url_analyses
    )

    # --- ML model prediction ---
    rule_score = keyword_score + total_url_score

    # Rule-score-based confidence ceiling and floor.
    # The ML model alone can be over-confident on phishing-flavoured language
    # even when hard evidence (URLs, VT hits, keyword density) is low.
    # We cap confidence by how much corroborating evidence the rules found.
    def _confidence_ceiling(rs: float) -> float:
        """Max confidence we allow at a given rule score."""
        if rs == 0:   return 0.60   # ML says phishing but zero rule evidence → soft flag
        if rs <= 2:   return 0.72
        if rs <= 4:   return 0.84
        if rs <= 7:   return 0.93
        return 0.99

    if model and vectorizer:
        tfidf_vec = vectorizer.transform([text])
        X = hstack([
            tfidf_vec,
            csr_matrix([[keyword_score]]),
            csr_matrix([[total_url_score]]),
        ])
        proba = model.predict_proba(X)[0]
        safe_prob, phish_prob = proba[0], proba[1]

        ceiling = _confidence_ceiling(rule_score)

        if phish_prob >= 0.5 or rule_score >= 2:
            label = "PHISHING"
            # Blend ML probability with rule evidence; cap by ceiling
            raw = (phish_prob * 0.55) + (min(rule_score / 15, 1.0) * 0.45)
            confidence = min(raw, ceiling)
        else:
            label = "SAFE"
            # Safe confidence can be high when both ML and rules agree it's clean
            confidence = min(safe_prob + 0.05, 0.97)
    else:
        if rule_score == 0:
            label, confidence = "SAFE", 0.85
        elif rule_score >= 8:
            label, confidence = "PHISHING", 0.95
        elif rule_score >= 4:
            label, confidence = "PHISHING", 0.82
        elif rule_score >= 2:
            label, confidence = "PHISHING", 0.70
        else:
            label, confidence = "SAFE", 0.65

    scores = {
        "keyword_score": keyword_score,
        "url_score": min(url_score, 10),
        "vt_score": min(total_vt_score, 10),
    }

    return (
        label,
        round(confidence, 2),
        min(total_url_score, 10),
        rule_explanations,
        url_analyses,
        ai_result,
        scores,
    )
