import os
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

from backend.features import extract_features, extract_urls, extract_domain, normalize_url
from backend.virustotal import check_virustotal

MODEL_PATH = os.path.join("models", "model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    from scipy.sparse import hstack, csr_matrix
    _test_vec = vectorizer.transform(["test"])
    _test_X = hstack([_test_vec, csr_matrix([[0]]), csr_matrix([[0]])])
    model.predict_proba(_test_X)
except Exception:
    model = None
    vectorizer = None

def generate_explanation(text, keyword_score, url_score, vt_results):
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

        # VirusTotal explanation for each URL
        if i < len(vt_results):
            vt = vt_results[i]
            if vt["error"] == "no_key":
                explanations.append("ℹ️ VirusTotal check skipped (no API key).")
            elif vt["error"] == "rate_limited":
                explanations.append("⏱️ VirusTotal rate limit reached. Try again shortly.")
            elif vt["error"] == "invalid_key":
                explanations.append("❌ VirusTotal API key is invalid.")
            elif vt["error"] == "timeout":
                explanations.append("⏱️ VirusTotal check timed out.")
            elif vt["error"]:
                explanations.append(f"⚠️ VirusTotal check failed: {vt['error']}.")
            else:
                if vt["malicious"] > 0:
                    explanations.append(f"🚨 VirusTotal: {vt['malicious']} security vendors flagged this URL as malicious.")
                elif vt["suspicious"] > 0:
                    explanations.append(f"⚠️ VirusTotal: {vt['suspicious']} security vendors flagged this URL as suspicious.")
                else:
                    explanations.append(f"✅ VirusTotal: URL appears clean ({vt['harmless']} vendors confirmed safe).")

    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")

    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")

    return explanations


def predict_message(text: str):
    features = extract_features(text)

    keyword_score = features["keyword_score"]
    url_score = features["url_score"]

    # Check ALL URLs with VirusTotal
    urls = extract_urls(text)
    vt_results = []
    total_vt_score = 0

    for url in urls:
        vt = check_virustotal(url)
        vt_results.append(vt)
        if vt["error"] is None:
            total_vt_score += vt["score"]

    total_url_score = url_score + total_vt_score

    explanations = generate_explanation(text, keyword_score, total_url_score, vt_results)

    rule_score = keyword_score + total_url_score

    if model and vectorizer:
        tfidf_vec = vectorizer.transform([text])

        keyword_feat = csr_matrix([[keyword_score]])
        url_feat = csr_matrix([[total_url_score]])

        X = hstack([tfidf_vec, keyword_feat, url_feat])

        proba = model.predict_proba(X)[0]
        safe_prob, phish_prob = proba[0], proba[1]

        boost = min(rule_score * 0.05, 0.35)  # increased from 0.03/0.25

        if phish_prob >= 0.5 or rule_score >= 4:
            label = "PHISHING"
            confidence = min(phish_prob + boost, 0.99)

        elif rule_score >= 2:
            label = "PHISHING"
            confidence = min(0.65 + boost, 0.92)  # increased from 0.55/0.85

        else:
            label = "SAFE"
            confidence = min(safe_prob + 0.05, 0.99)

    else:
        if rule_score >= 4:
            label = "PHISHING"
            confidence = 0.95  # increased from 0.90
        elif rule_score >= 2:
            label = "PHISHING"
            confidence = 0.80  # increased from 0.70
        else:
            label = "SAFE"
            confidence = 0.65

    return label, round(confidence, 2), min(total_url_score, 10), explanations
