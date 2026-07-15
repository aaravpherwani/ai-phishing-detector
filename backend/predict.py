import os

import joblib
from scipy.sparse import csr_matrix, hstack

from backend.ai_reasoning import get_ai_reasoning
from backend.features import extract_domain, extract_features, extract_urls, normalize_url
from backend.url_analysis import get_url_analysis
from backend.virustotal import check_virustotal

MODEL_PATH = os.path.join("models", "model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    test_vector = vectorizer.transform(["test"])
    test_features = hstack([
        test_vector,
        csr_matrix([[0]]),
        csr_matrix([[0]]),
    ])
    model.predict_proba(test_features)
except Exception:
    model = None
    vectorizer = None


def generate_rule_explanations(text, keyword_score, url_score, vt_results):
    """Create deterministic explanations for detected phishing indicators."""
    explanations = []
    text_lower = text.lower()

    if any(word in text_lower for word in ["urgent", "immediately", "act now"]):
        explanations.append("⚠️ Urgency language detected (pressure tactics).")

    if any(word in text_lower for word in ["verify", "password", "account"]):
        explanations.append("🔐 Mentions sensitive account/security actions.")

    if any(word in text_lower for word in ["won", "gift card", "prize"]):
        explanations.append("🎁 Possible scam reward / prize bait detected.")

    for index, original_url in enumerate(extract_urls(text)):
        normalized_url = normalize_url(original_url)
        domain = extract_domain(normalized_url)

        explanations.append(f"🔗 URL detected: {normalized_url}")
        explanations.append(f"🌐 Domain: {domain}")

        if original_url.startswith("http://"):
            explanations.append("⚠️ Non-secure HTTP link detected.")

        if any(tld in domain for tld in [".xyz", ".top", ".click", ".tk"]):
            explanations.append("⚠️ Suspicious domain extension detected.")

        if index >= len(vt_results):
            continue

        vt = vt_results[index]

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
        elif vt["malicious"] > 0:
            explanations.append(
                f"🚨 VirusTotal: {vt['malicious']} vendors flagged URL as malicious."
            )
        elif vt["suspicious"] > 0:
            explanations.append(
                f"⚠️ VirusTotal: {vt['suspicious']} vendors flagged URL as suspicious."
            )
        else:
            explanations.append(
                f"✅ VirusTotal: URL clean ({vt['harmless']} vendors confirmed safe)."
            )

    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")

    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")

    return explanations


def confidence_ceiling(rule_score):
    if rule_score == 0:
        return 0.60
    if rule_score <= 2:
        return 0.72
    if rule_score <= 4:
        return 0.84
    if rule_score <= 7:
        return 0.93
    return 0.99


def predict_message(text: str):
    """Return phishing verdict, confidence, analysis details, and score data."""
    features = extract_features(text)
    keyword_score = features["keyword_score"]
    url_score = features["url_score"]

    urls = extract_urls(text)
    vt_results = []
    total_vt_score = 0

    for url in urls:
        vt_result = check_virustotal(url)
        vt_results.append(vt_result)

        if vt_result["error"] is None:
            total_vt_score += vt_result["score"]

    total_url_score = url_score + total_vt_score
    rule_score = keyword_score + total_url_score

    url_analyses = get_url_analysis(text)

    rule_explanations = generate_rule_explanations(
        text,
        keyword_score,
        total_url_score,
        vt_results,
    )

    ai_result = get_ai_reasoning(
        text,
        keyword_score,
        total_url_score,
        vt_results,
        url_analyses,
    )

    if model is not None and vectorizer is not None:
        tfidf_vector = vectorizer.transform([text])
        feature_vector = hstack([
            tfidf_vector,
            csr_matrix([[keyword_score]]),
            csr_matrix([[total_url_score]]),
        ])

        safe_probability, phishing_probability = model.predict_proba(
            feature_vector
        )[0]

        if phishing_probability >= 0.5 or rule_score >= 2:
            label = "PHISHING"
            raw_confidence = (
                phishing_probability * 0.55
                + min(rule_score / 15, 1.0) * 0.45
            )
            confidence = min(raw_confidence, confidence_ceiling(rule_score))
        else:
            label = "SAFE"
            confidence = min(safe_probability + 0.05, 0.97)
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

    initial_confidence = round(confidence, 2)
    ai_adjusted = False

    if ai_result.get("used") and ai_result.get("confidence") is not None:
        ai_confidence = float(ai_result["confidence"])
        ai_verdict = ai_result.get("verdict")

        model_is_uncertain = confidence < 0.72
        rule_score_in_gray_zone = 2 <= rule_score <= 6
        ai_is_confident = ai_confidence >= 0.75

        agrees_on_phishing = (
            ai_verdict == "PHISHING" and label == "PHISHING"
        )
        agrees_on_safety = ai_verdict == "SAFE" and label == "SAFE"

        if (
            (model_is_uncertain or rule_score_in_gray_zone)
            and ai_is_confident
            and (agrees_on_phishing or agrees_on_safety)
        ):
            maximum_confidence = 0.99 if agrees_on_phishing else 0.97

            confidence = round(
                min(
                    (confidence * 0.60) + (ai_confidence * 0.40),
                    maximum_confidence,
                ),
                2,
            )
            ai_adjusted = confidence != initial_confidence

    scores = {
        "keyword_score": keyword_score,
        "url_score": min(url_score, 10),
        "vt_score": min(total_vt_score, 10),
        "confidence_pre_ai": initial_confidence,
        "ai_adjusted": ai_adjusted,
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
