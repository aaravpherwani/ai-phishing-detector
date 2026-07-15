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
    test_input = hstack([
        test_vector,
        csr_matrix([[0]]),
        csr_matrix([[0]]),
    ])
    model.predict_proba(test_input)
except Exception:
    model = None
    vectorizer = None


def generate_rule_explanations(text, keyword_score, url_score, vt_results):
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

        vt_result = vt_results[index]

        if vt_result["error"] == "no_key":
            explanations.append("ℹ️ VirusTotal check skipped (no API key).")
        elif vt_result["error"] == "rate_limited":
            explanations.append("⏱️ VirusTotal rate limit reached.")
        elif vt_result["error"] == "invalid_key":
            explanations.append("❌ VirusTotal API key is invalid.")
        elif vt_result["error"] == "timeout":
            explanations.append("⏱️ VirusTotal check timed out.")
        elif vt_result["error"]:
            explanations.append(
                f"⚠️ VirusTotal check failed: {vt_result['error']}."
            )
        elif vt_result["malicious"] > 0:
            explanations.append(
                f"🚨 VirusTotal: {vt_result['malicious']} vendors flagged URL as malicious."
            )
        elif vt_result["suspicious"] > 0:
            explanations.append(
                f"⚠️ VirusTotal: {vt_result['suspicious']} vendors flagged URL as suspicious."
            )
        else:
            explanations.append(
                f"✅ VirusTotal: URL clean ({vt_result['harmless']} vendors confirmed safe)."
            )

    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")

    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")

    return explanations


def get_confidence_ceiling(rule_score):
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
        text_vector = vectorizer.transform([text])
        model_input = hstack([
            text_vector,
            csr_matrix([[keyword_score]]),
            csr_matrix([[total_url_score]]),
        ])

        safe_probability, phishing_probability = model.predict_proba(
            model_input
        )[0]

        if phishing_probability >= 0.5 or rule_score >= 2:
            label = "PHISHING"
            raw_confidence = (
                phishing_probability * 0.55
                + min(rule_score / 15, 1.0) * 0.45
            )
            confidence = min(
                raw_confidence,
                get_confidence_ceiling(rule_score),
            )
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

    model_confidence = round(confidence, 2)
    ai_adjusted = False

    if ai_result.get("used") and ai_result.get("confidence") is not None:
        ai_confidence = float(ai_result["confidence"])
        ai_verdict = ai_result.get("verdict")

        model_is_uncertain = confidence < 0.72
        score_is_in_gray_zone = 2 <= rule_score <= 6
        ai_is_confident = ai_confidence >= 0.75

        agreement_on_phishing = (
            label == "PHISHING" and ai_verdict == "PHISHING"
        )
        agreement_on_safety = (
            label == "SAFE" and ai_verdict == "SAFE"
        )

        if (
            (model_is_uncertain or score_is_in_gray_zone)
            and ai_is_confident
            and (agreement_on_phishing or agreement_on_safety)
        ):
            maximum_confidence = (
                0.99 if agreement_on_phishing else 0.97
            )

            confidence = round(
                min(
                    (confidence * 0.60) + (ai_confidence * 0.40),
                    maximum_confidence,
                ),
                2,
            )

            ai_adjusted = confidence != model_confidence

    scores = {
        "keyword_score": keyword_score,
        "url_score": min(url_score, 10),
        "vt_score": min(total_vt_score, 10),
        "confidence_pre_ai": model_confidence,
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
