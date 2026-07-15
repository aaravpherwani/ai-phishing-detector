import os
import joblib
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
    """Create deterministic phishing-indicator explanations."""
    explanations = []
    text_lower = text.lower()

    if any(word in text_lower for word in ["urgent", "immediately", "act now"]):
        explanations.append("⚠️ Urgency language detected (pressure tactics).")

    if any(word in text_lower for word in ["verify", "password", "account"]):
        explanations.append("🔐 Mentions sensitive account/security actions.")

    if any(word in text_lower for word in ["won", "gift card", "prize"]):
        explanations.append("🎁 Possible scam reward / prize bait detected.")

    urls = extract_urls(text)

    for index, original_url in enumerate(urls):
        normalized_url = normalize_url(original_url)
        domain = extract_domain(normalized_url)

        explanations.append(f"🔗 URL detected: {normalized_url}")
        explanations.append(f"🌐 Domain: {domain}")

        if original_url.startswith("http://"):
            explanations.append("⚠️ Non-secure HTTP link detected.")

        if any(tld in domain for tld in [".xyz", ".top", ".click", ".tk"]):
            explanations.append("⚠️ Suspicious domain extension detected.")

        if index < len(vt_results):
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


def predict_message(text: str):
    """Analyze a message and return phishing verdict, evidence, and scoring."""
    features = extract_features(text)
    keyword_score = features["keyword_score"]
    url_score = features["url_score"]

    urls = extract_urls(text)
    vt_results = []
    total_vt_score = 0

    for url in urls:
        vt = check_virustotal(url)
        vt_results.append(vt)

        if vt["error"] is None:
            total_vt_score += vt["score"]

    total_url_score = url_score + total_vt_score
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

    rule_score = keyword_score + total_url_score

    def confidence_ceiling(score: float) -> float:
        if score == 0:
            return 0.60
        if score <= 2:
            return 0.72
        if score <= 4:
            return 0.84
        if score <= 7:
            return 0.93
        return 0.99

    if model and vectorizer:
        tfidf_vec = vectorizer.transform([text])
        feature_vector = hstack([
            tfidf_vec,
            csr_matrix([[keyword_score]]),
            csr_matrix([[total_url_score]]),
        ])

        probabilities = model.predict_proba(feature_vector)[0]
        safe_prob, phish_prob = probabilities[0], probabilities[1]

        if phish_prob >= 0.5 or rule_score >= 2:
            label = "PHISHING"
            raw_confidence = (
                phish_prob * 0.55
                + min(rule_score / 15, 1.0) * 0.45
            )
            confidence = min(raw_confidence, confidence_ceiling(rule_score))
        else:
            label = "SAFE"
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

    # These must be initialized before the AI adjustment and scores dictionary.
    confidence_before_ai = round(confidence, 2)
    ai_adjusted = False

    gray_zone_low = 2
    gray_zone_high = 6
    ml_uncertain_threshold = 0.72
    ai_confident_threshold = 0.75

    if ai_result.get("used") and ai_result.get("confidence") is not None:
        ai_confidence = float(ai_result["confidence"])
        ai_verdict = ai_result.get("verdict")

        ml_uncertain = confidence < ml_uncertain_threshold
        in_gray_zone = gray_zone_low <= rule_score <= gray_zone_high
        ai_confident = ai_confidence >= ai_confident_threshold

        agrees_phishing = ai_verdict == "PHISHING" and label == "PHISHING"
        agrees_safe = ai_verdict == "SAFE" and label == "SAFE"

        if (ml_uncertain or in_gray_zone) and ai_confident and (
            agrees_phishing or agrees_safe
        ):
            ceiling = 0.99 if agrees_phishing else 0.97
            confidence = round(
                min(
                    (confidence * 0.60) + (ai_confidence * 0.40),
                    ceiling,
                ),
                2,
            )
            ai_adjusted = confidence != confidence_before_ai

    scores = {
        "keyword_score": keyword_score,
        "url_score": min(url_score, 10),
        "vt_score": min(total_vt_score, 10),
        "confidence_pre_ai": confidence_before_ai,
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
