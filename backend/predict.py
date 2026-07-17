import os

import joblib
from scipy.sparse import csr_matrix, hstack

from backend.ai_reasoning import get_ai_reasoning
from backend.ensemble_runtime import predict_ensemble
from backend.features import extract_domain, extract_features, extract_urls, normalize_url
from backend.url_analysis import get_url_analysis
from backend.virustotal import check_virustotal

MODEL_PATH = os.path.join("models", "model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")
MAX_VIRUSTOTAL_SCANS_PER_MESSAGE = 2

try:
    legacy_model = joblib.load(MODEL_PATH)
    legacy_vectorizer = joblib.load(VECTORIZER_PATH)

    test_vector = legacy_vectorizer.transform(["test"])
    test_input = hstack([
        test_vector,
        csr_matrix([[0]]),
        csr_matrix([[0]]),
    ])
    legacy_model.predict_proba(test_input)
except Exception:
    legacy_model = None
    legacy_vectorizer = None


def should_scan_url(url_analysis, keyword_score):
    """Only spend VirusTotal calls on URLs with meaningful risk signals."""
    return any([
        keyword_score >= 4,
        url_analysis["uses_ip"],
        url_analysis["is_shortened"],
        url_analysis["suspicious_tld"],
        url_analysis["many_subdomains"],
        url_analysis["has_at_symbol"],
        url_analysis["has_hex_encoding"],
        url_analysis["is_long"],
        url_analysis["is_http"],
        url_analysis["fake_brand_score"] >= 3,
        bool(url_analysis["brand_spoof"]),
    ])


def generate_rule_explanations(text, keyword_score, url_score, vt_results):
    """Generate deterministic phishing and VirusTotal explanations."""
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

        if index >= len(vt_results):
            continue

        vt_result = vt_results[index]

        if vt_result["error"] == "not_scanned":
            explanations.append(
                "ℹ️ VirusTotal scan skipped because this URL did not meet the high-risk scan threshold."
            )
        elif vt_result["error"] == "no_key":
            explanations.append("ℹ️ VirusTotal check skipped (no API key).")
        elif vt_result["error"]:
            explanations.append(
                f"⚠️ VirusTotal check unavailable: {vt_result['error']}."
            )
        elif vt_result["status"] == "queued":
            explanations.append(
                "⏳ VirusTotal scan submitted; no completed report is available yet."
            )
        elif vt_result["suspicious"] > 0 and vt_result["harmless"] > 0:
            explanations.append(
                f"⚠️ VirusTotal has mixed results: "
                f"{vt_result['suspicious']} suspicious and "
                f"{vt_result['harmless']} harmless vendor votes."
            )
        elif vt_result["malicious"] > 0:
            explanations.append(
                f"🚨 VirusTotal: {vt_result['malicious']} vendor(s) flagged this URL as malicious."
            )
        elif vt_result["suspicious"] > 0:
            explanations.append(
                f"⚠️ VirusTotal: {vt_result['suspicious']} vendor(s) flagged this URL as suspicious."
            )
        else:
            explanations.append(
                f"✅ VirusTotal: no vendor detections "
                f"({vt_result['harmless']} harmless votes)."
            )

    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")

    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")

    return explanations


def legacy_prediction(text, keyword_score, total_url_score, rule_score):
    """Fallback to the existing logistic-regression model or rules."""
    if legacy_model is None or legacy_vectorizer is None:
        if rule_score == 0:
            return "SAFE", 0.85, "rule engine"
        if rule_score >= 4:
            return "PHISHING", 0.82, "rule engine"
        if rule_score >= 2:
            return "PHISHING", 0.70, "rule engine"
        return "SAFE", 0.65, "rule engine"

    text_vector = legacy_vectorizer.transform([text])

    model_input = hstack([
        text_vector,
        csr_matrix([[keyword_score]]),
        csr_matrix([[total_url_score]]),
    ])

    safe_probability, phishing_probability = legacy_model.predict_proba(
        model_input
    )[0]

    if phishing_probability >= 0.5 or rule_score >= 2:
        return "PHISHING", float(phishing_probability), (
            "legacy logistic regression"
        )

    return "SAFE", float(safe_probability), "legacy logistic regression"


def apply_vt_confidence_guardrail(confidence, label, vt_results):
    """Cap confidence when VirusTotal evidence is mixed or contradictory."""
    completed_results = [
        result
        for result in vt_results
        if result.get("error") is None and result.get("checked")
    ]

    has_suspicious = any(
        result["malicious"] > 0 or result["suspicious"] > 0
        for result in completed_results
    )

    has_harmless = any(
        result["harmless"] > 0
        for result in completed_results
    )

    if has_suspicious and has_harmless:
        return min(confidence, 0.80), (
            "Confidence limited because VirusTotal returned mixed vendor results."
        )

    if label == "PHISHING" and has_harmless and not has_suspicious:
        return min(confidence, 0.80), (
            "Confidence limited because VirusTotal found no vendor detections."
        )

    return confidence, None


def predict_message(text: str):
    """
    Analyze a message.

    Returns:
        label, confidence, url_score, rule_explanations, url_analyses,
        ai_result, scores
    """
    features = extract_features(text)
    keyword_score = features["keyword_score"]
    url_score = features["url_score"]

    urls = extract_urls(text)
    url_analyses = get_url_analysis(text)

    analyses_by_raw_url = {
        analysis["raw_url"]: analysis
        for analysis in url_analyses
    }

    vt_results = []
    total_vt_score = 0
    scans_used = 0

    for url in urls:
        url_analysis = analyses_by_raw_url.get(url)

        if (
            url_analysis
            and scans_used < MAX_VIRUSTOTAL_SCANS_PER_MESSAGE
            and should_scan_url(url_analysis, keyword_score)
        ):
            vt_result = check_virustotal(url)
            scans_used += 1
        else:
            vt_result = {
                "score": 0,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "error": "not_scanned",
                "status": "skipped",
                "checked": False,
            }

        vt_results.append(vt_result)

        if vt_result["error"] is None:
            total_vt_score += vt_result["score"]

    total_url_score = url_score + total_vt_score
    rule_score = keyword_score + total_url_score

    rule_explanations = generate_rule_explanations(
        text,
        keyword_score,
        total_url_score,
        vt_results,
    )

    ensemble_result = predict_ensemble(
        text,
        keyword_score,
        total_url_score,
    )

    if ensemble_result["available"]:
        phishing_probability = ensemble_result["phishing_probability"]

        label = (
            "PHISHING"
            if phishing_probability >= 0.50
            else "SAFE"
        )

        confidence = (
            phishing_probability
            if label == "PHISHING"
            else 1 - phishing_probability
        )

        model_source = (
            f"calibrated ensemble v{ensemble_result['model_version']}"
        )

        rule_explanations.append(
            f"🧠 Calibrated ensemble prediction: "
            f"LightGBM {ensemble_result['lightgbm_probability']:.0%} phishing risk, "
            f"DistilBERT {ensemble_result['distilbert_probability']:.0%} phishing risk."
        )
    else:
        label, confidence, model_source = legacy_prediction(
            text,
            keyword_score,
            total_url_score,
            rule_score,
        )

        rule_explanations.append(
            f"ℹ️ Calibrated ensemble unavailable; using {model_source} fallback."
        )

    confidence_before_ai = round(confidence, 2)
    ai_adjusted = False

    ai_result = get_ai_reasoning(
        text,
        keyword_score,
        total_url_score,
        vt_results,
        url_analyses,
    )

    if ai_result.get("used") and ai_result.get("confidence") is not None:
        ai_confidence = float(ai_result["confidence"])
        ai_verdict = ai_result.get("verdict")

        model_uncertain = confidence < 0.72
        in_gray_zone = 2 <= rule_score <= 6
        ai_confident = ai_confidence >= 0.75

        agrees = (
            (label == "PHISHING" and ai_verdict == "PHISHING")
            or (label == "SAFE" and ai_verdict == "SAFE")
        )

        if (model_uncertain or in_gray_zone) and ai_confident and agrees:
            ceiling = 0.99 if label == "PHISHING" else 0.97

            confidence = min(
                (confidence * 0.60) + (ai_confidence * 0.40),
                ceiling,
            )

            ai_adjusted = (
                round(confidence, 2) != confidence_before_ai
            )

    confidence, vt_note = apply_vt_confidence_guardrail(
        confidence,
        label,
        vt_results,
    )

    if vt_note:
        rule_explanations.append(f"ℹ️ {vt_note}")

    scores = {
        "keyword_score": keyword_score,
        "url_score": min(url_score, 10),
        "vt_score": min(total_vt_score, 10),
        "confidence_pre_ai": confidence_before_ai,
        "ai_adjusted": ai_adjusted,
        "model_source": model_source,
        "virustotal_scans_used": scans_used,
        "ensemble": ensemble_result,
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
