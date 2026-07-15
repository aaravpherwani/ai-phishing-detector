import os

import joblib
import numpy as np
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


def get_ml_explanations(model_input, keyword_score, total_url_score, label):
    """
    Return model-specific explanations using each logistic-regression feature's
    contribution: TF-IDF value × learned coefficient.
    """
    empty_result = {
        "available": False,
        "top_words": [],
        "why": "ML feature explanations are unavailable because the trained model could not be loaded.",
    }

    if model is None or vectorizer is None:
        return empty_result

    try:
        if not hasattr(model, "coef_") or not hasattr(vectorizer, "get_feature_names_out"):
            return empty_result

        feature_names = list(vectorizer.get_feature_names_out())
        feature_names.extend(["phishing keyword signals", "URL risk signals"])

        coefficients = model.coef_[0]
        feature_values = model_input.toarray()[0]
        contributions = feature_values * coefficients

        # In a binary Logistic Regression model, positive contribution pushes
        # towards model.classes_[1], which is the phishing class in this project.
        if label == "PHISHING":
            ranked_indexes = np.argsort(contributions)[::-1]
            relevant = [
                index for index in ranked_indexes
                if contributions[index] > 0
            ]
        else:
            ranked_indexes = np.argsort(contributions)
            relevant = [
                index for index in ranked_indexes
                if contributions[index] < 0
            ]

        top_features = []
        for index in relevant:
            name = feature_names[index]

            if name == "phishing keyword signals" and keyword_score <= 0:
                continue
            if name == "URL risk signals" and total_url_score <= 0:
                continue

            top_features.append({
                "feature": name,
                "contribution": round(float(abs(contributions[index])), 4),
            })

            if len(top_features) == 5:
                break

        top_words = [
            item["feature"]
            for item in top_features
            if item["feature"] not in {
                "phishing keyword signals",
                "URL risk signals",
            }
        ]

        signal_features = [
            item["feature"]
            for item in top_features
            if item["feature"] in {
                "phishing keyword signals",
                "URL risk signals",
            }
        ]

        if label == "PHISHING":
            if top_features:
                reasons = []

                if top_words:
                    reasons.append(
                        "the message contains language patterns previously associated with phishing"
                    )

                if "phishing keyword signals" in signal_features:
                    reasons.append("it includes phishing-related keyword signals")

                if "URL risk signals" in signal_features:
                    reasons.append("its URL structure added risk")

                why = (
                    "The ML model flagged this because "
                    + " and ".join(reasons)
                    + "."
                )
            else:
                why = (
                    "The ML model flagged this based on its overall message pattern, "
                    "although no single word was a strong standalone contributor."
                )
        else:
            if top_features:
                reasons = []

                if top_words:
                    reasons.append(
                        "its wording resembles legitimate messages in the training data"
                    )

                if keyword_score == 0:
                    reasons.append("it contains no high-risk phishing language")

                if total_url_score == 0:
                    reasons.append("it has no suspicious URL signals")

                why = "The ML model marked this safe because " + " and ".join(reasons) + "."
            else:
                why = (
                    "The ML model marked this safe because it found no strong "
                    "phishing-language or URL-risk signals."
                )

        return {
            "available": True,
            "top_words": top_words,
            "top_features": top_features,
            "why": why,
        }

    except Exception:
        return empty_result


def build_ml_explanation_bullets(ml_explanations, label):
    """Format ML explanations for the existing Streamlit Risk Indicators panel."""
    bullets = []

    if not ml_explanations.get("available"):
        return bullets

    top_words = ml_explanations.get("top_words", [])
    top_features = ml_explanations.get("top_features", [])
    why = ml_explanations.get("why")

    if top_words:
        formatted_words = ", ".join(f"`{word}`" for word in top_words)
        bullets.append(
            f"📊 Top contributing words (feature importance): {formatted_words}"
        )
    elif top_features:
        formatted_features = ", ".join(
            f"`{item['feature']}`"
            for item in top_features
        )
        bullets.append(
            f"📊 Top contributing signals (feature importance): {formatted_features}"
        )
    else:
        bullets.append(
            "📊 Top contributing words (feature importance): no single word had a strong standalone effect."
        )

    if label == "PHISHING":
        bullets.append(f"🧠 Why the model flagged this: {why}")
    else:
        bullets.append(f"✅ Why Safe: {why}")

    return bullets


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

    model_input = None

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

    if model_input is not None:
        ml_explanations = get_ml_explanations(
            model_input,
            keyword_score,
            total_url_score,
            label,
        )
        rule_explanations.extend(
            build_ml_explanation_bullets(ml_explanations, label)
        )
    else:
        ml_explanations = {
            "available": False,
            "top_words": [],
            "top_features": [],
            "why": "The trained ML model is unavailable; this verdict uses rule-based signals.",
        }

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
            maximum_confidence = 0.99 if agreement_on_phishing else 0.97

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
        "ml_explanations": ml_explanations,
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
