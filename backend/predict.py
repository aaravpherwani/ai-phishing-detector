"""Threat scoring and explainability for PhishGuard."""
import os
import re

import joblib
from scipy.sparse import csr_matrix, hstack

from backend.ai_reasoning import get_ai_reasoning
from backend.ensemble_runtime import predict_ensemble
from backend.features import extract_domain, extract_features, extract_urls, normalize_url
from backend.keywords import (
    CLICK_BAIT, FINANCIAL_BAIT, IMPERSONATION_BAIT, INFO_HARVESTING,
    PRIZE_BAIT, SECURITY_BAIT, TECH_SCAM, URGENT_WORDS,
)
from backend.url_analysis import get_url_analysis
from backend.virustotal import check_virustotal

MODEL_PATH = os.path.join("models", "model.pkl")
VECTORIZER_PATH = os.path.join("models", "vectorizer.pkl")
MAX_VIRUSTOTAL_SCANS_PER_MESSAGE = 2
# The rule engine can accumulate many phrase matches.  This is the documented
# ceiling used only when displaying the language-risk component on a /10 scale.
MAX_KEYWORD_RISK = 20

try:
    legacy_model = joblib.load(MODEL_PATH)
    legacy_vectorizer = joblib.load(VECTORIZER_PATH)
    probe = hstack([legacy_vectorizer.transform(["test"]), csr_matrix([[0]]), csr_matrix([[0]])])
    legacy_model.predict_proba(probe)
except Exception:
    legacy_model = legacy_vectorizer = None


RISK_PHRASE_GROUPS = {
    "urgency language": URGENT_WORDS,
    "account or security bait": SECURITY_BAIT,
    "credential-harvesting language": INFO_HARVESTING,
    "deceptive call to action": CLICK_BAIT,
    "impersonation language": IMPERSONATION_BAIT,
    "financial bait": FINANCIAL_BAIT,
    "prize bait": PRIZE_BAIT,
    "technical-support scam language": TECH_SCAM,
}


def _matched_risk_phrases(text, limit=5):
    lower = text.lower()
    matches = []
    for category, phrases in RISK_PHRASE_GROUPS.items():
        for phrase in phrases:
            if phrase in lower:
                matches.append({"phrase": phrase, "category": category})
                break
    return matches[:limit]


def should_scan_url(url_analysis, keyword_score):
    """Only spend VirusTotal calls on URLs with meaningful risk signals."""
    return any((
        keyword_score >= 4, url_analysis["uses_ip"], url_analysis["is_shortened"],
        url_analysis["suspicious_tld"], url_analysis["many_subdomains"],
        url_analysis["has_at_symbol"], url_analysis["has_hex_encoding"],
        url_analysis["is_long"], url_analysis["is_http"],
        url_analysis["fake_brand_score"] >= 3, bool(url_analysis["brand_spoof"]),
    ))


def _legacy_top_tokens(text, keyword_score, total_url_score, label):
    """Return LR TF-IDF contributions when the legacy interpretable model exists."""
    if legacy_model is None or legacy_vectorizer is None:
        return []
    try:
        vector = legacy_vectorizer.transform([text])
        model_input = hstack([vector, csr_matrix([[keyword_score]]), csr_matrix([[total_url_score]])])
        names = list(legacy_vectorizer.get_feature_names_out()) + ["phishing keyword signals", "URL risk signals"]
        contributions = model_input.toarray()[0] * legacy_model.coef_[0]
        indexes = contributions.argsort()[::-1] if label == "PHISHING" else contributions.argsort()
        tokens = []
        for index in indexes:
            value = contributions[index]
            if (label == "PHISHING" and value <= 0) or (label == "SAFE" and value >= 0):
                continue
            name = names[index]
            if name == "phishing keyword signals" and keyword_score == 0:
                continue
            if name == "URL risk signals" and total_url_score == 0:
                continue
            tokens.append({"feature": name, "contribution": round(abs(float(value)), 4)})
            if len(tokens) == 5:
                break
        return tokens
    except Exception:
        return []


def _safe_reasons(text, url_analyses, vt_results):
    """Evidence-based negative explanations; never call an unchecked link safe."""
    lower = text.lower()
    reasons = []
    if not any(phrase in lower for phrase in URGENT_WORDS):
        reasons.append("No urgency or pressure language detected")
    if not any(phrase in lower for phrase in INFO_HARVESTING):
        reasons.append("No credential-harvesting request detected")
    if not any(phrase in lower for phrase in IMPERSONATION_BAIT):
        reasons.append("No impersonation language detected")

    if not url_analyses:
        reasons.append("No links to inspect")
    else:
        suspicious = any(
            item[key] for item in url_analyses for key in (
                "is_http", "uses_ip", "is_shortened", "suspicious_tld", "many_subdomains",
                "has_at_symbol", "has_hex_encoding", "is_long",
            )
        ) or any(item.get("brand_spoof") for item in url_analyses)
        if not suspicious:
            reasons.append("Link structure showed no spoofing indicators")

    completed = [r for r in vt_results if r.get("error") is None and r.get("checked")]
    if completed and not any(r["malicious"] or r["suspicious"] for r in completed):
        reasons.append("No malicious vendor detections in completed checks")
    elif vt_results and not completed:
        reasons.append("Vendor reputation was not available for this message")
    return reasons


def build_explainability(text, label, keyword_score, total_url_score, url_analyses, vt_results):
    matched_phrases = _matched_risk_phrases(text)
    top_features = _legacy_top_tokens(text, keyword_score, total_url_score, label)
    top_tokens = [item["feature"] for item in top_features if item["feature"] not in {"phishing keyword signals", "URL risk signals"}]
    if not top_tokens:
        top_tokens = [item["phrase"] for item in matched_phrases]

    if label == "PHISHING":
        reasons = []
        if matched_phrases:
            reasons.append("risky phrasing was detected")
        if keyword_score:
            reasons.append("the language-risk score was elevated")
        if total_url_score:
            reasons.append("URL or reputation signals added risk")
        why = "The model flagged this because " + (", ".join(reasons) or "its overall message pattern resembled phishing") + "."
        safe_reasons = []
    else:
        safe_reasons = _safe_reasons(text, url_analyses, vt_results)
        why = "Why Safe: " + ("; ".join(safe_reasons) if safe_reasons else "no strong phishing indicators were detected") + "."

    return {
        "top_contributing_tokens": top_tokens[:5],
        "top_features": top_features,
        "matched_phrases": matched_phrases,
        "why": why,
        "safe_reasons": safe_reasons,
    }


def generate_rule_explanations(text, keyword_score, url_score, vt_results):
    explanations = []
    phrases = _matched_risk_phrases(text)
    for item in phrases:
        explanations.append(f"⚠️ {item['category'].title()}: “{item['phrase']}”.")
    for index, original_url in enumerate(extract_urls(text)):
        normalized = normalize_url(original_url)
        explanations.extend([f"🔗 URL detected: {normalized}", f"🌐 Domain: {extract_domain(normalized)}"])
        if index >= len(vt_results):
            continue
        result = vt_results[index]
        if result["error"] == "not_scanned":
            explanations.append("ℹ️ VirusTotal scan skipped: this URL did not meet the high-risk scan threshold.")
        elif result["error"] == "no_key":
            explanations.append("ℹ️ VirusTotal check skipped (no API key).")
        elif result["error"]:
            explanations.append(f"⚠️ VirusTotal check unavailable: {result['error']}.")
        elif result["status"] == "queued":
            explanations.append("⏳ VirusTotal scan submitted; no completed report is available yet.")
        elif result["malicious"]:
            explanations.append(f"🚨 VirusTotal: {result['malicious']} vendor(s) flagged this URL as malicious.")
        elif result["suspicious"]:
            explanations.append(f"⚠️ VirusTotal: {result['suspicious']} vendor(s) flagged this URL as suspicious.")
        else:
            explanations.append(f"✅ VirusTotal: no vendor detections ({result['harmless']} harmless votes).")
    if url_score >= 6:
        explanations.append("🚨 High URL risk detected.")
    elif url_score >= 3:
        explanations.append("⚠️ Medium URL risk detected.")
    if keyword_score >= 6:
        explanations.append("🚨 High phishing keyword density detected.")
    return explanations


def legacy_prediction(text, keyword_score, total_url_score, rule_score):
    if legacy_model is None or legacy_vectorizer is None:
        if rule_score == 0:
            return "SAFE", 0.85, "rule engine"
        if rule_score >= 4:
            return "PHISHING", 0.82, "rule engine"
        if rule_score >= 2:
            return "PHISHING", 0.70, "rule engine"
        return "SAFE", 0.65, "rule engine"
    vector = legacy_vectorizer.transform([text])
    model_input = hstack([vector, csr_matrix([[keyword_score]]), csr_matrix([[total_url_score]])])
    safe_probability, phishing_probability = legacy_model.predict_proba(model_input)[0]
    if phishing_probability >= 0.5 or rule_score >= 2:
        return "PHISHING", float(phishing_probability), "legacy logistic regression"
    return "SAFE", float(safe_probability), "legacy logistic regression"


def apply_vt_confidence_guardrail(confidence, label, vt_results):
    completed = [r for r in vt_results if r.get("error") is None and r.get("checked")]
    suspicious = any(r["malicious"] or r["suspicious"] for r in completed)
    harmless = any(r["harmless"] for r in completed)
    if suspicious and harmless:
        return min(confidence, 0.80), "Confidence limited because VirusTotal returned mixed vendor results."
    if label == "PHISHING" and harmless and not suspicious:
        return min(confidence, 0.80), "Confidence limited because VirusTotal found no vendor detections."
    return confidence, None


def predict_message(text: str):
    features = extract_features(text)
    keyword_score, url_score = features["keyword_score"], features["url_score"]
    urls, url_analyses = extract_urls(text), get_url_analysis(text)
    analyses = {item["raw_url"]: item for item in url_analyses}
    vt_results, total_vt_score, scans_used = [], 0, 0
    for url in urls:
        analysis = analyses.get(url)
        if analysis and scans_used < MAX_VIRUSTOTAL_SCANS_PER_MESSAGE and should_scan_url(analysis, keyword_score):
            result = check_virustotal(url)
            scans_used += 1
        else:
            result = {"score": 0, "malicious": 0, "suspicious": 0, "harmless": 0, "error": "not_scanned", "status": "skipped", "checked": False}
        vt_results.append(result)
        if result["error"] is None:
            total_vt_score += result["score"]

    total_url_score = url_score + total_vt_score
    rule_score = keyword_score + total_url_score
    rule_explanations = generate_rule_explanations(text, keyword_score, total_url_score, vt_results)
    ensemble = predict_ensemble(text, keyword_score, total_url_score)
    if ensemble["available"]:
        phishing_probability = ensemble["phishing_probability"]
        label = "PHISHING" if phishing_probability >= .50 else "SAFE"
        confidence = phishing_probability if label == "PHISHING" else 1 - phishing_probability
        model_source = f"calibrated ensemble v{ensemble['model_version']}"
        rule_explanations.append(f"🧠 Calibrated ensemble: LightGBM {ensemble['lightgbm_probability']:.0%}, DistilBERT {ensemble['distilbert_probability']:.0%} phishing risk.")
    else:
        label, confidence, model_source = legacy_prediction(text, keyword_score, total_url_score, rule_score)
        rule_explanations.append(f"ℹ️ Calibrated ensemble unavailable; using {model_source} fallback.")

    # These values are intentionally initialized before AI blending and before
    # the scores dictionary is built.
    confidence_before_ai = round(confidence, 2)
    ai_adjusted = False
    ai_result = get_ai_reasoning(text, keyword_score, total_url_score, vt_results, url_analyses)
    if ai_result.get("used") and ai_result.get("confidence") is not None:
        ai_confidence, ai_verdict = float(ai_result["confidence"]), ai_result.get("verdict")
        agrees = (label == "PHISHING" and ai_verdict == "PHISHING") or (label == "SAFE" and ai_verdict == "SAFE")
        if (confidence < .72 or 2 <= rule_score <= 6) and ai_confidence >= .75 and agrees:
            confidence = min(confidence * .60 + ai_confidence * .40, .99 if label == "PHISHING" else .97)
            ai_adjusted = round(confidence, 2) != confidence_before_ai
    confidence, vt_note = apply_vt_confidence_guardrail(confidence, label, vt_results)
    if vt_note:
        rule_explanations.append(f"ℹ️ {vt_note}")

    explainability = build_explainability(text, label, keyword_score, total_url_score, url_analyses, vt_results)
    scores = {
        "keyword_score": keyword_score, "max_keyword_risk": MAX_KEYWORD_RISK,
        "url_score": min(url_score, 10), "vt_score": min(total_vt_score, 10),
        "confidence_pre_ai": confidence_before_ai, "ai_adjusted": ai_adjusted,
        "model_source": model_source, "virustotal_scans_used": scans_used,
        "ensemble": ensemble, "explainability": explainability,
    }
    return label, round(confidence, 2), min(total_url_score, 10), rule_explanations, url_analyses, ai_result, scores
