import email
import io
import os
import re
import sys
from email import policy
from html.parser import HTMLParser

import streamlit as st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.predict import predict_message

try:
    GEMINI_KEY_SET = bool(st.secrets.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY"))
except Exception:
    GEMINI_KEY_SET = bool(os.getenv("GEMINI_API_KEY"))

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
html,body,[class*="css"]{font-family:'IBM Plex Sans',sans-serif} h1,h2,h3{font-family:'IBM Plex Mono',monospace}
.verdict{border:1.5px solid;border-radius:8px;padding:16px 20px;font:600 1.35rem 'IBM Plex Mono';letter-spacing:.04em}.danger{color:#ff5555}.safe{color:#28ca60}
.card{border:1px solid #2a2a2a;border-radius:8px;padding:14px;text-align:center}.label{font-size:.7rem;color:#888;text-transform:uppercase;letter-spacing:.1em}.value{font-size:1.8rem;font-weight:600}.low{color:#28ca60}.medium{color:#ffaa00}.high{color:#ff5555}
.section{font:600 .72rem 'IBM Plex Mono';color:#777;text-transform:uppercase;letter-spacing:.12em;border-bottom:1px solid #292929;padding-bottom:6px;margin:12px 0}.pill{display:inline-block;border:1px solid #777;border-radius:4px;padding:3px 8px;margin:2px;font:.72rem 'IBM Plex Mono'}.ai{border:1px solid #1a3a6a;border-radius:8px;padding:16px;line-height:1.6}
</style>""", unsafe_allow_html=True)


class _HTMLTextExtractor(HTMLParser):
    SKIP_TAGS = {"style", "script", "head"}
    def __init__(self):
        super().__init__(convert_charrefs=True); self.skip = 0; self.chunks = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.SKIP_TAGS: self.skip += 1
    def handle_endtag(self, tag):
        if tag.lower() in self.SKIP_TAGS: self.skip = max(0, self.skip - 1)
        if tag.lower() in {"p", "br", "div", "tr", "li", "h1", "h2", "h3", "h4"}: self.chunks.append("\n")
    def handle_data(self, data):
        if not self.skip: self.chunks.append(data)
    def text(self):
        return re.sub(r"\n{3,}", "\n\n", re.sub(r" {2,}", " ", "".join(self.chunks))).strip()


def _html_to_text(value):
    parser = _HTMLTextExtractor(); parser.feed(value); return parser.text()


def _ocr(image_bytes):
    try:
        import pytesseract
        from PIL import Image, ImageEnhance, ImageFilter
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        if image.width < 1000:
            scale = 1000 / image.width; image = image.resize((int(image.width * scale), int(image.height * scale)), Image.LANCZOS)
        return pytesseract.image_to_string(ImageEnhance.Contrast(image.filter(ImageFilter.SHARPEN)).enhance(1.5), config="--oem 3 --psm 6").strip()
    except Exception as error:
        return f"[OCR error: {error}]"


def extract_text(upload):
    name, data = upload.name.lower(), upload.read()
    if name.endswith(".txt"): return data.decode("utf-8", errors="ignore"), "plain text"
    if name.endswith(".eml"):
        message = email.message_from_string(data.decode("utf-8", errors="ignore"), policy=policy.default)
        headers = [f"{key}: {message.get(key)}" for key in ("From", "Subject") if message.get(key)]
        plain, html = [], []
        for part in message.walk() if message.is_multipart() else [message]:
            try: content = part.get_content() or ""
            except Exception: content = ""
            if part.get_content_type() == "text/plain": plain.append(content)
            elif part.get_content_type() == "text/html": html.append(content)
        body = "\n".join(plain).strip() or _html_to_text("\n".join(html))
        return "\n\n".join(["\n".join(headers), body]).strip(), "email parser"
    if name.endswith((".png", ".jpg", ".jpeg", ".webp")): return _ocr(data), "Tesseract OCR"
    return f"[Unsupported file type: {name}]", "none"


def score_style(value):
    return "high" if value >= 6 else "medium" if value >= 3 else "low"


st.markdown("## 🛡️ PhishGuard AI")
st.caption("Multi-layer threat analysis · ML + rule engine + VirusTotal + Gemini AI")
if "extracted_text" not in st.session_state: st.session_state.extracted_text = ""
upload = st.file_uploader("📎 Upload file to auto-fill (PNG, JPG, WEBP, EML, TXT)", type=["png", "jpg", "jpeg", "webp", "eml", "txt"])
if upload:
    with st.spinner("Extracting text…"):
        extracted, method = extract_text(upload)
    if extracted.startswith("["): st.error(extracted)
    else:
        st.session_state.extracted_text = extracted; st.success(f"Extracted via {method}.")
message = st.text_area("Paste message, email, or URL:", value=st.session_state.extracted_text, height=180, placeholder="Paste any suspicious message, email body, or URL here…")

if st.button("⚡ Analyze Threat", type="primary"):
    if not message.strip():
        st.warning("Please enter some text first."); st.stop()
    with st.spinner("Running multi-layer analysis…"):
        label, confidence, _, rule_explanations, url_analyses, ai_result, scores = predict_message(message)

    adjusted, before = scores["ai_adjusted"], scores["confidence_pre_ai"]
    delta = f" · AI adjusted {confidence - before:+.0%}" if adjusted else ""
    st.markdown(f'<div class="verdict {"danger" if label == "PHISHING" else "safe"}">{"⚠️ PHISHING DETECTED" if label == "PHISHING" else "✅ SAFE"} · {confidence:.0%} confidence{delta}</div>', unsafe_allow_html=True)

    max_keyword_risk = scores["max_keyword_risk"]
    language = round(min(scores["keyword_score"] / max_keyword_risk * 10, 10), 1)
    url, intel = scores["url_score"], scores["vt_score"]
    overall = round(language * .30 + url * .40 + intel * .30, 1)
    columns = st.columns(3)
    for column, name, subtitle, value in ((columns[0], "Language", f"30% · max risk {max_keyword_risk}", language), (columns[1], "URL Structure", "40% · link manipulation", url), (columns[2], "External Intel", "30% · VirusTotal vendors", intel)):
        column.markdown(f'<div class="card"><div class="label">{name}</div><div class="value {score_style(value)}">{value}<span style="font-size:.9rem;color:#777">/10</span></div><div class="label">{subtitle}</div></div>', unsafe_allow_html=True)
    st.caption(f"Signal score {overall}/10 is separate from confidence ({confidence:.0%}), which comes from the trained classifier.")

    explain = scores["explainability"]
    with st.expander("🔎 Model Explainability", expanded=True):
        st.markdown('<div class="section">Trust and interpretability</div>', unsafe_allow_html=True)
        tokens = explain["top_contributing_tokens"]
        if tokens:
            st.write("📊 **Top contributing words / phrases:** " + ", ".join(f"`{token}`" for token in tokens))
        else:
            st.write("📊 **Top contributing words / phrases:** No single token had a strong standalone effect.")
        st.write("🧠 " + explain["why"])
        if label == "SAFE":
            st.caption("A Safe verdict means no strong indicators were found; it is not proof that a sender or link is trustworthy.")
        if explain["top_features"]:
            st.caption("Feature importance is calculated from the legacy logistic-regression model when it is available; phrase matches are otherwise shown as supporting evidence.")

    if url_analyses:
        with st.expander("🔗 URL Analysis", expanded=True):
            for item in url_analyses:
                st.write(f"**`{item['domain']}`** · `{item['tld']}`")
                flags = []
                for key, text, colour in (("is_http", "HTTP (not HTTPS)", "#ff5555"), ("uses_ip", "IP-based URL", "#ff5555"), ("is_shortened", "URL shortener", "#ffaa00"), ("suspicious_tld", f"Suspicious TLD {item['tld']}", "#ff5555"), ("many_subdomains", f"{item['subdomain_count']} subdomains", "#ffaa00"), ("has_at_symbol", "@ symbol", "#ff5555"), ("has_hex_encoding", "Hex encoding", "#ffaa00"), ("is_long", f"Long URL ({item['url_length']} chars)", "#ffaa00")):
                    if item[key]: flags.append((text, colour))
                if item.get("brand_spoof"): flags.append((f"Possible {item['brand_spoof'].title()} spoof", "#ff5555"))
                if not flags: flags = [("No major structural flags", "#28ca60")]
                st.markdown("".join(f'<span class="pill" style="color:{colour};border-color:{colour}">{text}</span>' for text, colour in flags), unsafe_allow_html=True)

    with st.expander("🚦 Risk Indicators", expanded=True):
        for explanation in rule_explanations: st.write(explanation)
        if not rule_explanations: st.write("🟢 No phishing indicators detected by rule engine.")

    st.markdown('<div class="section">AI Security Analysis</div>', unsafe_allow_html=True)
    reasoning = ai_result.get("reasoning") if ai_result.get("used") else None
    if reasoning and not reasoning.strip().startswith(("{", "[")):
        st.markdown(f'<div class="ai">{reasoning}</div>', unsafe_allow_html=True)
    elif ai_result.get("error") == "no_key" or (not ai_result.get("used") and not GEMINI_KEY_SET):
        st.info("Add a GEMINI_API_KEY to enable AI-powered analysis.")
    elif not ai_result.get("used"):
        st.success("Risk below the AI threshold — rule-engine and model evidence shown above.")
    else:
        st.warning(f"AI analysis failed ({ai_result.get('error') or 'unknown error'}). Rule-based analysis is shown above.")
