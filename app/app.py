import streamlit as st
import sys
import os
import email
from email import policy
import io
import re
from html.parser import HTMLParser

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.predict import predict_message

try:
    import streamlit as _st
    GEMINI_KEY_SET = bool(_st.secrets.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY"))
except Exception:
    GEMINI_KEY_SET = bool(os.getenv("GEMINI_API_KEY"))

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');
html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
h1, h2, h3 { font-family: 'IBM Plex Mono', monospace; }
.verdict-phishing {
    border: 1.5px solid #ff3333; border-radius: 8px; padding: 16px 20px;
    color: #ff4444; font-family: 'IBM Plex Mono', monospace;
    font-size: 1.4rem; font-weight: 600; letter-spacing: 0.05em;
}
.verdict-safe {
    border: 1.5px solid #00cc44; border-radius: 8px; padding: 16px 20px;
    color: #00dd44; font-family: 'IBM Plex Mono', monospace;
    font-size: 1.4rem; font-weight: 600; letter-spacing: 0.05em;
}
.score-card { border: 1px solid #2a2a2a; border-radius: 8px; padding: 14px 18px; text-align: center; }
.score-label { font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 0.1em; font-family: 'IBM Plex Sans', sans-serif; }
.score-value { font-size: 1.8rem; font-weight: 600; font-family: 'IBM Plex Sans', sans-serif; margin: 4px 0 0 0; }
.score-denom { font-size: 0.9rem; font-weight: 400; color: #666; }
.score-high  { color: #ff4444; }
.score-med   { color: #ffaa00; }
.score-low   { color: #00dd44; }
.ai-box {
    border: 1px solid #1a3a6a;
    border-radius: 8px;
    padding: 18px 22px;
    line-height: 1.7;
    color: #1a2a3a;
    font-size: 0.95rem;
}
@media (prefers-color-scheme: dark) {
    .ai-box { color: #c8d8f0; }
}
.ai-badge { display: inline-block; color: #4d9fff; border: 1px solid #1a4a8a; border-radius: 4px; font-family: 'IBM Plex Mono', monospace; font-size: 0.65rem; letter-spacing: 0.12em; padding: 2px 8px; margin-bottom: 10px; text-transform: uppercase; }
.indicator-pill { display: inline-block; border-radius: 4px; padding: 3px 10px; font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; margin: 3px 3px 3px 0; font-weight: 600; }
.pill-danger { color: #ff5555; border: 1px solid #ff5555; }
.pill-warn   { color: #ffaa00; border: 1px solid #ffaa00; }
.pill-ok     { color: #44cc66; border: 1px solid #44cc66; }
.section-head { font-family: 'IBM Plex Mono', monospace; font-size: 0.7rem; color: #555; text-transform: uppercase; letter-spacing: 0.15em; border-bottom: 1px solid #1e1e1e; padding-bottom: 6px; margin-bottom: 12px; }
</style>
""", unsafe_allow_html=True)


class _HTMLTextExtractor(HTMLParser):
    SKIP_TAGS = {"style", "script", "head"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._skip = 0; self.chunks = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.SKIP_TAGS: self._skip += 1
    def handle_endtag(self, tag):
        if tag.lower() in self.SKIP_TAGS: self._skip = max(0, self._skip - 1)
        if tag.lower() in {"p","br","div","tr","li","h1","h2","h3","h4"}: self.chunks.append("\n")
    def handle_data(self, data):
        if self._skip == 0: self.chunks.append(data)
    def get_text(self):
        raw = "".join(self.chunks)
        raw = re.sub(r" {2,}", " ", raw)
        return re.sub(r"\n{3,}", "\n\n", raw).strip()

def _html_to_text(html):
    p = _HTMLTextExtractor(); p.feed(html); return p.get_text()

def _ocr_with_tesseract(image_bytes):
    try:
        import pytesseract
        from PIL import Image, ImageFilter, ImageEnhance
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        w, h = img.size
        if w < 1000:
            scale = 1000 / w
            img = img.resize((int(w*scale), int(h*scale)), Image.LANCZOS)
        img = img.filter(ImageFilter.SHARPEN)
        img = ImageEnhance.Contrast(img).enhance(1.5)
        return pytesseract.image_to_string(img, config=r"--oem 3 --psm 6").strip()
    except ImportError:
        return "[Error: pytesseract not installed.]"
    except Exception as e:
        return f"[OCR error: {e}]"

def extract_text_from_file(uploaded_file):
    filename = uploaded_file.name.lower()
    file_bytes = uploaded_file.read()
    if filename.endswith(".txt"):
        return file_bytes.decode("utf-8", errors="ignore"), "plain text"
    if filename.endswith(".eml"):
        raw = file_bytes.decode("utf-8", errors="ignore")
        msg = email.message_from_string(raw, policy=policy.default)
        headers = []
        if msg.get("From"): headers.append(f"From: {msg.get('From')}")
        if msg.get("Subject"): headers.append(f"Subject: {msg.get('Subject')}")
        plain_parts, html_parts = [], []
        for part in (msg.walk() if msg.is_multipart() else [msg]):
            ct = part.get_content_type()
            try: content = part.get_content() or ""
            except: content = ""
            if ct == "text/plain": plain_parts.append(content)
            elif ct == "text/html": html_parts.append(content)
        body = "\n".join(plain_parts).strip() if plain_parts else _html_to_text("\n".join(html_parts))
        result = "\n".join(headers)
        if body: result = (result + "\n\n" + body).strip()
        return result, "email parser"
    if filename.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return _ocr_with_tesseract(file_bytes), "Tesseract OCR"
    return f"[Unsupported file type: {filename}]", "none"

def _score_class(val, max_val=10):
    ratio = val / max_val if max_val else 0
    if ratio >= 0.6: return "score-high"
    if ratio >= 0.3: return "score-med"
    return "score-low"


# ═══════════════════════════ UI ═══════════════════════════════════════════════

st.markdown("## 🛡️ PhishGuard AI")
st.markdown("<span style='color:#555; font-size:0.9rem;'>Multi-layer threat analysis · ML + rule engine + VirusTotal + Gemini AI</span>", unsafe_allow_html=True)
st.markdown("---")

if "extracted_text" not in st.session_state:
    st.session_state.extracted_text = ""

# Full-width uploader above text area — no truncation
uploaded_file = st.file_uploader(
    "📎 Upload file to auto-fill (PNG, JPG, WEBP, EML, TXT)",
    type=["png", "jpg", "jpeg", "webp", "eml", "txt"],
)

if uploaded_file is not None:
    with st.spinner(f"Extracting text from {uploaded_file.name}…"):
        extracted, method = extract_text_from_file(uploaded_file)
    if any(extracted.startswith(p) for p in ("[Error", "[Unsupported", "[OCR")):
        st.error(extracted)
    else:
        st.session_state.extracted_text = extracted
        icons = {"Tesseract OCR": "🤖", "email parser": "📧", "plain text": "📄"}
        st.success(f"{icons.get(method,'✅')} Extracted via **{method}** — pasted below.")

user_input = st.text_area(
    "Paste message, email, or URL:",
    value=st.session_state.extracted_text,
    height=180,
    placeholder="Paste any suspicious message, email body, or URL here…",
)

analyze_btn = st.button("⚡ Analyze Threat", type="primary")

if analyze_btn:
    if not user_input.strip():
        st.warning("Please enter some text first.")
        st.stop()

    with st.spinner("Running multi-layer analysis…"):
        (label, confidence, url_score_capped,
         rule_explanations, url_analyses, ai_result, scores) = predict_message(user_input)

    st.markdown("---")

    # Verdict — border only, no background
    verdict_class = "verdict-phishing" if label == "PHISHING" else "verdict-safe"
    verdict_icon  = "⚠️ PHISHING DETECTED" if label == "PHISHING" else "✅ SAFE"
    st.markdown(f'<div class="{verdict_class}">{verdict_icon} &nbsp;·&nbsp; {confidence:.0%} confidence</div>', unsafe_allow_html=True)
    st.markdown(" ")

    # Score cards
    kw      = scores["keyword_score"]
    us      = scores["url_score"]
    vts     = scores["vt_score"]
    kw_norm = round(min(kw / 2, 10), 1)
    overall = round(min((kw_norm + us + vts) / 3, 10), 1)

    sc1, sc2, sc3, sc4 = st.columns(4)
    for col, lbl, val in [(sc1,"Keyword Risk",kw_norm),(sc2,"URL Risk",us),(sc3,"VirusTotal",vts),(sc4,"Overall Risk",overall)]:
        cls = _score_class(val)
        with col:
            st.markdown(
                f'<div class="score-card"><div class="score-label">{lbl}</div>'
                f'<div class="score-value {cls}">{val}<span class="score-denom">/10</span></div></div>',
                unsafe_allow_html=True)
    st.markdown(" ")

    # Bar chart — hidden when all zero, horizontal labels via transposed DataFrame
    if kw_norm > 0 or us > 0 or vts > 0:
        with st.expander("📊 Feature Score Breakdown", expanded=True):
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(3, 1))
            categories = ["Keyword Risk", "URL Risk", "VirusTotal"]
            values     = [kw_norm, us, vts]
            colors     = [
                "#ff4444" if v >= 6 else "#ffaa00" if v >= 3 else "#00dd44"
                for v in values
            ]
            bars = ax.bar(categories, values, color=colors, width=0.45, zorder=3)
            ax.set_ylim(0, 10)
            ax.set_ylabel("Score /10", fontsize=8, color="#888")
            ax.tick_params(axis="x", labelsize=9)
            ax.tick_params(axis="y", labelsize=8, colors="#888")
            ax.set_facecolor("none")
            fig.patch.set_alpha(0)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["left"].set_color("#333")
            ax.spines["bottom"].set_color("#333")
            ax.yaxis.label.set_color("#888")
            ax.tick_params(colors="#888")
            ax.grid(axis="y", color="#333", linewidth=0.5, zorder=0)
            for bar, val in zip(bars, values):
                if val > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.15,
                            str(val), ha="center", va="bottom", fontsize=8, color="#888")
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)

    # URL breakdown
    if url_analyses:
        with st.expander("🔗 URL Analysis", expanded=True):
            st.markdown('<div class="section-head">Detailed URL breakdown</div>', unsafe_allow_html=True)
            for u in url_analyses:
                st.markdown(f"**`{u['domain']}`** &nbsp; `{u['tld']}`")
                pills = []
                if u["is_http"]:          pills.append(('danger','HTTP (not HTTPS)'))
                if u["uses_ip"]:          pills.append(('danger','IP-based URL'))
                if u["is_shortened"]:     pills.append(('warn','URL Shortener'))
                if u["suspicious_tld"]:   pills.append(('danger',f'Suspicious TLD {u["tld"]}'))
                if u["many_subdomains"]:  pills.append(('warn',f'{u["subdomain_count"]} Subdomains'))
                if u["brand_spoof"]:      pills.append(('danger',f'Possible {u["brand_spoof"].title()} Spoof'))
                if u["has_at_symbol"]:    pills.append(('danger','@ Symbol'))
                if u["has_hex_encoding"]: pills.append(('warn','Hex Encoding'))
                if u["is_long"]:          pills.append(('warn',f'Long URL ({u["url_length"]} chars)'))
                if not pills:             pills.append(('ok','No major flags'))
                st.markdown("".join(f'<span class="indicator-pill pill-{c}">{t}</span>' for c,t in pills), unsafe_allow_html=True)
                st.markdown(" ")

    # Risk indicators
    with st.expander("🚦 Risk Indicators", expanded=True):
        st.markdown('<div class="section-head">Automated rule engine</div>', unsafe_allow_html=True)
        if rule_explanations:
            for exp in rule_explanations: st.write(exp)
        else:
            st.write("🟢 No phishing indicators detected by rule engine.")

    # AI section
    st.markdown(" ")
    st.markdown('<div class="section-head">AI Security Analysis</div>', unsafe_allow_html=True)

    reasoning = None
    if ai_result.get("used") and ai_result.get("reasoning"):
        r = ai_result["reasoning"].strip()
        if not (r.startswith("{") or r.startswith("[")):
            reasoning = r

    if ai_result.get("used") and reasoning:
        cached_note = " · cached" if ai_result.get("cached") else ""
        model_name  = ai_result.get("model", "gemini")
        st.markdown(f'<div class="ai-box"><div class="ai-badge">{model_name}{cached_note}</div><br>{reasoning}</div>', unsafe_allow_html=True)
        if ai_result.get("key_indicators"):
            st.markdown(" ")
            st.markdown("".join(f'<span class="indicator-pill pill-warn">{i}</span>' for i in ai_result["key_indicators"]), unsafe_allow_html=True)
        if ai_result.get("primary_threat"):
            st.caption(f"Primary threat category: **{ai_result['primary_threat']}**")
    else:
        err = ai_result.get("error")
        if err == "no_key" or (not ai_result.get("used") and not GEMINI_KEY_SET):
            st.info("Add a **GEMINI_API_KEY** to your Streamlit secrets to enable AI-powered explanations.", icon="🔑")
        elif err == "rate_limited":
            st.warning("⏱️ Gemini rate limit reached. Rule-based analysis shown above.")
        elif not ai_result.get("used"):
            st.success("🟢 Risk below AI threshold — rule engine found no significant indicators.")
        else:
            st.warning(f"⚠️ AI analysis failed ({err or 'unknown error'}). Rule-based analysis shown above.")
