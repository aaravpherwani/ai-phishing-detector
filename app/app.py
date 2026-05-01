import streamlit as st
import sys
import os
import email
from email import policy
import base64
import io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.predict import predict_message

st.set_page_config(page_title="AI Phishing Detector")
st.title("🖲️ AI Phishing Detector")
st.write("Enter a message, email, or URL to check if it's phishing.")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ocr_with_tesseract(image_bytes: bytes) -> str:
    """Run Tesseract OCR on raw image bytes and return extracted text."""
    try:
        import pytesseract
        from PIL import Image, ImageFilter, ImageEnhance

        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # Preprocess: upscale small images, sharpen, boost contrast
        # so Tesseract handles low-res screenshots better
        w, h = img.size
        if w < 1000:
            scale = 1000 / w
            img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

        img = img.filter(ImageFilter.SHARPEN)
        img = ImageEnhance.Contrast(img).enhance(1.5)

        # PSM 6 = assume uniform block of text (good for email screenshots)
        custom_config = r"--oem 3 --psm 6"
        text = pytesseract.image_to_string(img, config=custom_config)
        return text.strip()

    except ImportError:
        return (
            "[Error: pytesseract not installed. "
            "Run: pip install pytesseract pillow  "
            "and install Tesseract: https://github.com/tesseract-ocr/tesseract]"
        )
    except pytesseract.TesseractNotFoundError:
        return (
            "[Error: Tesseract binary not found. "
            "Install it via 'sudo apt install tesseract-ocr' (Linux) "
            "or 'brew install tesseract' (Mac).]"
        )
    except Exception as e:
        return f"[OCR error: {e}]"


def extract_text_from_image(file_bytes: bytes) -> tuple[str, str]:
    """Extract text from an image using Tesseract OCR."""
    return _ocr_with_tesseract(file_bytes), "Tesseract OCR"


# --------------------------------------------------------------------------- #
# Main extraction dispatcher
# --------------------------------------------------------------------------- #

def extract_text_from_file(uploaded_file):
    """Extract text from uploaded file based on its type."""
    filename = uploaded_file.name.lower()
    file_bytes = uploaded_file.read()

    # --- Plain text ---
    if filename.endswith(".txt"):
        return file_bytes.decode("utf-8", errors="ignore"), "plain text"

    # --- EML (email) ---
    if filename.endswith(".eml"):
        raw = file_bytes.decode("utf-8", errors="ignore")
        msg = email.message_from_string(raw, policy=policy.default)

        parts = []
        sender = msg.get("From", "")
        subject = msg.get("Subject", "")
        if sender:
            parts.append(f"From: {sender}")
        if subject:
            parts.append(f"Subject: {subject}")

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        parts.append(part.get_content() or "")
                    except Exception:
                        pass
        else:
            try:
                parts.append(msg.get_content() or "")
            except Exception:
                pass

        return "\n".join(parts).strip(), "email parser"

    # --- Image (PNG, JPG, JPEG, WEBP) ---
    if filename.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return extract_text_from_image(file_bytes)

    return f"[Unsupported file type: {filename}]", "none"


# --- File uploader ---
uploaded_file = st.file_uploader(
    "📎 Upload a file to auto-fill (image, .eml, .txt)",
    type=["png", "jpg", "jpeg", "webp", "eml", "txt"],
    label_visibility="visible",
)

# Track extracted text in session state so it persists across reruns
if "extracted_text" not in st.session_state:
    st.session_state.extracted_text = ""

if uploaded_file is not None:
    with st.spinner(f"Extracting text from {uploaded_file.name}..."):
        extracted, method = extract_text_from_file(uploaded_file)

    if extracted.startswith("[Error") or extracted.startswith("[Unsupported") or extracted.startswith("[OCR"):
        st.error(extracted)
    else:
        st.session_state.extracted_text = extracted
        method_emoji = {
            "Tesseract OCR": "🤖",
            "email parser": "📧",
            "plain text": "📄",
        }.get(method, "✅")
        st.success(f"{method_emoji} Text extracted via **{method}** from **{uploaded_file.name}**.")

# --- Text area (pre-filled if file was uploaded) ---
user_input = st.text_area(
    "Paste message or URL here:",
    value=st.session_state.extracted_text,
    height=200,
    placeholder="Example:\n\nSender Email/Number\nSubject (if email)\nContent of Message...",
)

if st.button("Check Message"):
    if user_input.strip() == "":
        st.warning("Please enter some text.")
    else:
        with st.spinner("Analyzing message... checking URLs against VirusTotal..."):
            label, confidence, url_score, explanations = predict_message(user_input)

        if label == "PHISHING":
            st.error(f"⚠️ {label}")
        else:
            st.success(f"✅ {label}")

        st.write(f"**Confidence:** {confidence:.0%}")
        st.write(f"**URL Risk Score:** {min(url_score, 10)}/10")

        st.subheader("🧠 AI Explanation")

        if explanations and len(explanations) > 0:
            for exp in explanations:
                st.write("- " + exp)
        else:
            if label == "SAFE":
                st.success("🟢 No phishing indicators detected. Message appears safe.")
            else:
                st.warning(
                    "⚠️ The AI model flagged this as suspicious based on learned patterns, "
                    "but no specific indicators were identified."
                )
