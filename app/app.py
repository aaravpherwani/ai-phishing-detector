import streamlit as st
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.predict import predict_message

st.set_page_config(page_title="AI Phishing Detector")
st.title("🖲️ AI Phishing Detector")
st.write("Enter a message, email, or URL to check if it's phishing.")

user_input = st.text_area(
    "Paste message or URL here:",
    height=200,
    placeholder="Example:\n\nSender Email/Number\nSubject (if email)\nContent of Message..."
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
                st.warning("⚠️ The AI model flagged this as suspicious based on learned patterns, but no specific indicators were identified.")
