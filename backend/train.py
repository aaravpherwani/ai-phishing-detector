import os
import email
import joblib
import numpy as np
import pandas as pd
from email import policy
from datasets import load_dataset
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from backend.features import extract_features

print("Starting training...")
os.makedirs("models", exist_ok=True)

# -----------------------------
# Load ucirvine/sms_spam from HuggingFace
# -----------------------------
print("Downloading spam dataset from HuggingFace...")
ds = load_dataset("ucirvine/sms_spam")
hf_df = ds["train"].to_pandas()

print(f"HuggingFace columns: {hf_df.columns.tolist()}")
print(hf_df.head(2))

hf_df = hf_df.rename(columns={"sms": "text"})
hf_df = hf_df[["text", "label"]].dropna()
hf_df["label"] = hf_df["label"].astype(int)

print(f"Spam dataset loaded: {len(hf_df)} messages")
print(f"  Ham:  {sum(hf_df['label'] == 0)}")
print(f"  Spam: {sum(hf_df['label'] == 1)}")

# -----------------------------
# Load phishing-2025.txt (Nazario)
# -----------------------------
def load_mbox_file(filepath):
    texts = []
    current = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("From ") and current:
                raw = "".join(current)
                msg = email.message_from_string(raw, policy=policy.default)
                subject = msg.get("subject", "") or ""
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body += part.get_content() or ""
                            except:
                                pass
                else:
                    try:
                        body = msg.get_content() or ""
                    except:
                        body = ""
                text = (subject + " " + body).strip()
                if text and len(text) > 10:
                    texts.append(text)
                current = [line]
            else:
                current.append(line)
    return texts

print("\nLoading phishing-2025.txt...")
phishing_texts = load_mbox_file("data/phishing-2025.txt")
print(f"  {len(phishing_texts)} phishing emails loaded")

phishing_df = pd.DataFrame({
    "text": phishing_texts,
    "label": [1] * len(phishing_texts)
})

# -----------------------------
# Combine datasets
# -----------------------------
df = pd.concat([hf_df, phishing_df], ignore_index=True)
df = df[df["text"].str.len() > 20].reset_index(drop=True)

print(f"\nFinal dataset: {len(df)} samples")
print(f"  Legitimate (0): {sum(df['label'] == 0)}")
print(f"  Phishing/Spam (1): {sum(df['label'] == 1)}")

# -----------------------------
# Extract keyword + URL features
# -----------------------------
print("\nExtracting features...")
feature_rows = df["text"].apply(extract_features)
keyword_scores = np.array([r["keyword_score"] for r in feature_rows]).reshape(-1, 1)
url_scores = np.array([r["url_score"] for r in feature_rows]).reshape(-1, 1)

# -----------------------------
# Train/test split
# -----------------------------
X_train_text, X_test_text, y_train, y_test = train_test_split(
    df["text"], df["label"],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

train_idx = X_train_text.index
test_idx = X_test_text.index

# -----------------------------
# TF-IDF vectorization
# -----------------------------
print("Vectorizing...")
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=10000,
    sublinear_tf=True,
    min_df=2
)
X_train_tfidf = vectorizer.fit_transform(X_train_text)
X_test_tfidf = vectorizer.transform(X_test_text)

# -----------------------------
# Stack TF-IDF + keyword + URL scores
# -----------------------------
X_train_combined = hstack([
    X_train_tfidf,
    csr_matrix(keyword_scores[train_idx]),
    csr_matrix(url_scores[train_idx])
])
X_test_combined = hstack([
    X_test_tfidf,
    csr_matrix(keyword_scores[test_idx]),
    csr_matrix(url_scores[test_idx])
])

# -----------------------------
# Train model
# -----------------------------
print("Training model...")
model = LogisticRegression(
    max_iter=1000,
    C=1.0,
    class_weight="balanced",
    solver="lbfgs"
)
model.fit(X_train_combined, y_train)

# -----------------------------
# Evaluation
# -----------------------------
y_pred = model.predict(X_test_combined)

print("\n========== MODEL EVALUATION ==========")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(f"  True Negatives  (legit correct):    {cm[0][0]}")
print(f"  False Positives (legit flagged):     {cm[0][1]}")
print(f"  False Negatives (phishing missed):   {cm[1][0]}")
print(f"  True Positives  (phishing caught):   {cm[1][1]}")
print("=======================================\n")

# -----------------------------
# Save model
# -----------------------------
joblib.dump(model, "models/model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print("Model trained and saved successfully!")