"""
Deployment-only ensemble runtime.

Artifact contract for the Hugging Face model repository:

metadata.json
lightgbm_model.joblib
lightgbm_vectorizer.joblib
distilbert/
    config.json
    model.safetensors (or pytorch_model.bin)
    tokenizer.json
    tokenizer_config.json
    vocab.txt
"""

import json
import os
from functools import lru_cache

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack


def _setting(name, default=None):
    try:
        import streamlit as st

        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass

    return os.getenv(name, default)


HF_MODEL_REPO = _setting("HF_MODEL_REPO")
HF_MODEL_REVISION = _setting("HF_MODEL_REVISION", "main")
HF_TOKEN = _setting("HF_TOKEN")
LOCAL_MODEL_DIR = _setting("PHISHGUARD_LOCAL_MODEL_DIR")


@lru_cache(maxsize=1)
def get_artifact_directory():
    """
    Resolve the artifact directory.

    Local artifacts take precedence for development. Production downloads the
    model snapshot from Hugging Face into the machine cache automatically.
    """
    if LOCAL_MODEL_DIR and os.path.isdir(LOCAL_MODEL_DIR):
        return LOCAL_MODEL_DIR

    if not HF_MODEL_REPO:
        return None

    try:
        from huggingface_hub import snapshot_download

        return snapshot_download(
            repo_id=HF_MODEL_REPO,
            revision=HF_MODEL_REVISION,
            token=HF_TOKEN,
            allow_patterns=[
                "metadata.json",
                "lightgbm_model.joblib",
                "lightgbm_vectorizer.joblib",
                "distilbert/*",
            ],
        )
    except Exception:
        return None


@lru_cache(maxsize=1)
def load_ensemble():
    """Load deployment artifacts once per Streamlit process."""
    artifact_directory = get_artifact_directory()

    unavailable = {
        "available": False,
        "reason": "Ensemble artifacts are not configured or could not be loaded.",
    }

    if not artifact_directory:
        return unavailable

    try:
        metadata_path = os.path.join(artifact_directory, "metadata.json")
        lightgbm_path = os.path.join(artifact_directory, "lightgbm_model.joblib")
        vectorizer_path = os.path.join(
            artifact_directory,
            "lightgbm_vectorizer.joblib",
        )
        distilbert_path = os.path.join(artifact_directory, "distilbert")

        with open(metadata_path, "r", encoding="utf-8") as file:
            metadata = json.load(file)

        lightgbm_model = joblib.load(lightgbm_path)
        lightgbm_vectorizer = joblib.load(vectorizer_path)

        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        distilbert_tokenizer = AutoTokenizer.from_pretrained(
            distilbert_path,
            local_files_only=True,
        )
        distilbert_model = AutoModelForSequenceClassification.from_pretrained(
            distilbert_path,
            local_files_only=True,
        )
        distilbert_model.eval()

        return {
            "available": True,
            "metadata": metadata,
            "lightgbm_model": lightgbm_model,
            "lightgbm_vectorizer": lightgbm_vectorizer,
            "distilbert_tokenizer": distilbert_tokenizer,
            "distilbert_model": distilbert_model,
        }

    except Exception as error:
        return {
            "available": False,
            "reason": f"Could not load ensemble artifacts: {str(error)[:120]}",
        }


def _lightgbm_probability(runtime, text, keyword_score, url_score):
    vectorizer = runtime["lightgbm_vectorizer"]
    model = runtime["lightgbm_model"]

    text_features = vectorizer.transform([text])
    model_input = hstack([
        text_features,
        csr_matrix([[keyword_score]]),
        csr_matrix([[url_score]]),
    ])

    return float(model.predict_proba(model_input)[0][1])


def _distilbert_probability(runtime, text):
    import torch

    tokenizer = runtime["distilbert_tokenizer"]
    model = runtime["distilbert_model"]

    encoded = tokenizer(
        text,
        truncation=True,
        max_length=256,
        padding=True,
        return_tensors="pt",
    )

    with torch.no_grad():
        logits = model(**encoded).logits
        probabilities = torch.softmax(logits, dim=1)[0]

    return float(probabilities[1].item())


def predict_ensemble(text, keyword_score, url_score):
    """
    Return ensemble phishing probability.

    The caller owns final policy decisions, URL intelligence, confidence caps,
    and explainability. This makes the same runtime reusable by Streamlit,
    FastAPI, and a future browser-extension API.
    """
    runtime = load_ensemble()

    if not runtime["available"]:
        return {
            "available": False,
            "reason": runtime["reason"],
            "phishing_probability": None,
            "lightgbm_probability": None,
            "distilbert_probability": None,
        }

    try:
        metadata = runtime["metadata"]
        weights = metadata.get(
            "ensemble_weights",
            {"lightgbm": 0.45, "distilbert": 0.55},
        )

        lightgbm_probability = _lightgbm_probability(
            runtime,
            text,
            keyword_score,
            url_score,
        )

        distilbert_probability = _distilbert_probability(runtime, text)

        phishing_probability = (
            lightgbm_probability * float(weights["lightgbm"])
            + distilbert_probability * float(weights["distilbert"])
        )

        return {
            "available": True,
            "reason": None,
            "phishing_probability": float(phishing_probability),
            "lightgbm_probability": float(lightgbm_probability),
            "distilbert_probability": float(distilbert_probability),
            "model_version": metadata.get("model_version", "unknown"),
        }

    except Exception as error:
        return {
            "available": False,
            "reason": f"Ensemble inference failed: {str(error)[:120]}",
            "phishing_probability": None,
            "lightgbm_probability": None,
            "distilbert_probability": None,
        }
