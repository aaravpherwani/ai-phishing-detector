"""
Google Colab T4 training pipeline for PhishGuard AI.

Usage in Colab:
    !git clone https://github.com/YOUR_USERNAME/ai-phishing-detector.git
    %cd ai-phishing-detector
    !pip install -r training/requirements-colab.txt
    !python training/train_ensemble_colab.py \
        --hf-repo-id YOUR_HF_USERNAME/phishguard-ensemble \
        --hf-token YOUR_HF_WRITE_TOKEN

The generated artifacts are uploaded to the Hugging Face model repository.
Do not commit the artifacts to the Streamlit GitHub repository.
"""

import argparse
import json
import os
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import torch
from datasets import concatenate_datasets, load_dataset
from huggingface_hub import HfApi
from lightgbm import LGBMClassifier
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.features import extract_features


SEED = 42
DISTILBERT_MODEL = "distilbert-base-uncased"
MAX_TEXT_LENGTH = 192
BERT_BATCH_SIZE = 16
BERT_GRADIENT_ACCUMULATION = 2
BERT_EPOCHS = 2
BERT_LEARNING_RATE = 2e-5
LIGHTGBM_MAX_FEATURES = 40_000
MAX_TOTAL_EXAMPLES = 60_000

OUTPUT_DIRECTORY = ROOT / "artifacts" / "phishguard-ensemble"


def set_seed(seed=SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def clean_text(value):
    text = str(value or "")
    return " ".join(text.replace("\x00", " ").split()).strip()


def normalize_label(value):
    if isinstance(value, (int, np.integer)):
        return int(value)

    value = str(value).strip().lower()

    if value in {"1", "spam", "phishing", "phish", "malicious", "fraud"}:
        return 1

    if value in {"0", "ham", "safe", "legitimate", "benign", "normal"}:
        return 0

    return None


def records_from_dataset(dataset, source_name):
    rows = []

    for row in dataset:
        text = None

        for candidate in [
            "text",
            "sms",
            "message",
            "Email Text",
            "email_text",
            "content",
            "body",
        ]:
            if candidate in row and row[candidate]:
                text = row[candidate]
                break

        label = None

        for candidate in [
            "label",
            "labels",
            "email_type",
            "Spam/Ham",
            "class",
            "target",
        ]:
            if candidate in row:
                label = normalize_label(row[candidate])
                break

        text = clean_text(text)

        if text and len(text) >= 20 and label in {0, 1}:
            rows.append({
                "text": text,
                "label": label,
                "source": source_name,
            })

    return rows


def load_huggingface_source(dataset_id, source_name):
    print(f"Loading {dataset_id}...")

    try:
        dataset_dict = load_dataset(dataset_id)

        splits = [
            dataset_dict[split]
            for split in dataset_dict.keys()
            if split in {"train", "test", "validation"}
        ]

        if not splits:
            return []

        dataset = concatenate_datasets(splits)
        records = records_from_dataset(dataset, source_name)

        print(f"  Loaded {len(records):,} usable records.")
        return records

    except Exception as error:
        print(f"  Skipped {dataset_id}: {error}")
        return []


def load_local_phishing_mbox():
    filepath = ROOT / "data" / "phishing-2025.txt"

    if not filepath.exists():
        print("Local phishing-2025.txt not found; continuing without it.")
        return []

    print("Loading local phishing-2025.txt...")
    records = []
    current_message = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.startswith("From ") and current_message:
                text = clean_text(" ".join(current_message))

                if len(text) >= 20:
                    records.append({
                        "text": text,
                        "label": 1,
                        "source": "local_nazario_phishing",
                    })

                current_message = [line]
            else:
                current_message.append(line)

    print(f"  Loaded {len(records):,} usable local phishing records.")
    return records


def deduplicate_and_balance(records):
    dataframe = pd.DataFrame(records)
    dataframe["normalized_text"] = (
        dataframe["text"]
        .str.lower()
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )

    dataframe = dataframe.drop_duplicates(
        subset=["normalized_text"],
        keep="first",
    ).drop(columns=["normalized_text"])

    phishing = dataframe[dataframe["label"] == 1]
    safe = dataframe[dataframe["label"] == 0]

    target_per_class = min(
        len(phishing),
        len(safe),
        MAX_TOTAL_EXAMPLES // 2,
    )

    phishing = phishing.sample(target_per_class, random_state=SEED)
    safe = safe.sample(target_per_class, random_state=SEED)

    output = pd.concat([phishing, safe], ignore_index=True)
    output = output.sample(frac=1, random_state=SEED).reset_index(drop=True)

    print(f"Final balanced training dataset: {len(output):,} examples")
    print(f"  Safe: {sum(output['label'] == 0):,}")
    print(f"  Phishing/spam: {sum(output['label'] == 1):,}")

    return output


def add_engineered_features(text_series):
    rows = text_series.apply(extract_features)

    keyword_scores = np.array(
        [row["keyword_score"] for row in rows],
        dtype=np.float32,
    ).reshape(-1, 1)

    url_scores = np.array(
        [row["url_score"] for row in rows],
        dtype=np.float32,
    ).reshape(-1, 1)

    return keyword_scores, url_scores


def build_lightgbm_input(vectorizer, texts):
    text_features = vectorizer.transform(texts)
    keyword_scores, url_scores = add_engineered_features(pd.Series(texts))

    return hstack([
        text_features,
        csr_matrix(keyword_scores),
        csr_matrix(url_scores),
    ])


class TextClassificationDataset(torch.utils.data.Dataset):
    def __init__(self, tokenizer, texts, labels):
        self.encodings = tokenizer(
            list(texts),
            truncation=True,
            padding="max_length",
            max_length=MAX_TEXT_LENGTH,
        )
        self.labels = list(labels)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, index):
        item = {
            key: torch.tensor(value[index], dtype=torch.long)
            for key, value in self.encodings.items()
        }
        item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
        return item


def predict_distilbert(model, tokenizer, texts, device):
    dataset = TextClassificationDataset(
        tokenizer,
        texts,
        [0] * len(texts),
    )

    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=32,
        shuffle=False,
        pin_memory=device.type == "cuda",
    )

    model.eval()
    probabilities = []

    with torch.no_grad():
        for batch in loader:
            labels = batch.pop("labels")
            del labels

            batch = {
                key: value.to(device)
                for key, value in batch.items()
            }

            logits = model(**batch).logits
            batch_probabilities = torch.softmax(logits, dim=1)[:, 1]
            probabilities.extend(batch_probabilities.cpu().numpy().tolist())

    return np.array(probabilities, dtype=np.float32)


def train_distilbert(train_texts, train_labels, device):
    print("Fine-tuning DistilBERT...")

    tokenizer = AutoTokenizer.from_pretrained(DISTILBERT_MODEL)

    model = AutoModelForSequenceClassification.from_pretrained(
        DISTILBERT_MODEL,
        num_labels=2,
        id2label={0: "SAFE", 1: "PHISHING"},
        label2id={"SAFE": 0, "PHISHING": 1},
    ).to(device)

    dataset = TextClassificationDataset(
        tokenizer,
        train_texts,
        train_labels,
    )

    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=BERT_BATCH_SIZE,
        shuffle=True,
        pin_memory=device.type == "cuda",
    )

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=BERT_LEARNING_RATE,
        weight_decay=0.01,
    )

    total_updates = (
        len(loader) * BERT_EPOCHS // BERT_GRADIENT_ACCUMULATION
    )

    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, total_updates // 10),
        num_training_steps=max(1, total_updates),
    )

    scaler = torch.amp.GradScaler(
        "cuda",
        enabled=device.type == "cuda",
    )

    model.train()

    for epoch in range(BERT_EPOCHS):
        running_loss = 0.0
        optimizer.zero_grad(set_to_none=True)

        for step, batch in enumerate(loader, start=1):
            batch = {
                key: value.to(device)
                for key, value in batch.items()
            }

            with torch.amp.autocast(
                device_type=device.type,
                enabled=device.type == "cuda",
            ):
                output = model(**batch)
                loss = output.loss / BERT_GRADIENT_ACCUMULATION

            scaler.scale(loss).backward()

            if step % BERT_GRADIENT_ACCUMULATION == 0 or step == len(loader):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
                scheduler.step()

            running_loss += loss.item() * BERT_GRADIENT_ACCUMULATION

        average_loss = running_loss / len(loader)
        print(f"  Epoch {epoch + 1}/{BERT_EPOCHS} loss: {average_loss:.4f}")

    return model, tokenizer


def print_metrics(name, labels, probabilities):
    predictions = (probabilities >= 0.50).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels,
        predictions,
        average="binary",
        zero_division=0,
    )

    print(f"\n{name}")
    print(f"  Accuracy:  {accuracy_score(labels, predictions):.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1:        {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc_score(labels, probabilities):.4f}")

    return {
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 4),
    }


def upload_to_huggingface(output_directory, repo_id, token):
    print(f"Uploading artifacts to Hugging Face: {repo_id}")

    api = HfApi(token=token)

    api.create_repo(
        repo_id=repo_id,
        repo_type="model",
        private=False,
        exist_ok=True,
    )

    api.upload_folder(
        repo_id=repo_id,
        repo_type="model",
        folder_path=str(output_directory),
        commit_message="Upload calibrated LightGBM + DistilBERT phishing ensemble",
    )


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--hf-repo-id",
        required=True,
        help="Example: your-hf-username/phishguard-ensemble",
    )

    parser.add_argument(
        "--hf-token",
        default=os.getenv("HF_TOKEN"),
        help="Hugging Face write token; alternatively set HF_TOKEN.",
    )

    parser.add_argument(
        "--skip-upload",
        action="store_true",
        help="Create local artifacts only.",
    )

    return parser.parse_args()


def main():
    arguments = parse_arguments()
    set_seed()

    if not arguments.skip_upload and not arguments.hf_token:
        raise ValueError(
            "Provide --hf-token or set HF_TOKEN before uploading artifacts."
        )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"Using device: {device}")
    print(f"PyTorch version: {torch.__version__}")

    all_records = []

    # Public datasets are intentionally recorded in datasets_used.json for
    # reproducibility. Review their licenses and source cards before publication.
    all_records.extend(
        load_huggingface_source(
            "ucirvine/sms_spam",
            "ucirvine_sms_spam",
        )
    )
    all_records.extend(
        load_huggingface_source(
            "SetFit/enron_spam",
            "setfit_enron_spam",
        )
    )
    all_records.extend(
        load_huggingface_source(
            "ealvaradob/phishing-dataset",
            "ealvaradob_phishing_dataset",
        )
    )
    all_records.extend(load_local_phishing_mbox())

    if not all_records:
        raise RuntimeError("No usable training data was loaded.")

    dataframe = deduplicate_and_balance(all_records)

    train_dataframe, temporary_dataframe = train_test_split(
        dataframe,
        test_size=0.30,
        random_state=SEED,
        stratify=dataframe["label"],
    )

    calibration_dataframe, test_dataframe = train_test_split(
        temporary_dataframe,
        test_size=0.50,
        random_state=SEED,
        stratify=temporary_dataframe["label"],
    )

    print(
        f"Split sizes — train: {len(train_dataframe):,}, "
        f"calibration: {len(calibration_dataframe):,}, "
        f"test: {len(test_dataframe):,}"
    )

    print("\nTraining LightGBM...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=LIGHTGBM_MAX_FEATURES,
        min_df=2,
        sublinear_tf=True,
        strip_accents="unicode",
    )

    train_text_features = vectorizer.fit_transform(
        train_dataframe["text"]
    )

    train_keyword_scores, train_url_scores = add_engineered_features(
        train_dataframe["text"]
    )

    lightgbm_train_input = hstack([
        train_text_features,
        csr_matrix(train_keyword_scores),
        csr_matrix(train_url_scores),
    ])

    lightgbm_model = LGBMClassifier(
        objective="binary",
        n_estimators=600,
        learning_rate=0.05,
        num_leaves=31,
        max_depth=-1,
        subsample=0.85,
        colsample_bytree=0.85,
        reg_lambda=1.0,
        random_state=SEED,
        n_jobs=-1,
    )

    lightgbm_model.fit(
        lightgbm_train_input,
        train_dataframe["label"],
    )

    calibration_lightgbm_input = build_lightgbm_input(
        vectorizer,
        calibration_dataframe["text"],
    )

    test_lightgbm_input = build_lightgbm_input(
        vectorizer,
        test_dataframe["text"],
    )

    calibration_lightgbm_probability = lightgbm_model.predict_proba(
        calibration_lightgbm_input
    )[:, 1]

    test_lightgbm_probability = lightgbm_model.predict_proba(
        test_lightgbm_input
    )[:, 1]

    train_distilbert_model, tokenizer = train_distilbert(
        train_dataframe["text"].tolist(),
        train_dataframe["label"].tolist(),
        device,
    )

    calibration_distilbert_probability = predict_distilbert(
        train_distilbert_model,
        tokenizer,
        calibration_dataframe["text"].tolist(),
        device,
    )

    test_distilbert_probability = predict_distilbert(
        train_distilbert_model,
        tokenizer,
        test_dataframe["text"].tolist(),
        device,
    )

    print_metrics(
        "LightGBM test metrics",
        test_dataframe["label"].to_numpy(),
        test_lightgbm_probability,
    )

    print_metrics(
        "DistilBERT test metrics",
        test_dataframe["label"].to_numpy(),
        test_distilbert_probability,
    )

    print("\nCalibrating ensemble...")
    calibration_features = np.column_stack([
        calibration_lightgbm_probability,
        calibration_distilbert_probability,
    ])

    ensemble_calibrator = LogisticRegression(
        class_weight="balanced",
        random_state=SEED,
    )

    ensemble_calibrator.fit(
        calibration_features,
        calibration_dataframe["label"],
    )

    test_ensemble_features = np.column_stack([
        test_lightgbm_probability,
        test_distilbert_probability,
    ])

    test_ensemble_probability = ensemble_calibrator.predict_proba(
        test_ensemble_features
    )[:, 1]

    ensemble_metrics = print_metrics(
        "Calibrated ensemble test metrics",
        test_dataframe["label"].to_numpy(),
        test_ensemble_probability,
    )

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    distilbert_output = OUTPUT_DIRECTORY / "distilbert"
    distilbert_output.mkdir(parents=True, exist_ok=True)

    print("\nExporting artifacts...")
    joblib.dump(
        lightgbm_model,
        OUTPUT_DIRECTORY / "lightgbm_model.joblib",
    )
    joblib.dump(
        vectorizer,
        OUTPUT_DIRECTORY / "lightgbm_vectorizer.joblib",
    )
    joblib.dump(
        ensemble_calibrator,
        OUTPUT_DIRECTORY / "ensemble_calibrator.joblib",
    )

    train_distilbert_model.save_pretrained(
        distilbert_output,
        safe_serialization=True,
    )
    tokenizer.save_pretrained(distilbert_output)

    datasets_used = {
        "sources": {
            "ucirvine/sms_spam": "SMS spam/ham text classification.",
            "SetFit/enron_spam": "Enron email spam/ham classification.",
            "ealvaradob/phishing-dataset": "Phishing/benign text, URL, and HTML samples.",
            "data/phishing-2025.txt": "Optional local phishing corpus.",
        },
        "counts_after_deduplication": {
            source: int(count)
            for source, count in dataframe["source"].value_counts().items()
        },
        "label_counts": {
            "safe": int(sum(dataframe["label"] == 0)),
            "phishing_or_spam": int(sum(dataframe["label"] == 1)),
        },
        "seed": SEED,
    }

    metadata = {
        "model_version": datetime.now(timezone.utc).strftime(
            "%Y.%m.%d-%H%M%S"
        ),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_model": DISTILBERT_MODEL,
        "max_text_length": MAX_TEXT_LENGTH,
        "labels": {"0": "SAFE", "1": "PHISHING"},
        "ensemble_type": "logistic_regression_calibrator",
        "artifact_files": {
            "lightgbm_model": "lightgbm_model.joblib",
            "lightgbm_vectorizer": "lightgbm_vectorizer.joblib",
            "ensemble_calibrator": "ensemble_calibrator.joblib",
            "distilbert_directory": "distilbert",
        },
        "test_metrics": ensemble_metrics,
        "training_examples": int(len(train_dataframe)),
        "calibration_examples": int(len(calibration_dataframe)),
        "test_examples": int(len(test_dataframe)),
    }

    with open(
        OUTPUT_DIRECTORY / "metadata.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(metadata, file, indent=2)

    with open(
        OUTPUT_DIRECTORY / "datasets_used.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(datasets_used, file, indent=2)

    print(f"Artifacts exported to: {OUTPUT_DIRECTORY}")

    if not arguments.skip_upload:
        upload_to_huggingface(
            OUTPUT_DIRECTORY,
            arguments.hf_repo_id,
            arguments.hf_token,
        )
        print("Upload complete.")

    print("\nFinal evaluation report:")
    print(
        classification_report(
            test_dataframe["label"],
            (test_ensemble_probability >= 0.50).astype(int),
            target_names=["SAFE", "PHISHING"],
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()
