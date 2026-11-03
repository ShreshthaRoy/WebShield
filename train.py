import json
import os

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from utils import extract_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
RESULTS_PATH = os.path.join(MODEL_DIR, "ml_results.json")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "domain_dot_count",
    "hyphen_count",
    "special_character_count",
    "https",
    "suspicious_keyword_count",
    "ip_address",
    "at_symbol",
    "url_depth",
    "subdomain_count",
    "suspicious_tld",
]


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")

df = pd.read_csv(DATASET)

required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError(
        f"Dataset must contain columns: {required_columns}"
    )

df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str)
df["label"] = df["label"].astype(int)
df = df.drop_duplicates(subset="url")

print("Total URLs:", len(df))
print("Legitimate:", (df["label"] == 0).sum())
print("Phishing:", (df["label"] == 1).sum())


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print("\nExtracting URL features...")

X = np.asarray(
    df["url"].apply(extract_features).tolist(),
    dtype=float,
)

y = df["label"].to_numpy()

if X.shape[1] != len(FEATURE_NAMES):
    raise RuntimeError(
        "Feature count does not match FEATURE_NAMES."
    )


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nDataset split:")
print("Training:", len(X_train))
print("Testing :", len(X_test))


# ============================================================
# MODELS
# ============================================================

rf = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
)

lr = LogisticRegression(
    max_iter=2000,
    random_state=42,
)


def evaluate_model(model, name):
    predictions = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test,
            predictions,
            zero_division=0,
        ),
        "recall": recall_score(
            y_test,
            predictions,
            zero_division=0,
        ),
        "f1": f1_score(
            y_test,
            predictions,
            zero_division=0,
        ),
    }

    print("\n==============================")
    print(name)
    print("==============================")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    for key, value in metrics.items():
        print(
            f"{key.capitalize():<10}:",
            round(value, 4),
        )

    return metrics


# ============================================================
# RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

rf.fit(X_train, y_train)

rf_metrics = evaluate_model(
    rf,
    "Random Forest",
)


# ============================================================
# LOGISTIC REGRESSION
# ============================================================

print("\nTraining Logistic Regression...")

lr.fit(X_train, y_train)

lr_metrics = evaluate_model(
    lr,
    "Logistic Regression",
)


# ============================================================
# SELECT MODEL
# ============================================================

if rf_metrics["f1"] >= lr_metrics["f1"]:
    best_model = rf
    best_model_name = "Random Forest"
else:
    best_model = lr
    best_model_name = "Logistic Regression"


joblib.dump(
    best_model,
    MODEL_PATH,
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

feature_importance = {}

if hasattr(best_model, "feature_importances_"):
    feature_importance = {
        name: round(float(value), 6)
        for name, value in zip(
            FEATURE_NAMES,
            best_model.feature_importances_,
        )
    }


# ============================================================
# SAVE RESULTS
# ============================================================

results = {
    "Random Forest": rf_metrics,
    "Logistic Regression": lr_metrics,
    "best_model": best_model_name,
    "feature_names": FEATURE_NAMES,
    "feature_importance": feature_importance,
    "dataset_size": int(len(df)),
    "test_size": int(len(X_test)),
}

with open(RESULTS_PATH, "w") as file:
    json.dump(results, file, indent=4)


metadata = {
    "model": best_model_name,
    "feature_count": len(FEATURE_NAMES),
    "feature_names": FEATURE_NAMES,
    "dataset": "PhishTank verified-online phishing + Tranco legitimate domains with realistic legitimate URL variants",
    "random_state": 42,
}

with open(METADATA_PATH, "w") as file:
    json.dump(metadata, file, indent=4)


# ============================================================
# EXTERNAL SMOKE TEST
# ============================================================

smoke_test_urls = [
    "https://www.google.com/",
    "https://github.com/",
    "https://www.amazon.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://www.paypal.com/",
    "https://www.linkedin.com/",
    "https://www.wikipedia.org/",
    "https://openai.com/",
    "http://secure-login-verify-account.com/login/verify",
]

print("\n==============================")
print("EXTERNAL SMOKE TEST")
print("==============================")

for url in smoke_test_urls:
    probability = best_model.predict_proba(
        [extract_features(url)]
    )[0][1]

    print(
        f"{url:<60} "
        f"{probability * 100:6.2f}% phishing probability"
    )


print("\n==============================")
print("MODEL COMPARISON")
print("==============================")
print(
    "Random Forest F1:",
    round(rf_metrics["f1"] * 100, 2),
    "%",
)
print(
    "Logistic Regression F1:",
    round(lr_metrics["f1"] * 100, 2),
    "%",
)
print("Best Model:", best_model_name)
print("Model saved to:", MODEL_PATH)
print("Results saved to:", RESULTS_PATH)
