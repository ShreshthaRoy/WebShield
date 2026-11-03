from pathlib import Path
from urllib.parse import urlparse
import json
import os
from datetime import datetime

import joblib
import tensorflow as tf
from flask import Flask, jsonify, request
from flask_cors import CORS
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

from risk_engine import (
    calculate_domain_risk,
    calculate_final_risk,
    calculate_page_risk,
    calculate_url_risk,
)
from utils import extract_features, normalize_url
from url_validation import validate_url
from history_store import append_scan


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "model.pkl"
DL_MODEL_PATH = MODEL_DIR / "url_cnn_bilstm.keras"
TOKENIZER_PATH = MODEL_DIR / "url_tokenizer.json"
DL_CONFIG_PATH = MODEL_DIR / "dl_config.json"
ML_RESULTS_PATH = MODEL_DIR / "ml_results.json"


# ============================================================
# FLASK SETUP
# ============================================================

app = Flask(__name__)

# The extension and local dashboard need cross-origin access.
CORS(app)


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading traditional ML model...")
model = joblib.load(MODEL_PATH)
print("Traditional ML model loaded.")

print("Loading CNN + BiLSTM model...")
dl_model = tf.keras.models.load_model(DL_MODEL_PATH)

with open(TOKENIZER_PATH, "r", encoding="utf-8") as file:
    dl_tokenizer = tokenizer_from_json(file.read())

print("CNN + BiLSTM model loaded.")

# Use the model's actual input length rather than duplicating a
# hard-coded value in the inference code.
DL_MAX_LENGTH = int(dl_model.input_shape[1])

# Validate the saved tokenizer configuration. The training pipeline
# intentionally preserves URL punctuation because characters such as
# /, ?, =, ., @ and - can carry useful URL information.
if getattr(dl_tokenizer, "char_level", False) is not True:
    raise RuntimeError("Saved DL tokenizer is not character-level.")

if getattr(dl_tokenizer, "filters", None) != "":
    raise RuntimeError(
        "Saved DL tokenizer was created with punctuation filters. "
        "Retrain the deep-learning model using train_deep_learning.py."
    )

if DL_CONFIG_PATH.exists():
    with open(DL_CONFIG_PATH, "r", encoding="utf-8") as file:
        dl_config = json.load(file)

    configured_length = int(dl_config.get("max_length", DL_MAX_LENGTH))

    if configured_length != DL_MAX_LENGTH:
        raise RuntimeError(
            "DL config and saved model input length do not match."
        )


# ============================================================
# KNOWN / TRUSTED DOMAINS
# ============================================================

known_domains = [
    "google.com",
    "amazon.com",
    "facebook.com",
    "paypal.com",
    "netflix.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "twitter.com",
    "wikipedia.org",
    "openai.com",
    "bit-bangalore.edu.in",
]


# ============================================================
# HELPERS
# ============================================================

def get_domain(url):
    """Return hostname including subdomains, without a port."""
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def is_trusted_domain(url):
    domain = get_domain(url).removeprefix("www.")

    for trusted in known_domains:
        trusted = trusted.lower().removeprefix("www.")

        # Trust the configured root and its conventional www host only.
        # Do not automatically trust arbitrary nested subdomains.
        if domain == trusted:
            return True

    return False


def get_dl_probability(url):
    sequence = dl_tokenizer.texts_to_sequences([url])

    padded = pad_sequences(
        sequence,
        maxlen=DL_MAX_LENGTH,
        padding="post",
        truncating="post",
    )

    probability = dl_model.predict(
        padded,
        verbose=0,
    )[0][0]

    return float(probability)


def get_risk_level(score):
    if score < 30:
        return "SAFE"

    if score < 70:
        return "SUSPICIOUS"

    return "HIGH RISK"


def get_context(url):
    """Provide a simple explainable investigation context."""
    url_lower = url.lower()

    financial_terms = [
        "bank",
        "payment",
        "paypal",
        "wallet",
        "finance",
        "invoice",
    ]

    authentication_terms = [
        "login",
        "signin",
        "password",
        "authenticate",
        "account",
        "verify",
    ]

    if any(term in url_lower for term in financial_terms):
        return "Financial"

    if any(term in url_lower for term in authentication_terms):
        return "Authentication"

    return "General"


# ============================================================
# ANALYZE
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        raw_url = str(data.get("url", "")).strip()

        url, validation_error = validate_url(raw_url)

        if validation_error:
            return jsonify({
                "error": validation_error
            }), 400

        page_analysis = data.get("page_analysis") or {}

        # ----------------------------------------------------
        # Traditional ML
        # ----------------------------------------------------

        features = extract_features(url)

        ml_prediction = int(
            model.predict([features])[0]
        )

        ml_probability = float(
            model.predict_proba([features])[0][1]
        )

        # ----------------------------------------------------
        # Deep learning
        # ----------------------------------------------------

        dl_probability = get_dl_probability(url)

        # ----------------------------------------------------
        # Explainable URL risk
        # ----------------------------------------------------

        url_risk, url_reasons = calculate_url_risk(url)

        # ----------------------------------------------------
        # Domain risk
        # ----------------------------------------------------

        domain = get_domain(url)

        (
            domain_risk,
            is_unknown_domain,
            domain_reasons,
        ) = calculate_domain_risk(
            domain,
            known_domains,
        )

        trusted_domain = is_trusted_domain(url)

        # ----------------------------------------------------
        # Page risk
        # ----------------------------------------------------

        page_risk, page_reasons = calculate_page_risk(
            page_analysis
        )

        # ----------------------------------------------------
        # Hybrid risk
        # ----------------------------------------------------

        final_score, risk_breakdown = calculate_final_risk(
            ml_probability=ml_probability,
            dl_probability=dl_probability,
            url_risk=url_risk,
            domain_risk=domain_risk,
            page_risk=page_risk,
            trusted_domain=trusted_domain,
        )

        risk_level = get_risk_level(final_score)

        # The final system decision is separate from the raw
        # Random Forest prediction.
        final_prediction = int(final_score >= 30)

        all_reasons = (
            url_reasons
            + domain_reasons
            + page_reasons
        )
        if risk_breakdown.get("trusted_domain_adjustment"):
            all_reasons.append(
                "Trusted-domain safeguard reduced a model-only high score because the hostname exactly matches a configured official domain and no strong structural warning was found; compromised trusted sites remain possible."
            )

        response = {
            "url": url,
            "prediction": final_prediction,
            "status": risk_level,
            "risk_level": risk_level,
            "risk_score": round(final_score, 2),

            # Raw model signals
            "ml_prediction": ml_prediction,
            "ml_probability": round(ml_probability, 4),
            "ml_probability_percent": round(
                ml_probability * 100,
                2,
            ),
            "dl_probability": round(dl_probability, 4),
            "dl_probability_percent": round(
                dl_probability * 100,
                2,
            ),

            # Explainable signals
            "url_risk": round(url_risk, 2),
            "url_reasons": url_reasons,
            "domain": domain,
            "domain_risk": round(domain_risk, 2),
            "domain_reasons": domain_reasons,
            "unknown_domain": bool(is_unknown_domain),
            "trusted_domain": bool(trusted_domain),
            "page_risk": round(page_risk, 2) if page_risk is not None else None,
            "page_analysis_available": page_risk is not None,
            "page_reasons": page_reasons,
            "reasons": all_reasons,

            # Investigation context
            "context": get_context(url),

            # Full hybrid breakdown
            "risk_breakdown": risk_breakdown,

            "models": {
                "traditional_ml": "Random Forest",
                "deep_learning": "CNN + BiLSTM",
            },
        }

        # One canonical writer records dashboard and extension scans with the
        # same schema. Missing page telemetry stays blank, not a false zero.
        breakdown = response["risk_breakdown"]
        append_scan({
            "url": url,
            "risk_score": final_score,
            "status": risk_level,
            "ml_score": breakdown.get("ml_score"),
            "dl_score": breakdown.get("dl_score"),
            "model_score": breakdown.get("model_score"),
            "url_risk": breakdown.get("url_risk"),
            "domain_risk": breakdown.get("domain_risk"),
            "page_risk": breakdown.get("page_risk"),
            "page_analysis_available": breakdown.get("page_analysis_available", False),
            "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        })
        return jsonify(response)

    except Exception as exc:
        app.logger.exception("WebShield analysis failed")

        return jsonify({
            "error": str(exc)
        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    """Machine-readable component status for dashboard and demo checks."""
    return jsonify({
        "status": "ok",
        "api": True,
        "models": {
            "random_forest": MODEL_PATH.exists(),
            "cnn_bilstm": DL_MODEL_PATH.exists(),
            "tokenizer": TOKENIZER_PATH.exists(),
        },
        "page_analysis": "browser extension telemetry; not fetched server-side",
        "history_file": str(BASE_DIR / "phishing_history.csv"),
    })


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "WebShield API is running",
        "models": {
            "traditional_ml": "Random Forest",
            "deep_learning": "CNN + BiLSTM",
        },
        "endpoint": "/analyze",
    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    print("")
    print("======================================")
    print("        WEBSHIELD SECURITY API")
    print("======================================")
    print("Traditional ML : Random Forest")
    print("Deep Learning  : CNN + BiLSTM")
    print("Server         : http://127.0.0.1:5000")
    print("======================================")
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
