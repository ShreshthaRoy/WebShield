import json
import os
from urllib.parse import urlparse

# Reproducibility before TensorFlow is initialized.
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("TF_DETERMINISTIC_OPS", "1")

import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold

from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.layers import (
    Bidirectional,
    Conv1D,
    Dense,
    Dropout,
    Embedding,
    GlobalMaxPooling1D,
    LSTM,
    MaxPooling1D,
)
from tensorflow.keras.models import Sequential
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(BASE_DIR, "data", "phishing.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")

MAX_WORDS = 10000
MAX_LENGTH = 200
EMBEDDING_DIM = 32
EPOCHS = 15
BATCH_SIZE = 32
RANDOM_STATE = 42

TOKENIZER_PATH = os.path.join(MODEL_DIR, "url_tokenizer.json")
CNN_PATH = os.path.join(MODEL_DIR, "url_cnn.keras")
BILSTM_PATH = os.path.join(MODEL_DIR, "url_cnn_bilstm.keras")
RESULTS_PATH = os.path.join(MODEL_DIR, "deep_learning_results.json")
CONFIG_PATH = os.path.join(MODEL_DIR, "dl_config.json")

os.makedirs(MODEL_DIR, exist_ok=True)

tf.keras.utils.set_random_seed(RANDOM_STATE)


# ============================================================
# HELPERS
# ============================================================

def normalize_url(url):
    url = str(url or "").strip().lower()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_hostname(url):
    try:
        hostname = (urlparse(normalize_url(url)).hostname or "").lower()
        return hostname.removeprefix("www.")
    except Exception:
        return ""


def make_legitimate_variants(url):
    """Create realistic URL variants from a legitimate held-out/training domain."""
    domain = get_hostname(url)
    if not domain:
        return []

    return [
        f"https://{domain}",
        f"https://www.{domain}",
        f"https://{domain}/",
        f"https://www.{domain}/",
        f"https://{domain}/about",
        f"https://www.{domain}/about",
        f"https://{domain}/contact",
        f"https://www.{domain}/contact",
        f"https://{domain}/login",
        f"https://www.{domain}/login",
        f"https://{domain}/search?q=test",
        f"https://www.{domain}/search?q=test",
        f"https://{domain}/search?page=2",
        f"https://www.{domain}/search?page=2",
        f"https://{domain}/?utm_source=webshield",
        f"https://www.{domain}/?utm_source=webshield",
        f"https://{domain}/?zx=1790098591777",
        f"https://www.{domain}/?zx=1790098591777",
    ]


def group_split(X, y, groups, n_splits, random_state):
    """Return one stratified group-aware split."""
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )
    train_idx, test_idx = next(
        splitter.split(X, y, groups=groups)
    )
    return train_idx, test_idx


def encode_urls(tokenizer, urls):
    sequences = tokenizer.texts_to_sequences(urls)
    return pad_sequences(
        sequences,
        maxlen=MAX_LENGTH,
        padding="post",
        truncating="post",
    ).astype("int32")


def evaluate_model(model, X_test_pad, y_test, name):
    probabilities = model.predict(
        X_test_pad,
        batch_size=BATCH_SIZE,
        verbose=0,
    ).reshape(-1)

    predictions = (probabilities >= 0.5).astype(int)

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(
            precision_score(y_test, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(y_test, predictions, zero_division=0)
        ),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
    }

    print("\n==============================")
    print(name)
    print("==============================")

    for key, value in metrics.items():
        print(f"{key.capitalize():<10}:", round(value * 100, 2), "%")

    return metrics


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")
df = pd.read_csv(DATASET)

df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(int)
df = df.drop_duplicates(subset="url").reset_index(drop=True)
df["group"] = df["url"].apply(get_hostname)

df = df[df["group"] != ""].reset_index(drop=True)

X = df["url"].to_numpy()
y = df["label"].to_numpy()
groups = df["group"].to_numpy()

print("Total URLs:", len(df))
print("Legitimate:", int((y == 0).sum()))
print("Phishing:", int((y == 1).sum()))
print("Unique hostname groups:", len(set(groups)))


# ============================================================
# GROUP-AWARE TRAIN / VALIDATION / TEST SPLIT
# ============================================================
#
# We split by hostname instead of randomly splitting individual URLs.
# This prevents URLs from the same domain appearing in both train and
# test, which would make the reported metrics overly optimistic.
# ============================================================

train_val_idx, test_idx = group_split(
    X,
    y,
    groups,
    n_splits=5,
    random_state=RANDOM_STATE,
)

X_train_val = X[train_val_idx]
y_train_val = y[train_val_idx]
groups_train_val = groups[train_val_idx]

X_test = X[test_idx]
y_test = y[test_idx]
groups_test = groups[test_idx]

train_idx_rel, val_idx_rel = group_split(
    X_train_val,
    y_train_val,
    groups_train_val,
    n_splits=4,
    random_state=RANDOM_STATE + 1,
)

X_train_base = X_train_val[train_idx_rel]
y_train_base = y_train_val[train_idx_rel]
groups_train_base = groups_train_val[train_idx_rel]

X_val = X_train_val[val_idx_rel]
y_val = y_train_val[val_idx_rel]
groups_val = groups_train_val[val_idx_rel]

# Verify there is no hostname leakage.
assert not (set(groups_train_base) & set(groups_val))
assert not (set(groups_train_base) & set(groups_test))
assert not (set(groups_val) & set(groups_test))

print("\nBase split:")
print("Training:", len(X_train_base))
print("Validation:", len(X_val))
print("Testing:", len(X_test))


# ============================================================
# TRAINING AUGMENTATION
# ============================================================
#
# Only the training partition is augmented. Test/validation domains
# remain unseen. This specifically teaches the DL model that legitimate
# websites can contain paths, www, query strings and login pages.
# ============================================================

augmented_urls = []
augmented_labels = []

for url, label in zip(X_train_base, y_train_base):
    if label == 0:
        variants = make_legitimate_variants(url)
        augmented_urls.extend(variants)
        augmented_labels.extend([0] * len(variants))
    else:
        augmented_urls.append(url)
        augmented_labels.append(1)

train_df = pd.DataFrame({
    "url": augmented_urls,
    "label": augmented_labels,
})

train_df = train_df.drop_duplicates(subset="url").reset_index(drop=True)

X_train = train_df["url"].to_numpy()
y_train = train_df["label"].to_numpy()

print("\nAugmented training set:", len(X_train))
print("Training legitimate:", int((y_train == 0).sum()))
print("Training phishing:", int((y_train == 1).sum()))


# ============================================================
# CHARACTER TOKENIZATION
# ============================================================

print("\nCreating character tokenizer...")

# URL punctuation is part of the input signal, so DO NOT use Keras'
# default punctuation filters.
tokenizer = Tokenizer(
    num_words=MAX_WORDS,
    char_level=True,
    oov_token="<OOV>",
    lower=True,
    filters="",
)

tokenizer.fit_on_texts(X_train)

X_train_pad = encode_urls(tokenizer, X_train)
X_val_pad = encode_urls(tokenizer, X_val)
X_test_pad = encode_urls(tokenizer, X_test)

vocab_size = min(MAX_WORDS, len(tokenizer.word_index) + 1)

print("Vocabulary size:", vocab_size)
print("Input shape:", X_train_pad.shape)

with open(TOKENIZER_PATH, "w", encoding="utf-8") as file:
    file.write(tokenizer.to_json())

print("Tokenizer saved:", TOKENIZER_PATH)


# ============================================================
# MODELS
# ============================================================

def create_cnn():
    model = Sequential([
        Embedding(
            input_dim=vocab_size,
            output_dim=EMBEDDING_DIM,
            name="character_embedding",
        ),
        Conv1D(
            filters=32,
            kernel_size=5,
            activation="relu",
            name="local_pattern_conv",
        ),
        MaxPooling1D(pool_size=2),
        Conv1D(
            filters=16,
            kernel_size=3,
            activation="relu",
        ),
        GlobalMaxPooling1D(),
        Dense(16, activation="relu"),
        Dropout(0.3),
        Dense(1, activation="sigmoid"),
    ])

    model.build((None, MAX_LENGTH))
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def create_cnn_bilstm():
    model = Sequential([
        Embedding(
            input_dim=vocab_size,
            output_dim=EMBEDDING_DIM,
            name="character_embedding",
        ),
        Conv1D(
            filters=32,
            kernel_size=5,
            activation="relu",
            name="local_pattern_conv",
        ),
        MaxPooling1D(pool_size=2),
        Bidirectional(
            LSTM(16),
            name="bidirectional_sequence_layer",
        ),
        Dense(16, activation="relu"),
        Dropout(0.3),
        Dense(1, activation="sigmoid"),
    ])

    model.build((None, MAX_LENGTH))
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def make_callbacks():
    return [
        EarlyStopping(
            monitor="val_loss",
            patience=3,
            restore_best_weights=True,
            verbose=1,
        ),
        ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=1,
            min_lr=1e-5,
            verbose=1,
        ),
    ]


# ============================================================
# TRAIN CNN
# ============================================================

print("\n==============================")
print("TRAINING CNN")
print("==============================")

cnn = create_cnn()

cnn.fit(
    X_train_pad,
    y_train,
    validation_data=(X_val_pad, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=make_callbacks(),
    verbose=1,
)

cnn_results = evaluate_model(cnn, X_test_pad, y_test, "CNN Results")
cnn.save(CNN_PATH)
print("CNN saved.")


# ============================================================
# TRAIN CNN + BiLSTM
# ============================================================

print("\n==============================")
print("TRAINING CNN + BiLSTM")
print("==============================")

cnn_bilstm = create_cnn_bilstm()

cnn_bilstm.fit(
    X_train_pad,
    y_train,
    validation_data=(X_val_pad, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=make_callbacks(),
    verbose=1,
)

cnn_bilstm_results = evaluate_model(
    cnn_bilstm,
    X_test_pad,
    y_test,
    "CNN + BiLSTM Results",
)

cnn_bilstm.save(BILSTM_PATH)
print("CNN + BiLSTM saved.")


# ============================================================
# ROBUSTNESS TEST — UNSEEN LEGITIMATE URL VARIANTS
# ============================================================
#
# Generate variants from held-out legitimate domains only. These variants
# were not used during training. This gives us a separate check for the
# exact problem we observed with query-string URLs.
# ============================================================

robust_urls = []
for url, label in zip(X_test, y_test):
    if label == 0:
        robust_urls.extend(make_legitimate_variants(url))

robust_urls = list(dict.fromkeys(robust_urls))

if robust_urls:
    X_robust_pad = encode_urls(tokenizer, robust_urls)
    robust_probabilities = cnn_bilstm.predict(
        X_robust_pad,
        batch_size=BATCH_SIZE,
        verbose=0,
    ).reshape(-1)

    robust_predictions = (robust_probabilities >= 0.5).astype(int)
    robust_labels = np.zeros(len(robust_predictions), dtype=int)

    robustness_metrics = {
        "samples": int(len(robust_predictions)),
        "false_positive_rate": float(
            (robust_predictions == 1).mean()
        ),
        "accuracy": float(
            accuracy_score(robust_labels, robust_predictions)
        ),
    }

    print("\n==============================")
    print("UNSEEN LEGITIMATE URL VARIANT TEST")
    print("==============================")
    print("Samples:", robustness_metrics["samples"])
    print(
        "False positive rate:",
        round(robustness_metrics["false_positive_rate"] * 100, 2),
        "%",
    )
else:
    robustness_metrics = {
        "samples": 0,
        "false_positive_rate": None,
        "accuracy": None,
    }


# ============================================================
# SAVE RESULTS + CONFIG
# ============================================================

results = {
    "CNN": cnn_results,
    "CNN_BiLSTM": cnn_bilstm_results,
    "dataset_size": int(len(df)),
    "base_training_size": int(len(X_train_base)),
    "augmented_training_size": int(len(X_train)),
    "validation_size": int(len(X_val)),
    "test_size": int(len(X_test)),
    "split_method": "StratifiedGroupKFold by hostname",
    "augmentation": "legitimate training-domain URL variants only",
    "robustness_test": robustness_metrics,
}

with open(RESULTS_PATH, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

config = {
    "model": "CNN + BiLSTM",
    "char_level": True,
    "filters": "",
    "lower": True,
    "max_words": MAX_WORDS,
    "max_length": MAX_LENGTH,
    "embedding_dim": EMBEDDING_DIM,
    "batch_size": BATCH_SIZE,
    "epochs_max": EPOCHS,
    "random_state": RANDOM_STATE,
    "input_shape": list(cnn_bilstm.input_shape),
}

with open(CONFIG_PATH, "w", encoding="utf-8") as file:
    json.dump(config, file, indent=4)

print("\nResults saved to:", RESULTS_PATH)
print("DL config saved to:", CONFIG_PATH)
print("\nDeep-learning training completed successfully.")
