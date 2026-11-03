import json
from pathlib import Path

import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "url_cnn_bilstm.keras"
TOKENIZER_PATH = MODEL_DIR / "url_tokenizer.json"
CONFIG_PATH = MODEL_DIR / "dl_config.json"

print("Loading WebShield CNN + BiLSTM...")
model = tf.keras.models.load_model(MODEL_PATH)

with open(TOKENIZER_PATH, "r", encoding="utf-8") as file:
    tokenizer = tokenizer_from_json(file.read())

with open(CONFIG_PATH, "r", encoding="utf-8") as file:
    config = json.load(file)

max_length = int(config["max_length"])

assert tokenizer.char_level is True
assert tokenizer.filters == ""
assert int(model.input_shape[1]) == max_length

TEST_URLS = [
    # Google
    "https://www.google.com",
    "https://www.google.com/",
    "https://www.google.com/search?q=test",
    "https://www.google.com/?zx=1790098591777",
    "https://www.google.com/login",

    # Amazon
    "https://www.amazon.com",
    "https://www.amazon.com/",
    "https://www.amazon.com/search?q=laptop",
    "https://www.amazon.com/?ref=test",

    # Microsoft
    "https://www.microsoft.com",
    "https://www.microsoft.com/en-us/",
    "https://www.microsoft.com/search?q=test",

    # GitHub
    "https://github.com",
    "https://github.com/",
    "https://github.com/search?q=test",
    "https://github.com/login",

    # LinkedIn
    "https://www.linkedin.com",
    "https://www.linkedin.com/feed/",
    "https://www.linkedin.com/login",

    # Phishing
    "https://secure-login-verify-account-example.com/login/verify",
    "https://paypal-secure-login-example.com/verify/account",
    "https://account-update-security-example.com/login"
]

sequences = tokenizer.texts_to_sequences(TEST_URLS)
padded = pad_sequences(
    sequences,
    maxlen=max_length,
    padding="post",
    truncating="post",
)

probabilities = model.predict(padded, verbose=0).reshape(-1)

print("\nDL smoke test")
print("=" * 90)

for url, probability in zip(TEST_URLS, probabilities):
    print(f"{probability * 100:7.2f}%  {url}")

print("\nModel input length:", max_length)
print("Tokenizer vocabulary:", len(tokenizer.word_index) + 1)
print("Tokenizer char_level:", tokenizer.char_level)
print("Tokenizer filters: repr=", repr(tokenizer.filters))
