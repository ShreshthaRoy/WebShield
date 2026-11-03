import os
import joblib

from utils import extract_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "model.pkl")

model = joblib.load(MODEL_PATH)

TEST_URLS = [
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


print("WebShield model smoke test")
print("=" * 80)

for url in TEST_URLS:
    probability = model.predict_proba(
        [extract_features(url)]
    )[0][1]

    prediction = int(probability >= 0.5)

    print(
        f"{url:<60} "
        f"{probability * 100:6.2f}% "
        f"prediction={prediction}"
    )
