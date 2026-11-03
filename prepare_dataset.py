import os
import pandas as pd
from urllib.parse import urlparse


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PHISHTANK_FILE = os.path.join(
    BASE_DIR, "data", "raw", "phishtank.csv"
)

TRANCO_FILE = os.path.join(
    BASE_DIR, "data", "raw", "tranco.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR, "data", "phishing.csv"
)

TARGET_SAMPLES = 5000

# Legitimate URLs from Tranco are originally bare home-page URLs.
# Real websites also commonly use www, paths and query strings.
# We therefore select ONE realistic URL variant per legitimate
# domain. This improves diversity without putting the same domain
# into both train and test samples through multiple variants.
LEGITIMATE_URL_VARIANTS = [
    "https://{domain}",
    "https://www.{domain}",
    "https://{domain}/",
    "https://www.{domain}/",
    "https://{domain}/about",
    "https://www.{domain}/about",
    "https://{domain}/contact",
    "https://www.{domain}/contact",
    "https://{domain}/login",
    "https://www.{domain}/login",
    "https://{domain}/search?q=test",
    "https://www.{domain}/search?q=test",
]


def get_domain(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    except Exception:
        return ""


# ============================================================
# PHISHTANK
# ============================================================

print("Loading PhishTank...")

phish = pd.read_csv(PHISHTANK_FILE)

phish = phish[
    (phish["verified"].astype(str).str.lower() == "yes")
    & (phish["online"].astype(str).str.lower() == "yes")
]

phish = phish[["url"]].dropna()
phish["url"] = phish["url"].astype(str).str.strip()
phish = phish.drop_duplicates(subset="url")
phish["label"] = 1

print("Unique phishing URLs:", len(phish))


# ============================================================
# TRANCO
# ============================================================

print("\nLoading Tranco...")

tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["rank", "domain"],
)

tranco["domain"] = (
    tranco["domain"]
    .astype(str)
    .str.strip()
    .str.lower()
)

tranco = tranco[tranco["domain"] != ""]
tranco = tranco.drop_duplicates(subset="domain")

print("Unique legitimate domains:", len(tranco))


# ============================================================
# REMOVE DOMAIN OVERLAP
# ============================================================

print("\nChecking phishing/legitimate domain overlap...")

phish_domains = set(
    phish["url"].apply(get_domain)
)

tranco = tranco[
    ~tranco["domain"].apply(
        lambda domain:
        domain.removeprefix("www.") in phish_domains
    )
]

print(
    "Legitimate domains after overlap removal:",
    len(tranco)
)


# ============================================================
# SAMPLE AND CREATE REALISTIC LEGITIMATE URLs
# ============================================================

sample_size = min(
    TARGET_SAMPLES,
    len(phish),
    len(tranco),
)

phish = phish.sample(
    n=sample_size,
    random_state=42,
)

tranco = tranco.sample(
    n=sample_size,
    random_state=42,
)

# Use a deterministic random generator so the same dataset can
# be reproduced.
rng = __import__("numpy").random.default_rng(42)

legitimate_urls = [
    rng.choice(LEGITIMATE_URL_VARIANTS).format(domain=domain)
    for domain in tranco["domain"]
]

legitimate = pd.DataFrame({
    "url": legitimate_urls,
    "label": 0,
})


# ============================================================
# COMBINE
# ============================================================

dataset = pd.concat(
    [
        phish[["url", "label"]],
        legitimate[["url", "label"]],
    ],
    ignore_index=True,
)

dataset["url"] = dataset["url"].astype(str).str.strip()

dataset = dataset.drop_duplicates(
    subset="url"
)

dataset = dataset.sample(
    frac=1,
    random_state=42,
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

dataset.to_csv(
    OUTPUT_FILE,
    index=False,
)


print("\n==============================")
print("Dataset created successfully")
print("==============================")
print("Total samples:", len(dataset))
print("\nClass distribution:")
print(dataset["label"].value_counts())
print("\nSaved to:")
print(OUTPUT_FILE)
