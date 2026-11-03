# WebShield — Hybrid Phishing Detection & URL Risk Analysis System

WebShield is a local cybersecurity system for detecting and investigating potentially malicious websites.

It combines:

- Random Forest URL classification
- CNN + BiLSTM character-level URL classification
- Explainable URL structural analysis
- Domain reputation/structure analysis
- Browser-based webpage structural analysis
- Hybrid risk scoring
- Chrome browser extension
- Flask REST API
- Streamlit security dashboard
- DNS, IP geolocation and ASN intelligence
- IP/domain RDAP intelligence
- Domain registration-age signal
- Threat history and analytics

## Architecture

```text
Website / URL
      |
      v
Chrome Extension
      |
      v
Flask API
      |
      +-------------------+
      |                   |
      v                   v
Random Forest        CNN + BiLSTM
      |                   |
      +---------+---------+
                |
                v
       Hybrid Risk Engine
       /       |        \
      v        v         v
    URL     Domain      Page
   Risk      Risk       Risk
                |
                v
         Final Risk Score
                |
       +--------+--------+
       |        |        |
      SAFE  SUSPICIOUS HIGH RISK
                |
                v
        Streamlit Dashboard
                |
                v
     Infrastructure Intelligence
```

## Hybrid risk model

The final score uses these weights:

| Signal | Weight |
|---|---:|
| ML/DL ensemble | 30% |
| URL structural risk | 25% |
| Domain risk | 15% |
| Webpage structural risk | 30% |

The ML/DL ensemble itself combines the Random Forest and CNN + BiLSTM probabilities equally.

Risk levels:

- **0–29:** SAFE
- **30–69:** SUSPICIOUS
- **70–100:** HIGH RISK

When browser page telemetry is available, the hybrid score uses the configured 30/25/15/30 weights. When page telemetry is unavailable (for example, a URL typed into the dashboard), WebShield **reweights the available model, URL and domain signals proportionally** rather than treating the missing webpage analysis as a zero-risk result. The response explicitly reports whether page telemetry was available. A conservative trusted-host safeguard can cap some model-only false positives for exact configured domains when structural signals are clean; arbitrary nested subdomains are not automatically trusted.

## Dataset

The training dataset is constructed from:

- **PhishTank:** verified and currently online phishing URLs
- **Tranco:** legitimate domains

The legitimate Tranco domains are represented using varied, realistic URL forms such as:

- root URLs
- `www` URLs
- common paths such as `/about` and `/contact`
- legitimate `/login` pages
- simple search/query URLs

Only one URL variant is selected per legitimate domain so that the same domain is not duplicated across multiple variants.

This is intended to reduce the dataset bias caused by training every legitimate example as only `https://domain`.

## Important model limitation

The reported ML/DL metrics are **held-out experimental dataset metrics**. They should not be presented as real-world phishing detection accuracy.

Real-world performance can differ because phishing and legitimate URL sources have different distributions and because attackers continuously change their infrastructure and URL patterns.

WebShield therefore combines model predictions with independent structural and domain/page signals.

## Infrastructure intelligence

The dashboard can investigate:

- resolved IP address
- approximate IP location
- ASN
- hosting organization
- IP RDAP information
- domain RDAP information
- registrar
- registration/expiration dates
- nameservers
- domain-age risk signal

Infrastructure location describes the observed hosting/network infrastructure. It does **not** identify the attacker's physical location or identity.

## Installation

Create a virtual environment and install the required packages.

Then run:

```bash
python3 prepare_dataset.py
python3 train.py
python3 train_deep_learning.py
python3 app.py
```

In another terminal:

```bash
streamlit run dashboard.py
```

For the Chrome extension:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Choose **Load unpacked**
4. Select the `extension` folder
5. Reload the extension after code changes

## Infrastructure API

Set the IPinfo token as an environment variable:

```bash
export IPINFO_TOKEN="YOUR_TOKEN"
```

Do not commit API tokens to GitHub.

## Project structure

```text
phishing-project/
├── app.py
├── dashboard.py
├── prepare_dataset.py
├── train.py
├── train_deep_learning.py
├── risk_engine.py
├── utils.py
├── phishing_history.csv
├── data/
│   ├── phishing.csv
│   └── raw/
│       ├── phishtank.csv
│       └── tranco.csv
├── models/
│   ├── model.pkl
│   ├── ml_results.json
│   ├── model_metadata.json
│   ├── url_tokenizer.json
│   ├── url_cnn.keras
│   ├── url_cnn_bilstm.keras
│   └── deep_learning_results.json
└── extension/
    ├── manifest.json
    ├── background.js
    ├── content.js
    ├── popup.js
    ├── popup.html
    └── icon.png
```

## Correct Deep-Learning Retraining

The CNN + BiLSTM pipeline must be retrained whenever `train_deep_learning.py` changes. The saved tokenizer and saved model must come from the same training run.

From the project root:

```bash
python3 train_deep_learning.py
python3 test_dl_model.py
python3 app.py
```

The corrected DL pipeline:

- tokenizes URLs at character level
- preserves URL punctuation (`filters=""`)
- splits data by hostname to reduce domain leakage
- augments only training legitimate domains with realistic paths and query strings
- uses validation data with early stopping
- saves the tokenizer, CNN + BiLSTM model, results and DL configuration together
- runs a separate unseen legitimate URL-variant robustness test

Do not report the robustness-test result as the main held-out test accuracy. It is a separate stress test for legitimate URL variants.
