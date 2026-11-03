# WebShield final demo checklist

## One-time setup (Mac)

After unzipping the project, open Terminal and move into the extracted project folder. Replace the example path with the actual location:

```bash
cd "/path/to/WebShield-Corrected 2"
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

The shareable ZIP intentionally excludes `venv`; create it on the machine where you will present. Keep the existing `models/` artifacts—do not rerun training just for the demo.

## Start-up (Mac)

Open Terminal 1 and run:

```bash
cd "/path/to/WebShield-Corrected 2"
source venv/bin/activate
python3 app.py
```

Wait for the startup message and keep this terminal open. In a second terminal:

```bash
cd "/path/to/WebShield-Corrected 2"
source venv/bin/activate
streamlit run dashboard.py
```

Open the dashboard URL printed by Streamlit (normally `http://localhost:8501`). Check **System Status** and confirm the API and model artifacts are available. You can also open `http://127.0.0.1:5000/health` in a browser.

## Chrome extension

1. Open `chrome://extensions` and enable Developer mode.
2. Load unpacked → choose the project's `extension` folder.
3. Reload the extension after any source change.
4. Keep `python3 app.py` running. The extension uses the local API at `http://127.0.0.1:5000`.
5. Navigate to a normal site, wait for the page to load, then open the WebShield popup. Chrome internal pages and some protected pages cannot be inspected.

## Live panel flow

1. Open **Demo Lab** and run the full suite. It submits URL strings to the local API; it does not open suspicious test URLs.
2. Show `https://bit-bangalore.edu.in/` and `https://bit-bangalore.edu.in/ise-about` in Live Scanner.
3. Show the BIT spelling-lookalike test and explain why hostname matching is based on the actual hostname, not a substring.
4. Show the brand-lookalike and IP-hosted login patterns.
5. Open Chrome on a supported website and show the extension's RF, CNN + BiLSTM, URL, domain, and page signals.
6. Show **ML vs DL Comparison**, **Analytics**, and **Threat Monitor** after several scans.

## Before presenting

- Run tests: `python3 -m unittest discover -s tests -v`
- Check JavaScript syntax: `node --check extension/background.js`, `node --check extension/content.js`, `node --check extension/popup.js`
- Test the official BIT homepage and ISE URL from the same machine/network as the demo.
- If a model flags a legitimate URL, explain that raw model probabilities and the final hybrid decision are different signals; do not claim perfect detection.
- If the backend is offline, WebShield should display an error rather than a SAFE result.
- Keep the `venv` local to the machine. It is intentionally excluded from the shareable project ZIP.

## Honest scope

- Dashboard URL-only scans analyze the URL and domain signals; they do not fetch and inspect the remote webpage.
- Page structure signals are supplied by the Chrome extension on pages where Chrome permits content scripts.
- IP location and ASN describe hosting/network infrastructure, not the attacker's identity or physical location.
- A SAFE result is not a guarantee that a website is harmless. Dataset and external validation limits should be acknowledged.
