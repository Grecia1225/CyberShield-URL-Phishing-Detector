# CyberShield — URL Phishing Detection (Local Working Project)

A beginner-friendly, local-first phishing URL detector with:
- A Flask web dashboard to scan URLs manually.
- A Chrome/Chromium Manifest V3 extension that checks navigated URLs automatically.
- Heuristic risk scoring with explainable reasons.
- A JSON API and basic automated tests.
- Optional CSV-based ML training script (requires a real, labelled dataset).

**Important:** This is a defensive prototype, not a guarantee that a site is safe. Heuristics can produce false positives and false negatives. Do not enter passwords or sensitive information on a suspicious site.

## Project structure

```text
CyberShield_URL_Phishing_Detector/
├── backend/
│   ├── app.py
│   ├── detector.py
│   ├── templates/index.html
│   └── static/style.css
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── popup.html
│   ├── popup.js
│   ├── warning.html
│   └── warning.js
├── tests/test_detector.py
├── data/sample_urls.csv
├── train_model.py
├── requirements.txt
├── .gitignore
└── README.md
```

## 1. Requirements

- Python 3.10+ recommended
- Google Chrome or a Chromium-based browser
- Internet is not required for the local detector itself

## 2. Run the backend

### Windows (PowerShell)

```powershell
cd CyberShield_URL_Phishing_Detector
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python backend/app.py
```

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe backend/app.py
```

### Linux / macOS

```bash
cd CyberShield_URL_Phishing_Detector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python backend/app.py
```

Open **http://127.0.0.1:5000** in your browser.

The server binds to `127.0.0.1` only, so it is not exposed to your local network by default.

## 3. Install the Chrome extension

1. Keep the backend running.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode**.
4. Click **Load unpacked**.
5. Select this project's `extension` folder.
6. Open a website in a new tab. The extension checks its URL using your local backend.
7. Click the CyberShield extension icon to view the last scan.

The extension needs broad website-navigation access to inspect visited URLs. Chrome will show a permission notice. Its source code sends the URL only to `http://127.0.0.1:5000/api/scan` on your own computer; it does not upload URLs to a cloud service. You can disable or remove it at `chrome://extensions`.

## 4. Test the API

In a second terminal:

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://secure-login-example.invalid/verify-account\"}"
```

Expected: JSON containing `label`, `risk_score`, and `reasons`.

Health check:
```bash
curl http://127.0.0.1:5000/api/health
```

## 5. Run tests

```bash
python -m unittest discover -s tests -v
```

## 6. Optional ML training

`train_model.py` is optional. It expects a labelled CSV with columns:
- `url`
- `label` (`1` = phishing, `0` = legitimate)

Example:
```bash
pip install -r requirements-ml.txt
python train_model.py --csv path/to/your_labelled_urls.csv
```

Only train on a dataset you are legally allowed to use. The small `data/sample_urls.csv` file is for testing the workflow and is **not** a credible training dataset. The production detector currently uses explainable heuristics and does not load a trained model automatically.

## What the detector checks

- URL parsing and hostname validity
- IP-address hostnames
- HTTPS versus HTTP (a weak signal, not proof)
- `@` in a URL
- Punycode hostnames (`xn--`)
- Suspicious URL words such as `login`, `verify`, `wallet`, `update`, `password`
- Unusually long URLs / hostnames
- Many subdomains
- Numeric/hyphen-heavy hostnames
- Known high-risk URL patterns

Risk score bands:
- 0–29: **LOW RISK** (not proof of safety)
- 30–59: **SUSPICIOUS**
- 60–100: **HIGH RISK**

## Limitations and next steps

- No live domain-age lookup, reputation feed, sandboxing, or real-time threat-intelligence provider is included.
- HTTPS does not mean a website is trustworthy.
- A malicious site can evade simple heuristics; a legitimate URL can be flagged.
- For a serious deployment, add trusted threat-intelligence feeds, allow-list management, robust logging controls, privacy review, rate limiting, and a proper trained model validated on current data.
