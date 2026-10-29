# PhishGuard AI – Phishing Website Detector

A machine-learning web app that analyses a URL and tells you whether it looks like a phishing site.

**Tech stack:** Python (Flask, scikit-learn, pandas) · HTML · CSS · SQL (SQLite)

## Features
- Paste a URL and get a verdict: **Safe / Suspicious / Phishing** with a probability score
- Plain-English explanation of the warning signs found
- Every scan stored in an SQL database; history page with filters
- Live statistics (total / phishing / suspicious / safe)
- JSON REST API (`/api/scan`, `/api/stats`)

## Project structure
```
phishing_detector/
├── app.py                # Flask app (routes, prediction)
├── features.py           # URL feature extraction + explanations
├── generate_dataset.py   # Builds a demo dataset (data/urls.csv)
├── train_model.py        # Trains Random Forest, saves model/phishing_model.pkl
├── database.py           # SQLite helper functions
├── schema.sql            # SQL table definition
├── requirements.txt
├── templates/            # base.html, index.html, history.html, about.html
└── static/style.css
```

## Setup & run
```bash
pip install -r requirements.txt
python generate_dataset.py     # creates data/urls.csv
python train_model.py          # trains and saves the model
python app.py                  # open http://127.0.0.1:5000
```

## How it works
1. **Feature extraction** – 21 numeric features per URL: length, dots, hyphens, digit ratio, number of subdomains, IP-address host, `@` symbol, HTTPS, non-standard port, suspicious keywords (login, verify, secure…), suspicious TLDs, URL shorteners, punycode, host entropy, etc.
2. **Model** – Random Forest classifier outputs P(phishing).
3. **Verdict** – ≥ 0.70 phishing · 0.40–0.69 suspicious · < 0.40 safe.
4. **Storage** – results saved to the `scans` table in `scans.db`.

## API example
```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.xyz/verify"}'
```

## Important: dataset note
`generate_dataset.py` creates a **synthetic** dataset so the project runs offline. The ~98 % accuracy it reports is
on that synthetic data and will be **optimistic** for real-world links. For a real project:
1. Download phishing URLs from [PhishTank](https://phishtank.org) / [OpenPhish](https://openphish.com) and legitimate URLs from the [Tranco](https://tranco-list.eu) top-sites list (or a Kaggle "Phishing Site URLs" dataset).
2. Save as `data/urls.csv` with columns `url,label` (1 = phishing, 0 = legitimate).
3. Run `python train_model.py` again.

## Limitations
- Analyses the URL string only, not page content, SSL certificate or domain age.
- A real deployment should combine this with blocklists and domain-reputation checks.

## Ideas to extend
- Add WHOIS domain-age and SSL-certificate features
- HTML content features (forms asking for passwords, hidden iframes)
- Browser extension that calls `/api/scan`
- Switch SQLite to MySQL/PostgreSQL; add user login
- Compare models (Logistic Regression, XGBoost) in `train_model.py`


## Deploy online with Render

1. Create a GitHub repository and upload the contents of this project folder (including `app.py`, `model/`, `templates/`, and `static/`) to the repository root.
2. In Render, create a new **Blueprint** and connect that GitHub repository. Render reads `render.yaml` and builds the web service.
3. Wait for the deployment to finish, then open the `onrender.com` URL Render shows for the service.

The SQLite scan history is stored on the service filesystem and may reset when a free service restarts or redeploys. The model uses a synthetic training dataset for demonstration, so predictions are educational and should not be treated as definitive security advice.
