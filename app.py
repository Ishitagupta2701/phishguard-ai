"""Flask web app: AI-based phishing website detector."""
import os

import joblib
import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, url_for

import database
from features import FEATURE_NAMES, explain, feature_vector, normalize

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")

app = Flask(__name__)
database.init_db()

if not os.path.exists(MODEL_PATH):
    raise SystemExit("Model not found. Run:  python train_model.py")
model = joblib.load(MODEL_PATH)


def classify(raw_url: str) -> dict:
    url = raw_url.strip()
    vec = pd.DataFrame([feature_vector(url)], columns=FEATURE_NAMES)
    prob = float(model.predict_proba(vec)[0][1])
    if prob >= 0.70:
        verdict = "phishing"
    elif prob >= 0.40:
        verdict = "suspicious"
    else:
        verdict = "safe"
    reasons = explain(url)
    return {
        "url": url,
        "normalized": normalize(url),
        "verdict": verdict,
        "probability": round(prob, 4),
        "percent": round(prob * 100, 1),
        "reasons": reasons,
    }


def valid_input(url: str) -> bool:
    return bool(url) and len(url) <= 2048 and " " not in url.strip()


@app.route("/")
def index():
    return render_template("index.html", stats=database.get_stats(), result=None)


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    if not valid_input(url):
        return render_template(
            "index.html", stats=database.get_stats(), result=None,
            error="Please enter a valid URL (no spaces, max 2048 characters).",
        ), 400
    result = classify(url)
    database.save_scan(result["url"], result["verdict"], result["probability"], result["reasons"])
    return render_template("index.html", stats=database.get_stats(), result=result)


@app.route("/history")
def history():
    verdict = request.args.get("verdict")
    rows = database.get_history(limit=200, verdict=verdict)
    return render_template("history.html", rows=rows, active=verdict, stats=database.get_stats())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not valid_input(url):
        return jsonify(error="Provide a valid 'url' in the JSON body"), 400
    result = classify(url)
    database.save_scan(result["url"], result["verdict"], result["probability"], result["reasons"])
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    return jsonify(database.get_stats())


@app.route("/about")
def about():
    return render_template("about.html", features=FEATURE_NAMES)


if __name__ == "__main__":
    app.run(debug=True)
