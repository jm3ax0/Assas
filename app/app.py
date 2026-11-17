"""
app/app.py
----------
A small Flask web app: paste a URL, get a verdict + risk score + reasons.

Run from the project root:
    python app/app.py
then open http://127.0.0.1:5000 in your browser.

The URL is NEVER visited. We only analyse the text you typed.
"""

import sys
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from features.extract import FEATURE_DESCRIPTIONS, FEATURE_NAMES, extract_features  # noqa: E402

MODEL_PATH = ROOT / "model" / "phishing_model.joblib"
if not MODEL_PATH.exists():
    sys.exit("Model not found. Train it first:  python model/train.py")

bundle = joblib.load(MODEL_PATH)
model = bundle["model"]

app = Flask(__name__)

# Human-readable sentences for the "top reasons" card.
# Each entry: feature -> (condition on value, text shown when condition is true)
REASON_RULES = [
    ("has_ip_address",       lambda v: v == 1, "The domain is a raw IP address instead of a name"),
    ("has_at_symbol",        lambda v: v == 1, "Contains an '@' symbol, which can hide the real destination"),
    ("is_shortened",         lambda v: v == 1, "Uses a URL-shortening service that hides where it really goes"),
    ("suspicious_tld",       lambda v: v == 1, "Domain ends in a cheap TLD frequently abused by phishers"),
    ("num_suspicious_words", lambda v: v >= 1, "Contains bait words such as login / verify / secure / account"),
    ("num_subdomains",       lambda v: v >= 2, "Has many subdomains (a brand name may be hiding in front of the real domain)"),
    ("num_hyphens",          lambda v: v >= 2, "Domain contains several hyphens, typical of made-up look-alike names"),
    ("url_length",           lambda v: v >= 75, "The URL is unusually long"),
    ("num_digits",           lambda v: v >= 6, "Contains many digits, common in throw-away phishing links"),
    ("has_double_slash",     lambda v: v == 1, "Has an extra '//' inside the path (possible redirect trick)"),
    ("num_query_params",     lambda v: v >= 3, "Carries many query parameters"),
    ("uses_https",           lambda v: v == 0, "Does not use HTTPS"),
]
SAFE_RULES = [
    ("uses_https",           lambda v: v == 1, "Uses HTTPS"),
    ("num_subdomains",       lambda v: v == 0, "Simple domain with no extra subdomains"),
    ("num_suspicious_words", lambda v: v == 0, "No bait words"),
    ("url_length",           lambda v: v < 40, "Short, clean URL"),
    ("has_ip_address",       lambda v: v == 0, "Uses a real domain name, not an IP"),
]


def explain(features: dict, is_phishing: bool) -> list:
    """Pick the top reasons, ordered by how important the model finds each feature."""
    importance = dict(zip(FEATURE_NAMES, model.feature_importances_))
    rules = REASON_RULES if is_phishing else SAFE_RULES
    hits = [(importance[f], text) for f, cond, text in rules if cond(features[f])]
    hits.sort(reverse=True)
    return [text for _, text in hits[:4]]


def analyse(url: str) -> dict:
    features = extract_features(url)
    # One-row table with the same column names the model was trained on.
    row = pd.DataFrame([[features[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
    # predict_proba gives [P(legit), P(phishing)] -> we show P(phishing) as the risk.
    risk = float(model.predict_proba(row)[0][1])
    is_phishing = risk >= 0.5
    return {
        "url": url,
        "verdict": "Phishing" if is_phishing else "Legitimate",
        "risk_percent": round(risk * 100),
        "reasons": explain(features, is_phishing),
        "features": {n: {"value": features[n], "about": FEATURE_DESCRIPTIONS[n]} for n in FEATURE_NAMES},
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result, error = None, None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please enter a URL."
        elif len(url) > 2048:
            error = "URL is too long (max 2048 characters)."
        else:
            result = analyse(url)
    return render_template("index.html", result=result, error=error)


@app.route("/api/check", methods=["POST"])
def api_check():
    """JSON endpoint:  curl -X POST -H "Content-Type: application/json" -d '{"url":"http://..."}' /api/check"""
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url or len(url) > 2048:
        return jsonify({"error": "Provide a 'url' (max 2048 chars)"}), 400
    return jsonify(analyse(url))


if __name__ == "__main__":
    # debug=True auto-reloads on code changes. Turn it off if you ever deploy this.
    app.run(host="127.0.0.1", port=5000, debug=True)
