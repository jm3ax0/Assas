"""
model/train.py
--------------
Trains the AI model and saves it to model/phishing_model.joblib

Run from the project root:
    python model/train.py

What happens, step by step:
  1. Load a CSV of URLs with labels (1 = phishing, 0 = legitimate).
  2. Convert every URL into numbers using features/extract.py.
  3. Split into a TRAINING set (model learns from it) and a TEST set
     (model has never seen it, so we can measure honest accuracy).
  4. Train a RandomForest classifier.
  5. Print accuracy, precision, recall, F1 and the confusion matrix.
  6. Save the model + feature names with joblib so the Flask app can use it.
"""

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_score, recall_score)
from sklearn.model_selection import train_test_split

# Let Python find the "features" package one folder up.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from features.extract import FEATURE_NAMES, features_as_list  # noqa: E402

DATA_DIR = ROOT / "data"
MODEL_PATH = Path(__file__).with_name("phishing_model.joblib")

# Accept the most common ways datasets write labels.
LABEL_MAP = {
    "1": 1, "0": 0, "phishing": 1, "bad": 1, "malicious": 1, "malware": 1,
    "defacement": 1, "legitimate": 0, "good": 0, "benign": 0, "safe": 0,
}


def load_dataset() -> pd.DataFrame:
    """Prefer the real dataset (data/urls.csv); fall back to the generated sample."""
    real, sample = DATA_DIR / "urls.csv", DATA_DIR / "sample_urls.csv"
    if real.exists():
        print(f"[1/6] Loading REAL dataset: {real}")
        df = pd.read_csv(real)
    else:
        if not sample.exists():
            print("No dataset found - generating sample data first...")
            from data.make_sample_data import main as make_sample
            make_sample()
        print(f"[1/6] Loading SAMPLE dataset: {sample}  (drop a real one at data/urls.csv)")
        df = pd.read_csv(sample)

    # Normalise column names: some datasets call them URL/Label or url/type.
    df.columns = [c.strip().lower() for c in df.columns]
    if "type" in df.columns and "label" not in df.columns:
        df = df.rename(columns={"type": "label"})
    if "url" not in df.columns or "label" not in df.columns:
        sys.exit(f"CSV must have 'url' and 'label' columns. Found: {list(df.columns)}")

    df["label"] = df["label"].astype(str).str.strip().str.lower().map(LABEL_MAP)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    print(f"      {len(df)} rows  |  phishing={int(df.label.sum())}  legitimate={int((df.label == 0).sum())}")
    return df


def main():
    df = load_dataset()

    print("[2/6] Extracting features from every URL (string analysis only)...")
    X = pd.DataFrame([features_as_list(u) for u in df["url"].astype(str)], columns=FEATURE_NAMES)
    y = df["label"].values

    print("[3/6] Splitting 80% train / 20% test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[4/6] Training RandomForest (150 decision trees)...")
    model = RandomForestClassifier(
        n_estimators=150,     # number of trees in the forest
        max_depth=24,         # cap tree depth: keeps the saved model < 50 MB (GitHub-friendly)
        min_samples_leaf=3,   # a leaf must hold >= 3 URLs, so trees don't memorise single examples
        class_weight="balanced",  # protect against unbalanced datasets
        random_state=42,
        n_jobs=-1,            # use all CPU cores
    )
    model.fit(X_train, y_train)

    print("[5/6] Evaluating on the unseen test set...\n")
    y_pred = model.predict(X_test)
    print(f"  Accuracy : {accuracy_score(y_test, y_pred):.3f}   (share of all URLs classified correctly)")
    print(f"  Precision: {precision_score(y_test, y_pred):.3f}   (of URLs flagged phishing, how many really were)")
    print(f"  Recall   : {recall_score(y_test, y_pred):.3f}   (of real phishing URLs, how many we caught)\n")
    print("  Confusion matrix  [rows = truth, cols = prediction]")
    cm = confusion_matrix(y_test, y_pred)
    print("                 pred Legit  pred Phish")
    print(f"  true Legit     {cm[0][0]:>9}  {cm[0][1]:>10}")
    print(f"  true Phish     {cm[1][0]:>9}  {cm[1][1]:>10}\n")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Which features did the forest rely on most? (useful for your motivation letter)
    print("  Feature importance (what the model pays attention to):")
    for name, imp in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1]):
        print(f"    {name:22} {'#' * int(imp * 60):<30} {imp:.3f}")

    print(f"\n[6/6] Saving model to {MODEL_PATH}")
    # compress=3 keeps the file small enough to commit to GitHub.
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_PATH, compress=3)
    print(f"      model size: {MODEL_PATH.stat().st_size / 1e6:.1f} MB")
    print("Done. Now run:  python app/app.py")


if __name__ == "__main__":
    main()
