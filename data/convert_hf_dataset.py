"""
data/convert_hf_dataset.py
--------------------------
Converts the Hugging Face dataset  ealvaradob/phishing-dataset  (file: urls.json)
into the simple  data/urls.csv  format that model/train.py expects (url,label).

Usage:
    python data/convert_hf_dataset.py  path/to/urls.json

Source: https://huggingface.co/datasets/ealvaradob/phishing-dataset  (Apache-2.0)
~800k URLs compiled from PhishTank, OpenPhish, JPCERT and other public feeds.
"""

import json
import sys
from pathlib import Path

import pandas as pd


def main(src: str):
    print(f"Reading {src} ...")
    with open(src, encoding="utf-8") as f:
        records = json.load(f)

    df = pd.DataFrame(records)
    # The HF file uses the columns 'text' (the URL) and 'label' (1 phishing / 0 benign).
    df = df.rename(columns={"text": "url"})[["url", "label"]]
    before = len(df)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len().between(4, 2048)]      # drop empty / absurd rows
    df = df.drop_duplicates(subset="url")               # same URL twice teaches nothing
    df["label"] = df["label"].astype(int)

    out = Path(__file__).with_name("urls.csv")
    df.to_csv(out, index=False)
    print(f"Wrote {len(df):,} rows (removed {before - len(df):,} duplicates/invalid) -> {out}")
    print(f"  phishing   = {int(df.label.sum()):,}")
    print(f"  legitimate = {int((df.label == 0).sum()):,}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python data/convert_hf_dataset.py <path to urls.json>")
    main(sys.argv[1])
