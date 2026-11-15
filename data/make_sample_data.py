"""
data/make_sample_data.py
------------------------
Creates a SMALL labeled sample dataset (data/sample_urls.csv) so the project
runs end-to-end even without downloading anything.

>>> HOW TO USE A REAL DATASET INSTEAD <<<
Download one of these open datasets and save it as  data/urls.csv  with two columns:
    url,label        (label = 1 for phishing, 0 for legitimate)

  * Kaggle "Phishing Site URLs" (bad/good labels)
      https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
  * Kaggle "Malicious URLs dataset" (phishing/benign/defacement/malware)
      https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
  * PhishTank verified phishing feed (CSV)   https://phishtank.org/developer_info.php
    (combine with a list of legitimate sites, e.g. the Tranco top-1M list)

The training script (model/train.py) automatically prefers data/urls.csv if it exists,
and falls back to data/sample_urls.csv otherwise. It also understands labels written
as "bad"/"good" or "phishing"/"legitimate"/"benign".

The sample below is HAND-WRITTEN + PROGRAMMATICALLY VARIED, so the numbers you get
from it are only a demo. Real accuracy must be measured on a real dataset.
"""

import csv
import random
from pathlib import Path

random.seed(42)  # same "random" data every time, so results are reproducible

# --- Legitimate examples (well-known sites, normal paths) -------------------
LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "amazon.com", "bbc.co.uk",
    "microsoft.com", "apple.com", "python.org", "stackoverflow.com", "nytimes.com",
    "reddit.com", "linkedin.com", "youtube.com", "mozilla.org", "cloudflare.com",
    "paypal.com", "netflix.com", "spotify.com", "dropbox.com", "zoom.us",
    "coursera.org", "edx.org", "mit.edu", "ox.ac.uk", "who.int", "un.org",
    "nasa.gov", "europa.eu", "bbc.com", "theguardian.com", "cnn.com",
    "adobe.com", "oracle.com", "ibm.com", "intel.com", "samsung.com",
]
LEGIT_PATHS = [
    "", "/", "/about", "/docs", "/blog/2024/intro-to-ai", "/products",
    "/help/faq", "/news/world", "/wiki/Machine_learning", "/en/contact",
    "/search?q=python", "/watch?v=dQw4w9WgXcQ", "/jobs", "/pricing",
    "/learn/course-101", "/user/settings", "/download", "/terms",
]
LEGIT_SUBS = ["", "", "", "www.", "docs.", "mail.", "support.", "en."]

# --- Phishing examples (built from typical tricks) --------------------------
BRANDS = ["paypal", "apple", "amazon", "microsoft", "netflix", "facebook",
          "google", "bankofamerica", "chase", "dhl", "whatsapp", "instagram"]
LOOKALIKE = {"paypal": "paypa1", "apple": "app1e", "amazon": "amaz0n",
             "microsoft": "micros0ft", "google": "g00gle", "netflix": "netf1ix"}
BAIT_WORDS = ["login", "verify", "secure", "account", "update", "confirm",
              "signin", "billing", "unlock", "support", "password"]
BAD_TLDS = ["xyz", "tk", "top", "ml", "ga", "cf", "click", "buzz", "info", "ru", "cn"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy"]


def random_token(n):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def make_legit():
    scheme = "https://" if random.random() < 0.9 else "http://"
    return scheme + random.choice(LEGIT_SUBS) + random.choice(LEGIT_DOMAINS) + random.choice(LEGIT_PATHS)


def make_phish():
    """Pick one of several classic phishing URL shapes."""
    brand = random.choice(BRANDS)
    bait = random.choice(BAIT_WORDS)
    tld = random.choice(BAD_TLDS)
    scheme = "https://" if random.random() < 0.5 else "http://"
    style = random.randint(0, 6)

    if style == 0:   # brand as subdomain of an evil domain: paypal.com.secure-check.xyz
        return f"{scheme}{brand}.com.{bait}-{random_token(5)}.{tld}/{bait}"
    if style == 1:   # hyphenated words: secure-paypal-login.top
        return f"{scheme}{bait}-{brand}-{random.choice(BAIT_WORDS)}.{tld}/{random_token(8)}"
    if style == 2:   # raw IP address
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{brand}/{bait}.php?id={random.randint(1000, 99999)}"
    if style == 3:   # '@' trick: real-looking text before @, evil host after
        return f"http://{brand}.com@{random_token(10)}.{tld}/{bait}"
    if style == 4:   # look-alike spelling: paypa1-verify.com
        fake = LOOKALIKE.get(brand, brand + "1")
        return f"{scheme}{fake}-{bait}.com/{random_token(6)}/{bait}"
    if style == 5:   # URL shortener
        return f"https://{random.choice(SHORTENERS)}/{random_token(7)}"
    # style 6: very long URL with lots of params and digits
    params = "&".join(f"{random_token(3)}={random.randint(100, 99999)}" for _ in range(random.randint(3, 6)))
    return f"{scheme}{random_token(12)}.{tld}/{brand}/{bait}/{random_token(10)}?{params}"


def main(n_each=400):
    out = Path(__file__).with_name("sample_urls.csv")
    rows = [(make_legit(), 0) for _ in range(n_each)] + [(make_phish(), 1) for _ in range(n_each)]
    random.shuffle(rows)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
