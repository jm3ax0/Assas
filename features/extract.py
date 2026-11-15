"""
features/extract.py
-------------------
Turns a URL (just a piece of text) into a list of NUMBERS the AI model can learn from.

IMPORTANT: We NEVER visit the URL. Everything here is pure string analysis,
so it is safe to run on dangerous links.

Why numbers? A machine-learning model cannot "read" text like a human.
It needs measurable facts, e.g. "this URL is 87 characters long" or
"this URL contains an @ symbol (1 = yes, 0 = no)". Each of these facts is a FEATURE.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Small word lists used by some features
# ---------------------------------------------------------------------------

# Words that phishers love, because they create urgency or imitate a login page.
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "bank", "secure", "account",
    "update", "confirm", "password", "webscr", "ebayisapi", "wallet", "billing",
    "suspend", "unlock", "support", "free", "bonus", "lucky",
]

# Well-known URL shortening services. They hide the real destination.
SHORTENERS = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id", "t.ly", "v.gd", "qr.ae",
]

# Cheap / free top-level domains that are very common in phishing reports.
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "click", "country",
    "work", "loan", "men", "live", "buzz", "rest", "fit",
]

# Two-part endings such as "example.co.uk" – needed to count subdomains correctly.
TWO_PART_SUFFIXES = ["co.uk", "com.au", "co.jp", "co.in", "com.br", "co.za", "org.uk", "ac.uk", "gov.uk"]

# A simple pattern that recognises an IPv4 address like 192.168.10.5
IPV4_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# The list of features, in a FIXED order (the model always needs the same order)
# plus a beginner-friendly explanation of each one.
# ---------------------------------------------------------------------------
FEATURE_DESCRIPTIONS = {
    "url_length":        "Total number of characters. Phishing URLs are often very long to hide the real domain.",
    "hostname_length":   "Length of the domain part (e.g. 'www.paypal.com'). Fake domains are often long and messy.",
    "num_dots":          "How many '.' characters. Many dots usually mean many subdomains, e.g. paypal.com.evil.xyz.",
    "num_hyphens":       "How many '-' in the domain. Phishers glue words together: 'secure-paypal-login.com'.",
    "has_at_symbol":     "1 if the URL contains '@'. Browsers ignore everything before '@', so it can hide the real site.",
    "has_ip_address":    "1 if the domain is a raw IP address (e.g. http://45.12.9.1/) instead of a name.",
    "num_subdomains":    "Number of subdomains before the main domain. 'a.b.example.com' has 2.",
    "uses_https":        "1 if the URL starts with https://. Note: many phishing sites ALSO use https today.",
    "num_digits":        "How many digits (0-9). Random numbers often appear in throw-away phishing URLs.",
    "num_suspicious_words": "How many 'bait' words like login, verify, bank, secure, account appear.",
    "is_shortened":      "1 if a URL shortener (bit.ly, tinyurl...) is used, which hides the destination.",
    "has_double_slash":  "1 if '//' appears later in the URL (a trick to redirect to another site).",
    "suspicious_tld":    "1 if the domain ends in a cheap TLD often abused for phishing (.tk, .xyz, .top...).",
    "num_query_params":  "How many '?key=value' parameters. Phishing links often carry many tracking params.",
    "path_depth":        "How many folders deep the path is: /a/b/c has depth 3.",
}

# The order of this list is the order of columns the model is trained on.
FEATURE_NAMES = list(FEATURE_DESCRIPTIONS.keys())


def _parse(url: str):
    """Split the URL into parts (scheme, hostname, path...).

    urlparse needs a scheme ('http://') to find the hostname, so if the user
    typed just 'example.com/login' we temporarily add 'http://' in front.
    """
    has_scheme = "://" in url
    try:
        parsed = urlparse(url if has_scheme else "http://" + url)
        hostname = (parsed.hostname or "").lower()
    except ValueError:  # e.g. badly formed brackets – just treat as no hostname
        parsed, hostname = urlparse(""), ""
    return parsed, hostname


def _count_subdomains(hostname: str, is_ip: bool) -> int:
    """'mail.google.com' -> 1 subdomain ('mail'). 'a.b.example.co.uk' -> 2."""
    if not hostname or is_ip:
        return 0
    parts = hostname.split(".")
    if parts[0] == "www":          # 'www' is so common we don't count it
        parts = parts[1:]
    # The 'registered domain' is normally the last 2 parts (example.com),
    # or the last 3 for endings like '.co.uk'.
    base = 3 if ".".join(parts[-2:]) in TWO_PART_SUFFIXES else 2
    return max(len(parts) - base, 0)


def extract_features(url: str) -> dict:
    """Return a dictionary {feature_name: number} for ONE url."""
    url = url.strip()
    lower = url.lower()
    parsed, hostname = _parse(url)

    is_ip = bool(IPV4_PATTERN.match(hostname))
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    # Look for '//' AFTER the 'https://' part (position 8 onwards).
    after_scheme = lower.split("://", 1)[1] if "://" in lower else lower

    path_parts = [p for p in parsed.path.split("/") if p]

    features = {
        "url_length":           len(url),
        "hostname_length":      len(hostname),
        "num_dots":             url.count("."),
        "num_hyphens":          hostname.count("-"),
        "has_at_symbol":        int("@" in url),
        "has_ip_address":       int(is_ip),
        "num_subdomains":       _count_subdomains(hostname, is_ip),
        "uses_https":           int(lower.startswith("https://")),
        "num_digits":           sum(ch.isdigit() for ch in url),
        "num_suspicious_words": sum(word in lower for word in SUSPICIOUS_WORDS),
        "is_shortened":         int(hostname.removeprefix("www.") in SHORTENERS),
        "has_double_slash":     int("//" in after_scheme),
        "suspicious_tld":       int(tld in SUSPICIOUS_TLDS),
        "num_query_params":     len([p for p in parsed.query.split("&") if p]),
        "path_depth":           len(path_parts),
    }
    return features


def features_as_list(url: str) -> list:
    """Same as extract_features, but returns just the numbers in FEATURE_NAMES order."""
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]


# Try it yourself:  python features/extract.py "http://paypal-login.verify-account.xyz/@secure"
if __name__ == "__main__":
    import sys
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://secure-login.paypa1-verify.xyz/account/update?id=123"
    print(f"Features for: {test_url}\n")
    for name, value in extract_features(test_url).items():
        print(f"  {name:22} = {value:<5}  # {FEATURE_DESCRIPTIONS[name]}")
