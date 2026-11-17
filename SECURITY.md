# Security Policy

## Scope

Assas is a **defensive, educational** tool. It classifies URLs by analysing the URL
string only; it never visits, downloads or contacts the URLs it is given.

## Supported versions

Only the latest commit on the `main` branch is supported.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub instead:
**Security** tab of this repository → **Report a vulnerability**.

Include, if possible:
- what the problem is and where (file / endpoint),
- steps to reproduce,
- the impact you expect.

You should get a first reply within 7 days. Once a fix is available, the issue will be
disclosed in the release notes with credit to the reporter (unless you prefer otherwise).

## Things to know when running Assas

- **Model files are pickles.** `model/phishing_model.joblib` is loaded with `joblib`,
  which can execute code. Only load model files you trained yourself or downloaded from
  this repository. Never load a `.joblib` file from an untrusted source.
- **Local use only.** `app/app.py` runs Flask's development server bound to
  `127.0.0.1` with `debug=True`. Do not expose it to a network or the internet. For any
  shared deployment, set `debug=False` and use a production WSGI server behind a reverse proxy.
- **Predictions can be wrong.** A "Legitimate" verdict is not a guarantee that a URL is safe.
  Do not use Assas as the only control for blocking or allowing traffic.

## Out of scope

- Misclassification of individual URLs (false positives / negatives) — please open a
  normal issue with the URL instead.
- Vulnerabilities in third-party dependencies (Flask, scikit-learn, pandas, joblib) —
  report those to the respective projects.
