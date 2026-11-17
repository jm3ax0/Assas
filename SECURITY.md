# Security Policy

## Scope

Assas is a **defensive, educational** tool. It classifies URLs by analysing the URL
string only; it never visits, downloads or contacts the URLs it is given.

## Supported versions

Only the latest commit on the `main` branch is supported.

## Reporting a vulnerability

Open an [issue](https://github.com/jm3ax0/Assas/issues/new) with a title starting
with **`[Security]`**. Describe the problem in general terms and where it is
(file / endpoint), but **do not post working exploit code or step-by-step attack details**
in the public issue. The maintainer will reply and, if needed, arrange a private way
to share the full details.

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
