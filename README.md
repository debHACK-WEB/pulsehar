# PulseHAR

A Python CLI tool for security analysis of **HAR (HTTP Archive)** files, identifying weak configurations and sensitive exposures such as leaked tokens, cookies missing the `Secure` flag, and missing security headers.

> **Ethical & Legal Disclaimer:** This tool is intended strictly for authorized security testing, education, and analyzing traffic you own or have explicit permission to inspect. Do not use it against systems or targets without prior authorization.

---

## Problem It Solves

Capturing HAR files during web testing or traffic inspection is straightforward, but manually reviewing entries for security issues is slow and tedious, while generic scanners often produce noisy false positives. **PulseHAR** focuses on analyzing recorded HTTP/HTTPS traffic and summarizing actionable security findings directly from the terminal.

---

## Installation

`pip install pulsehar`

Or for local development from the repository:

`git clone https://github.com/your-username/pulsehar.git && cd pulsehar && pip install -e .`

---

## Quick Start

Export a HAR file from your browser, **Burp Suite**, or **mitmproxy**, then run an analysis:

`pulsehar analyze examples/sample.har`

Filter findings by severity or ignore specific rules:

`pulsehar analyze examples/sample.har --severity high --ignore missing-csp`

---

## Example Output

[HIGH] Exposed Bearer Token in Request Header
  URL: https://api.example.com/v1/profile
  Detail: Authorization header contains a bearer token over a non-TLS or unmasked trace.

[MEDIUM] Cookie Missing Secure Flag
  URL: https://example.com/login
  Detail: Set-Cookie header sets session_id without the Secure attribute.

Summary: 1 High, 1 Medium | Scanned 42 HTTP entries in 0.14s

---

## Rules & Customization

See the `rules/` directory for details on what each rule detects, why it matters, and expected false positives. You can customize scans using `--ignore` or a configuration file.

---

## Contributing & License

Contributions are welcome via Issues and Pull Requests (see `CONTRIBUTING.md`). Licensed under `LICENSE`.
