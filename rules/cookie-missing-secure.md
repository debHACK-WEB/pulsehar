# Rule: Cookie Missing Secure Flag (`cookie-missing-secure`)

- **Severity:** Medium
- **Category:** Session & Cookies

## What It Detects
Checks `Set-Cookie` response headers and flags cookies that do not include the `Secure` attribute.

## Why It Matters
Without the `Secure` flag, a browser may send the cookie over unencrypted HTTP connections, exposing session identifiers or tokens to interception.

## Expected False Positives
- Non-sensitive UI or preference cookies with minimal security impact.
- Local development setups (`localhost` / `127.0.0.1`) running without HTTPS.
