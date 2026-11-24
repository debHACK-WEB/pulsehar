# Rule: Missing Content-Security-Policy (`missing-csp`)

- **Severity:** Low
- **Category:** Security Headers

## What It Detects
Flags HTTP responses that do not include a `Content-Security-Policy` header.

## Why It Matters
`Content-Security-Policy` helps mitigate Cross-Site Scripting (XSS) and data injection risks by restricting allowed resource origins.

## Expected False Positives
- Non-HTML API responses (`application/json`) where browser script execution risk is lower.
- Static assets or endpoints behind a reverse proxy that injects security headers downstream.
