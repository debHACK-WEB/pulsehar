# Rule: Exposed Bearer Token (`exposed-bearer-token`)

- **Severity:** High
- **Category:** Authentication & Secrets

## What It Detects
Detects Bearer tokens in `Authorization` headers or token-like query parameters inside recorded HAR entries.

## Why It Matters
Leaked bearer tokens can enable unauthorized access to accounts or APIs if a HAR capture is shared or stored without sanitization.

## Expected False Positives
- Dummy or placeholder tokens in test or documentation traffic.
- Revoked or short-lived demo tokens in non-production environments.
