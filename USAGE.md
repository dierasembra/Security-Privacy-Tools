# Usage Notes

This repo provides defensive utilities for teams to detect accidental secret leakage and sanitize logs locally or in CI.

- `scan-secrets` is a lightweight scanner using regex patterns; it's not a replacement for full secret-scanning solutions but is handy for small projects and CI.
- `redact-file` and `sanitize-log` create safe copies with secrets and PII masked.
- `check-password` performs a quick, local entropy estimate and common-password check (do not rely on it for compliance).

Extend the patterns and integrate into pre-commit or GitHub Actions for automated scanning.
