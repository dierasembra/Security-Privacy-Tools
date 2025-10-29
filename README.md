# Security & Privacy Tools

A lightweight toolkit of **Security & Privacy** utilities for developers and teams.  
Designed as a GitHub Sponsor-ready open-source starter repo focused on defensive tooling (secret detection, log redaction, password checks, and simple privacy helpers).

**Important**: This project is defensive only — it helps find and redact accidental secret leakage, check password strength, and sanitize logs. It does not provide offensive or exploit code.

## Features

- `scan-secrets <path>` — scan files or directories for common secret patterns (API keys, AWS secrets, private keys) and report findings.
- `redact-file <infile> <outfile>` — redact detected secrets in a file and write a safe copy.
- `sanitize-log <infile> <outfile>` — remove or mask IP addresses, emails, and known secrets from logs.
- `check-password <password>` — basic password checks: length, entropy estimate, common-password check (local list).
- Simple, well-documented, and extendable for teams; suitable for GitHub Sponsors.

## Quickstart

1. Create virtualenv and install:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Scan a directory for secrets:
```bash
security-tools scan-secrets ./
```

3. Redact a file:
```bash
security-tools redact-file examples/sample_secrets.txt examples/safe_copy.txt
```

4. Sanitize logs:
```bash
security-tools sanitize-log logs/app.log logs/app.safe.log
```

5. Check a password:
```bash
security-tools check-password "S3cureP@ssw0rd!"
```

## Sponsorship

If you find this project useful, consider sponsoring development to fund:
- more detection rules (YAML, Terraform, cloud config)
- integration with CI (pre-commit, GitHub Actions)
- larger common-password lists and telemetry (privacy-preserving)

Add a `FUNDING.yml` file and Sponsor button on the repo to make supporting easy.

## Structure

- `src/security_privacy_tools` — CLI and helpers
- `examples` — sample files
- `docs` — usage notes
- `tests` — unit tests
- `.github` — workflow templates

## License

MIT
