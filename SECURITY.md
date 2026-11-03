# Security Policy

## Secrets handling

- API keys (AbuseIPDB, VirusTotal, OTX) live in a local `.env` file or in GitHub Secrets.
- `.env` is listed in `.gitignore`; use `.env.example` as the template.
- gitleaks runs as a pre-commit hook and in the CI pipeline.
- If a secret is ever pushed: revoke it with the provider immediately. Removing it from the history is not enough.

## Reporting a vulnerability

Open a private Security Advisory in this repository with steps to reproduce.
