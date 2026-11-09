# SOC Lab as Code

A complete SOC lab deployed 100% as code: build it, harden it, attack it, and detect the attack.

> Status: **Phase 2 complete** (v0.2.0) — next: Phase 3, CI/CD
## What it is

An IOC enrichment API (IP, domain, hash) at the center of a lab built with:

- **Docker** to package the API
- **GitHub Actions** running a DevSecOps pipeline (gitleaks, Semgrep, Trivy, Checkov)
- **Ansible** for CIS hardening and agent installation
- **Terraform** to provision the network and VMs
- **Kubernetes** with NetworkPolicies, RBAC and Falco
- **Wazuh** as the SIEM, attack simulation with **Atomic Red Team**, and detections mapped to **MITRE ATT&CK**

## Roadmap

| Phase | Tool | Status |
| --- | --- | --- |
| 1 | Git and GitHub | Done ([docs](docs/phase-1-git.md)) |
| 2 | Docker | Done ([docs](docs/phase-2-docker.md)) |
| 3 | CI/CD | In progress |
| 4 | Ansible | Planned |
| 5 | Terraform | Planned |
| 6 | Kubernetes | Planned |
| 7 | SOC integration | Planned |

## Run the API locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r app/requirements.txt
uvicorn app.main:app --reload
```

Interactive docs: http://127.0.0.1:8000/docs

```bash
curl -X POST http://127.0.0.1:8000/ioc/classify \
  -H "Content-Type: application/json" \
  -d '{"value": "8[.]8[.]8[.]8"}'
```
## Run with Docker

```bash
docker build -f docker/Dockerfile -t ioc-enricher:dev .
docker run -d --name ioc -p 127.0.0.1:8000:8000 --env-file .env ioc-enricher:dev
curl http://127.0.0.1:8000/health
```

The image is built in two stages and hardened:

- Runs as an unprivileged user (UID 10001), never as root
- Application code is owned by root and read-only for the app user
- pip is removed from the final image
- Built-in healthcheck against `/health` (`docker ps` shows `healthy`)
- Secrets are passed at runtime with `--env-file` and excluded from the build context by `.dockerignore`
## Run the full stack with Docker Compose

Add the PostgreSQL variables to your `.env` (see `.env.example`), then:

```bash
docker compose up -d --build
docker compose ps
```

- API: http://127.0.0.1:8000/docs
- Lookup history: `GET /ioc/history`

Network design:

- `frontend`: the API, its published port (127.0.0.1 only) and internet access for threat intelligence lookups
- `backend` (internal): API ↔ PostgreSQL only; no internet access, database port not published
- Data persists in the `pgdata` volume across `docker compose down` / `up`

Runtime hardening (both services):

- Read-only root filesystem; `/tmp` is a small in-memory tmpfs mounted `noexec,nosuid`
- All Linux capabilities dropped (PostgreSQL gets back only the 5 it needs to start)
- `no-new-privileges` blocks privilege escalation through setuid binaries
- Memory, CPU and process limits contain runaway or compromised containers
## Vulnerability scanning

The image is scanned with [Trivy](https://trivy.dev):

```bash
docker compose build --pull
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.57.1 \
  image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 ioc-enricher:dev
```

Acceptance rule: **no HIGH or CRITICAL vulnerabilities with an available fix.**
Unfixed vulnerabilities are monitored. Accepted risks, if any, are listed in `.trivyignore` with a justification and an expiration date.
## Tests

```bash
pytest -v
```
## Enrich an IP with AbuseIPDB

Requires `ABUSEIPDB_API_KEY` in your `.env` file (see `.env.example`).

```bash
uvicorn app.main:app --reload --env-file .env
curl -X POST http://127.0.0.1:8000/ioc/enrich \
  -H "Content-Type: application/json" \
  -d '{"value": "8.8.8.8"}'
```

Private and loopback addresses are never sent to AbuseIPDB.
## Development setup

```bash
pip install -r requirements-dev.txt
pre-commit install
```

All commits must be signed and pass the pre-commit hooks (gitleaks, private key detection, formatting).
## Repository layout

```text
app/          IOC API (FastAPI) and tests
docker/       Phase 2
.github/      Phase 3 — workflows
ansible/      Phase 4
terraform/    Phase 5
k8s/          Phase 6
detections/   Phase 7 — detection rules
docs/         Documentation for each phase
```

## Security

See [SECURITY.md](SECURITY.md). Secrets are never committed; gitleaks runs on every commit.
