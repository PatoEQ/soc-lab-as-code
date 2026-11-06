# SOC Lab as Code

A complete SOC lab deployed 100% as code: build it, harden it, attack it, and detect the attack.

> Status: **Phase 1 — Git** (Day 6: practicing conflicts and rebase)

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
| 1 | Git and GitHub | In progress |
| 2 | Docker | Planned |
| 3 | CI/CD | Planned |
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

## Tests

```bash
pytest -v
```
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
