# Phase 2 — Docker

**Period:** 2026-11-06 to 2026-11-09
**Release:** [v0.2.0](https://github.com/PatoEQ/soc-lab-as-code/releases/tag/v0.2.0)

## Goal

Package the IOC Enricher API in a minimal, hardened container image, run it with PostgreSQL through Docker Compose, and keep the image free of known fixable HIGH and CRITICAL vulnerabilities.

## What was built

- `docker/Dockerfile`: multi-stage build on `python:3.12-slim`, non-root user, no pip, healthcheck.
- `.dockerignore`: secrets, `.git`, tests and tooling never reach the build context.
- `compose.yaml`: API + PostgreSQL 16 with segmented networks and runtime hardening.
- Lookup history: every enrichment is stored in PostgreSQL and exposed through `GET /ioc/history`.
- Vulnerability scanning with Trivy and a documented acceptance rule.

## Architecture

```text
                 127.0.0.1:8000 (this computer only)
                          │
     ┌──── frontend network (internet access) ────┐
     │               ┌─────────┐                  │
     │               │   api   │ ───────────────────► AbuseIPDB
     │               └────┬────┘                  │
     └────────────────────┼───────────────────────┘
     ┌──── backend network (internal, no internet) ──┐
     │               ┌────┴────┐                     │
     │               │   db    │ PostgreSQL 16       │
     │               └────┬────┘ no published ports  │
     └────────────────────┼──────────────────────────┘
                     pgdata volume
```

## Security controls

| Layer | Control | What it prevents |
| --- | --- | --- |
| Build | `.dockerignore` excludes `.env`, `.git`, tests | Secrets or history baked into the image |
| Image | `python:3.12-slim` base with a pinned tag | Hundreds of unneeded packages; surprise changes from `latest` |
| Image | Multi-stage build; pip removed | Installing attack tools inside the container |
| Image | Non-root user (UID 10001); code owned by root | Root inside the container; tampering with the code |
| Image | Debian security updates applied at build time | Known OS vulnerabilities waiting for a base image rebuild |
| Image | `HEALTHCHECK` on `/health` | A running but broken service going unnoticed |
| Runtime | Read-only root filesystem | Persisting files or modifying binaries |
| Runtime | `/tmp` tmpfs with `noexec,nosuid` | Running downloaded payloads |
| Runtime | All capabilities dropped (db keeps 5) | Privileged kernel operations |
| Runtime | `no-new-privileges` | Escalation through setuid binaries |
| Runtime | Memory, CPU and PID limits | Resource exhaustion, fork bombs |
| Network | API published on 127.0.0.1 only | Exposure to the local network |
| Network | Database on an internal network, no published port | Direct access to the database; data exfiltration |
| Secrets | Passed at runtime with `--env-file`; random 48-char DB password | Credentials inside images or the repository |

## Vulnerability management

Acceptance rule: **no HIGH or CRITICAL vulnerabilities with an available fix.**

```bash
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 ioc-enricher:dev
```

Results (HIGH / CRITICAL):

| Image | HIGH | CRITICAL |
| --- | --- | --- |
| python:3.12 (full) | ? | ? |
| python:3.12-slim | ? | ? |
| ioc-enricher:dev before fixes | 2 | 0 |
| ioc-enricher:dev after fixes | 0 | 0 |

Finding analysis:

- **CVE-2026-85091** — zlib heap buffer overflow in `gz_vacate()`, HIGH (CVSS 8.3). Fixed in Debian `1:1.3.dfsg+really1.3.1-1+deb13u1` (DSA-6613-1), not yet in the base image. Exploitability for this API is low (it does not use `gzprintf`/`gzvprintf`), fixed anyway per the acceptance rule by applying Debian security updates at build time.
- **CVE-2026-76844** — reported on the same zlib package with an unrelated title (webpack-dev-middleware). Treated as a scanner data error; resolved by the same package update.
- Python dependencies: no HIGH or CRITICAL findings with a fix.

## What I learned

- An image is a read-only template made of layers; a container is a running instance of it.
- Anything copied into a layer stays in the image, even if a later step deletes it.
- Containers share the host kernel, so isolation must be reinforced: non-root, no capabilities, read-only filesystem.
- Smaller base images mean fewer packages and fewer vulnerabilities.
- Vulnerability management is prioritization: fix what has a patch, document the rest.
- Scanners can be wrong; findings are verified against primary sources before acting.

## Evidence

![nginx access logs](images/phase-2/01-nginx-logs.png)
![Base image sizes](images/phase-2/02-base-image-sizes.png)
![Fully cached rebuild](images/phase-2/03-build-cache.png)
![Container runs as UID 10001](images/phase-2/04-non-root-user.png)
![Writes and sensitive reads denied](images/phase-2/05-permission-denied.png)
![Healthy containers](images/phase-2/06-healthy.png)
![Lookup history](images/phase-2/07-lookup-history.png)
![Database isolated from the host and the internet](images/phase-2/08-network-isolation.png)
![Trivy before fixes](images/phase-2/09-trivy-before.png)
![Trivy after fixes](images/phase-2/10-trivy-after.png)
![Trivy Dockerfile checks](images/phase-2/11-trivy-config.png)
![Read-only filesystem and noexec tmp](images/phase-2/12-readonly-noexec.png)
![No capabilities and no new privileges](images/phase-2/13-capabilities.png)
![Resource limits](images/phase-2/14-resource-limits.png)

## Problems and solutions

| Problem | Cause | Solution |
| --- | --- | --- |
| `port is already allocated` on 8080 and 8088 | Other local labs already published those ports | Checked with `netstat -ano`, used a free port |
| `container name "/web" is already in use` | Failed `docker run` attempts still create the container | `docker rm -f` on the leftovers |
| `mkdir C:\Program Files\Git\var: Access is denied` | Git Bash converts paths starting with `/` to Windows paths | `export MSYS_NO_PATHCONV=1` in `~/.bashrc` on each workstation |
| `ModuleNotFoundError: No module named 'app'` | pytest import path detection | `pytest.ini` with `pythonpath = .` and `testpaths` |
| Local Python 3.13 vs 3.12 in the image | Different interpreter installed on one workstation | Recreated `.venv` with `py -3.12` |
| HIGH zlib CVE still present after `--pull` | Debian patch not yet in the base image | `apt-get upgrade` in the runtime stage |
| Trivy 0.57.1 failed to parse newer built-in checks | Old scanner with a newer rules bundle | `--skip-check-update`; pin scanner and rules together |
| `docker compose config` prints secrets | It renders the final config with interpolated variables | Use `docker compose config --quiet` to validate only |

## Decisions

- `python:3.12-slim` as base image: small and compatible with Python wheels.
- Fixed numeric UID (10001) so Kubernetes `runAsNonRoot` can verify it in Phase 6.
- Debian security updates applied at build time instead of waiting for base image rebuilds.
- Ports bound to 127.0.0.1; the database is never published.
- `httpx` kept for now; migration to `httpx2` (Starlette deprecation warning) evaluated in Phase 3.

## Local setup per workstation

These live on each computer and are not versioned:

| Item | Location |
| --- | --- |
| Git identity, signing, editor | `~/.gitconfig` |
| SSH keys (one per device) | `~/.ssh/` |
| `MSYS_NO_PATHCONV`, Trivy alias | `~/.bashrc` |
| API key and PostgreSQL credentials | `.env` |
| pre-commit hooks | `.git/hooks/` |
| Python 3.12 virtual environment | `.venv/` |

## Next phase

Phase 3 — CI/CD: run tests, gitleaks, Semgrep and Trivy automatically on every pull request with GitHub Actions, and publish the image to GitHub Container Registry.
