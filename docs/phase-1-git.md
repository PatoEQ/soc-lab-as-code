# Phase 1 — Git and GitHub

**Period:** 2026-10-28 to 2026-11-06
**Release:** [v0.1.0](https://github.com/PatoEQ/soc-lab-as-code/releases/tag/v0.1.0)

## Goal

Create the repository, work with branches and pull requests, protect the repo against secret leaks, and publish the first version of the IOC Enricher API.

## What was built

- Repository structure for all seven phases, with README, SECURITY policy and `.env.example`.
- IOC Enricher API v0.1:
  - `POST /ioc/classify` detects IPv4, IPv6, domains and MD5/SHA1/SHA256 hashes, including defanged values (`8[.]8[.]8[.]8`).
  - `POST /ioc/enrich` looks up public IPs in AbuseIPDB and returns a verdict.
  - `GET /health` returns service name, version and a UTC timestamp.
- 24 automated tests; external APIs are mocked, so tests never touch the network.

## What I learned

- Branches isolate work; `main` only changes through pull requests.
- Signed commits prove authorship; anyone can fake `user.email`, nobody can fake my signature.
- gitleaks blocks secrets before they become part of the history.
- Rebase replays my commits on top of `main` and keeps a linear history.
- `git stash` saves unfinished work without committing it.
- The Git history is an audit trail: `git blame` and `git log -S` answer "who changed what, and when".

## Security controls

| Control | Where | What it prevents |
| --- | --- | --- |
| `.gitignore` for `.env`, keys, Terraform state | Repository | Committing secrets by accident |
| gitleaks + private key detection (pre-commit) | Each workstation | Secrets reaching the history |
| SSH commit signing | Each workstation | Commits impersonating the author |
| Ruleset `protect-main` | GitHub | Direct pushes, force pushes, unsigned commits, branch deletion |
| One SSH key and one API key per device | GitHub / AbuseIPDB | A single stolen laptop compromising every device |
| Private IPs never sent to AbuseIPDB | API code | Leaking internal network information to third parties |

## Workflow

1. `git pull` on `main`.
2. Create a branch: `feature/`, `fix/`, `docs/`, `sec/`, `infra/`.
3. Small commits following Conventional Commits.
4. Push, open a PR, review the diff, squash merge.
5. Delete the branch and pull `main` again.

## Evidence

![First PR merged](images/phase-1/01-first-pr-merged.png)
![Verified signed commit](images/phase-1/02-verified-commit.png)
![gitleaks blocking a fake GitHub token](images/phase-1/03-gitleaks-blocked.png)
![Direct push to main rejected by the ruleset](images/phase-1/04-main-protected.png)
![AbuseIPDB enrichment returning a malicious verdict](images/phase-1/05-enrich-malicious.png)
![Rebase conflict](images/phase-1/06-rebase-conflict.png)
![Searching the history with git log -S](images/phase-1/07-history-search.png)

## Problems and solutions

| Problem | Cause | Solution |
| --- | --- | --- |
| `end-of-file-fixer` blocked the commit | Files saved without a final newline | Reviewed the auto-fix with `git diff`, re-staged and committed |
| Hook fixes rolled back ("stashed changes conflicted") | Earlier hook fixes left unstaged | Ran `pre-commit run --all-files`, staged everything, committed again |
| `CRLF will be replaced by LF` warnings | Windows line endings | Configured VS Code to use LF and insert a final newline |
| Work committed on `main` by mistake | Skipped creating the branch | Moved uncommitted work with `git switch -c` before committing |
| `git log --show-signature` showed "No public key" | GitHub signs merge commits with its own GPG key | Expected behavior; imported GitHub's public key to verify locally |
| `protect-main` ruleset missing | Step skipped on day 3 | Created the ruleset with PR, signed commits and no force pushes |
| Multi-line commands broke when pasted in Git Bash | Git Bash paste handling | Ran commands one by one; used `gh pr create --web` for PR bodies |
| Merge conflict in README during rebase | Two branches edited the same line | Combined both changes, `git add`, `git rebase --continue` |

## Decisions

- Conventional Commits for commit messages.
- Squash merge only: one commit per pull request on `main`.
- The whole repository (code, comments, docs) is written in English.
- Private and loopback IPs are never sent to external services.
- Verdict thresholds: ≥75 malicious, ≥25 suspicious (AbuseIPDB confidence score).

## Next phase

Phase 2 — Docker: package the API in a minimal, non-root container image and scan it with Trivy.
