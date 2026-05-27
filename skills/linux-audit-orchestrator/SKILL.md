---
name: linux-audit-orchestrator
description: This skill should be used when the user asks for a full Linux security audit covering sensitive-info, privesc, container escape, lateral movement, and egress control in one go — or wants to run a curated subset against a host (and any containers it hosts). Triggers on phrases like "full security audit", "全部检查", "扫描这台主机", "audit this Linux box", "scan host and containers", "linux 安全基线". Calls into the four sibling skills, writes a single per-run report directory, and produces summary.md + summary.json via lib/report.py.
version: 1.0.0
---

# Linux Audit Orchestrator

One-stop entry point for the linux-security-audit toolkit. Coordinates:

- `sensitive-info-scan` — gitleaks-based secret hunt with FP triage
- `privesc-escape-check` — host LPE + container escape
- `lateral-movement-scan` — discovery, service scan, credential reuse
- `egress-control-audit` — egress inventory + allowlist proposal

## When to use

- "Run a full audit on this server."
- "Do everything — secrets, privesc, lateral, egress."
- "全部检查这台 Linux 机器和上面的容器"

For a single domain only, prefer the focused skill (`sensitive-info-scan`,
`privesc-escape-check`, `lateral-movement-scan`, `egress-control-audit`).

## Usage

```bash
# Default: all modules, dry-run for any policy changes, host + containers
./scripts/run_all.sh

# Subset
./scripts/run_all.sh --only sensitive-info,privesc

# Host only (skip container enumeration)
./scripts/run_all.sh --no-containers

# Apply egress allowlist after audit (NOT default)
./scripts/run_all.sh --egress-apply
```

## Output

```
reports/<host>-<UTC-timestamp>/
  sensitive-info-scan/
    raw.json result.json scan.log targets.txt
  privesc-escape-check/
    host.json containers/ result.json
  lateral-movement-scan/
    live.txt nmap.* services.json result.json
  egress-control-audit/
    endpoints.json allowlist.suggested.json egress.iptables.rules result.json
  summary.md          <- aggregated, human-friendly
  summary.json
```

## Order of operations

1. `sensitive-info-scan/scripts/scan.sh` — file-system scan, FP triage.
2. `privesc-escape-check/scripts/enter_container.sh` — host privesc + per-container.
3. `lateral-movement-scan/scripts/discover.sh` then `service_scan.sh` then `creds_reuse.sh`.
4. `egress-control-audit/scripts/egress_check.sh` then `suggest_allowlist.sh`.
5. `lib/report.py` aggregates each module's `result.json` into `summary.md` + `summary.json`.

Steps 1-3 can run in parallel; step 4 runs serially (it samples sockets and is
sensitive to load). The orchestrator handles this.

## Safety

- Read-only by default. No firewall rule is applied unless `--egress-apply`
  (host) or `--isolate-apply` (containers) is passed.
- All policy appliers in egress skill keep their own dry-run default and write
  rollback scripts; the orchestrator delegates safety to them.

## Gotchas

- `LSA_RUN_DIR` is exported by the orchestrator so each child writes into the
  same per-run directory tree. Don't override it from the inside.
- If `gitleaks` isn't installed, the orchestrator runs `bin/fetch_tools.sh`
  once before continuing.
- Lateral-movement service scan is gated on a non-empty `live.txt`; with no
  reachable subnets the module produces a warn result and the orchestrator
  moves on.
