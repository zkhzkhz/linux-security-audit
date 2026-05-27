# linux-security-audit

A Claude Code skill set for auditing Linux hosts and the containers they run.
Covers four risk areas, each as a focused skill, plus a one-shot orchestrator.

```
linux-security-audit/
├── skills/
│   ├── linux-audit-orchestrator/      # one-shot full audit
│   ├── sensitive-info-scan/           # gitleaks + FP triage
│   ├── privesc-escape-check/          # host LPE + container breakout
│   ├── lateral-movement-scan/         # nmap discovery/service + creds reuse
│   └── egress-control-audit/          # outbound + inter-container isolation
├── lib/                               # shared helpers (logging, arch, report)
├── bin/                               # tool fetcher, gitleaks static binary slot
├── reports/                           # per-run output (created on demand)
└── .claude-plugin/plugin.json         # so the skills are discoverable
```

Supports both **x86_64** and **aarch64** Linux. Container engines auto-detected
in priority order: `docker`, `nerdctl`, `crictl` (containerd), `podman`. From
the host, container audits run via `docker cp + exec` (or equivalent) by default
and via `nsenter` when the runtime CLI is broken/absent — both can be enabled at
once with `--mode both`.

## Quick start

```bash
# Install the static gitleaks binary for this arch (skip if it's already on PATH)
bash bin/fetch_tools.sh gitleaks

# Full audit, dry-run for any policy actions
bash skills/linux-audit-orchestrator/scripts/run_all.sh

# Look at the aggregated report
cat reports/<host>-<ts>/summary.md
```

`run_all.sh` flags:

| Flag | Effect |
|---|---|
| `--only sensitive-info,privesc` | run a subset of modules |
| `--no-containers` | skip per-container privesc/escape checks |
| `--full` | aggressive nmap (`-sV -sC`) on lateral scan |
| `--egress-apply` | actually install egress allowlist (default = dry-run) |
| `--isolate-apply` | install DOCKER-USER inter-container policy (default = dry-run) |

All "apply" actions write a backup + `rollback.sh` first.

## Skill details

### 1. sensitive-info-scan

Optimized gitleaks scan with FP triage.

- Custom rule set (`config/gitleaks-custom.toml`) merging the user's reference
  rules from `https://github.com/zkhzkhz/GoDemo/blob/master/gitleaks.toml` plus
  cloud-provider keys, JWT, kubeconfig, shadow-hash, htpasswd, etc.
- Path exclusions in `config/exclude-paths.txt` (overlay2, containerd,
  node_modules, browser caches, etc.).
- Per-file size cap, parallel partitioned scans, archive scanning enabled
  (zip/tar/jar) with bounded depth.
- `triage.py` scores each finding by rule weight + entropy + path-context boosts/
  penalties + nearby keywords; flags placeholders/example values; deduplicates;
  emits `result.json` ranked by severity.

### 2. privesc-escape-check

Two readers + an enumerator:

- `host_privesc.sh` — kernel ver, SUID/SGID, sudoers (NOPASSWD), writable PATH
  dirs, cron, systemd unit writability, file capabilities, kernel-hardening
  sysctls, /etc/passwd /etc/shadow checks.
- `container_escape.sh` — runs **inside** a container; checks privileged caps
  (CapEff bitmap), seccomp, AppArmor, mounted host sockets/paths, raw devices,
  cgroup release_agent writability, namespace sharing, kube SA token.
- `enter_container.sh` — host-side enumerator; for each container drops the
  escape script via `cp + exec` and/or joins namespaces with `nsenter` (root
  required), then aggregates host + per-container results.

### 3. lateral-movement-scan

- `discover.sh` derives subnets from the routing table (skipping /8 /12); does
  ARP + ICMP + TCP-SYN top-50 fallback to find live neighbours.
- `service_scan.sh` runs nmap top-300 plus a curated high-port list (kubelet,
  etcd, docker daemon, ZK, ES/Kibana, Mongo, Redis, MQ, Vault, Consul,
  Hadoop, registries...). `--full` adds `-sV -sC`.
- `creds_reuse.sh` enumerates SSH keys (encrypted vs not), `~/.aws/credentials`,
  `~/.kube/config`, `~/.docker/config.json`, netrc, git-credentials — anything
  that might reuse against the targets in `live.txt`.

### 4. egress-control-audit

- `egress_check.sh` (read-only): routes, DNS log scrape, established sockets,
  iptables-save / nft list ruleset, container peers; writes
  `endpoints.json`.
- `suggest_allowlist.sh`: derives a per-(addr,port,proto) allowlist using a
  count threshold; produces `allowlist.suggested.json` and an
  `egress.iptables.rules` drop-in.
- `apply_egress_iptables.sh`: dry-run by default; `--apply` runs the rules,
  with backup + rollback.sh; refuses `--policy drop` if your SSH source isn't
  in the allowlist.
- `apply_container_isolation.sh`: dry-run by default; `--apply` adds a
  DOCKER-USER policy that drops bridge-to-bridge except declared pairs.

## Reports

Every run produces:

```
reports/<host>-<ts>/
  sensitive-info-scan/result.json      # triaged secrets
  privesc-escape-check/result.json     # host + per-container findings
  lateral-movement-scan/result.json    # nmap + creds
  egress-control-audit/result.json     # endpoints + suggested allowlist
  summary.md                            # human-readable
  summary.json                          # machine-readable
```

`summary.md` has a per-module table + the top 20 findings per module. Re-run
`python3 lib/report.py reports/<host>-<ts>/` to refresh after manual edits.

## Tooling

- `gitleaks` — static binary fetcher in `bin/fetch_tools.sh` (downloads the
  matching arch from the official GitHub release into `bin/gitleaks-linux-<arch>`).
- `nmap` — expected on PATH; the toolkit will warn but not fail without it.
- Both `python3` and `bash` are required.

## Safety summary

- Read-only by default. **No firewall rule, no file edit, no container
  command** runs unless you explicitly pass `--apply` (or for the orchestrator,
  `--egress-apply` / `--isolate-apply`).
- Every apply step writes a `rollback.sh` and a backup of the prior state into
  the run directory before changing anything.
- The egress applier refuses `--policy drop` when your SSH source isn't in the
  allowlist.
