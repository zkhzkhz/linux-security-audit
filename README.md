# linux-security-audit

A Claude Code skill set for auditing **Linux** and **Windows** hosts (plus the
containers they run). Four core risk areas, each as a focused skill, with a
one-shot orchestrator per OS and an AI-powered report analyzer.

```
linux-security-audit/
├── skills/
│   ├── linux-audit-orchestrator/      # one-shot full Linux audit
│   ├── sensitive-info-scan/           # gitleaks + trufflehog + FP triage
│   ├── privesc-escape-check/          # host LPE + container escape (linpeas/les/cdk/deepce/amicontained/peirates/trivy/kube-bench)
│   ├── lateral-movement-scan/         # nmap discovery/service + creds reuse + ssh-audit
│   ├── egress-control-audit/          # outbound + inter-container isolation + docker-bench
│   ├── audit-report-analyzer/         # AI-powered analysis of a finished report archive
│   ├── windows-audit-orchestrator/    # Windows full audit
│   ├── windows-privesc-check/         # WinPEAS / Seatbelt / SharpUp / Watson
│   ├── windows-sensitive-scan/        # gitleaks for Windows hosts
│   ├── windows-lateral-movement/      # SMB / WinRM / RDP discovery + creds
│   └── windows-egress-control/        # Windows Firewall egress audit
├── lib/                               # shared helpers + report generators
├── bin/                               # static tool binaries + fetchers
├── reports/                           # per-run output (created on demand)
└── .claude-plugin/plugin.json         # makes skills discoverable
```

Linux supports both **x86_64** and **aarch64**. Container engines auto-detected
in priority order: `docker`, `nerdctl`, `crictl` (containerd), `podman`. Container
audits run via `docker cp + exec` (or equivalent) by default and via `nsenter`
when the runtime CLI is broken/absent.

## Quick start (Linux)

```bash
# Fetch static binaries for the current arch
bash bin/fetch_tools.sh                  # gitleaks + trivy + amicontained
# (or one tool at a time: bash bin/fetch_tools.sh gitleaks)

# Full audit (dry-run for any policy actions)
bash skills/linux-audit-orchestrator/scripts/run_all.sh

# Aggregated report
cat reports/<host>-<ts>/summary.md
```

### `run_all.sh` flags

| Flag | Effect |
|---|---|
| `--only sensitive-info,privesc` | run a subset of modules |
| `--no-containers` | skip container privesc/escape + container creds scans |
| `--full` | aggressive nmap (`-sV -sC`) on lateral scan |
| `--container <name>` / `--container-id <id>` | scope container scans to one target |
| `--runtime docker\|crictl\|nerdctl\|podman` | pin a container runtime |
| `--egress-apply` | actually install host egress allowlist (default = dry-run) |
| `--isolate-apply` | install DOCKER-USER inter-container policy (default = dry-run) |

All "apply" steps write a backup + `rollback.sh` first.

### Ad-hoc / lightweight usages (Linux)

When you don't need a full audit, the following one-shot scripts are useful:

```bash
# Host-side quick container security overview (privileged, caps, mounts, net mode)
bash bin/quick_container_check.sh

# Lightweight gitleaks scan — pick scope on the fly
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target history
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target env
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target proc-env          # all processes
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target proc-env:1234     # single PID
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target /etc,/opt/myapp   # dirs
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target all               # combined
bash skills/sensitive-info-scan/scripts/scan_lightweight.sh --target history,env,/etc  # mix

# Single-target gitleaks (raw scan.sh, no triage)
bash skills/sensitive-info-scan/scripts/scan.sh --no-triage /opt/myapp

# Container escape check from inside a container
bash skills/privesc-escape-check/scripts/container_escape.sh

# Host-side enter into a specific container only
bash skills/privesc-escape-check/scripts/enter_container.sh \
  --mode host --runtime docker --container myapp

# Lateral discovery on custom subnets
bash skills/lateral-movement-scan/scripts/discover.sh 10.0.0.0/24 192.168.10.0/24

# Egress sample only (no allowlist proposal, no apply)
bash skills/egress-control-audit/scripts/egress_check.sh

# Pre-bundle every tool for every supported arch (release helper)
bash bin/fetch_all_platforms.sh
```

## Quick start (Windows)

```powershell
# Fetch Windows tools (winpeas, seatbelt, sharpup, watson, gitleaks, trivy)
.\bin\fetch_windows_tools.ps1

# Full audit
.\skills\windows-audit-orchestrator\scripts\run_all.ps1

# Subset / custom output / timeout
.\skills\windows-audit-orchestrator\scripts\run_all.ps1 -Only privesc
.\skills\windows-audit-orchestrator\scripts\run_all.ps1 -Output C:\audit -Timeout 900
```

### Per-module Windows usages

```powershell
# Privilege escalation: all tools or pick a subset
.\skills\windows-privesc-check\scripts\run.ps1
.\skills\windows-privesc-check\scripts\run.ps1 -Tools winpeas,watson -Timeout 300

# Sensitive info: default paths or custom targets
.\skills\windows-sensitive-scan\scripts\scan.ps1
.\skills\windows-sensitive-scan\scripts\scan.ps1 -Targets C:\Users,C:\Projects -Jobs 2
.\skills\windows-sensitive-scan\scripts\scan.ps1 -NoTriage

# Lateral movement (SMB / WinRM / RDP discovery + cached creds + sessions)
.\skills\windows-lateral-movement\scripts\scan.ps1 -Output C:\audit

# Egress: firewall outbound rules + proxy + DNS + isolation
.\skills\windows-egress-control\scripts\audit.ps1 -Output C:\audit
```

## Skill details

### 1. sensitive-info-scan

Two scanners in parallel, with FP triage:

- **gitleaks** (`scan.sh`) — custom rule set merging cloud-provider keys, JWT,
  kubeconfig, shadow-hash, htpasswd, etc. with the user's reference rules.
  Path exclusions for overlay2, containerd, node_modules, browser caches, …
  Per-file size cap, parallel partitioned scans, archive scanning
  (zip/tar/jar) with bounded depth.
- **trufflehog** (`run_trufflehog.sh`) — verified-secrets engine, runs in
  parallel with gitleaks.
- **scan_containers.sh** — repeats the gitleaks scan against each container
  filesystem (skipped under `--no-containers`).
- **triage.py** — scores findings by rule weight + entropy + path-context
  boosts + nearby keywords; flags placeholders/example values; deduplicates;
  emits `result.json` ranked by severity.

### 2. privesc-escape-check

Host enumeration + per-container escape probes, plus a battery of established
community tools:

| Script | Tool |
|---|---|
| `host_privesc.sh` | built-in checks: kernel, SUID/SGID, sudoers, cron, systemd, file caps, sysctls, passwd/shadow |
| `enter_container.sh` + `container_escape.sh` | privileged caps, seccomp, AppArmor, host mounts, devices, cgroup release_agent, kube SA token |
| `run_les.sh` | linux-exploit-suggester |
| `run_cdk.sh` | CDK container-escape detector |
| `run_deepce.sh` | DeepCE container security checks |
| `run_amicontained.sh` | amicontained introspection |
| `run_peirates.sh` | Kubernetes privilege-escalation finder |
| `run_trivy.sh` | image / filesystem CVE scanning |
| `run_kube_bench.sh` | CIS Kubernetes benchmark |

Each tool has a `parse_*.py` companion that normalizes its output into the
common `findings + counts` schema; results merge into one `result.json`.

### 3. lateral-movement-scan

- `discover.sh` derives subnets from the routing table (skipping /8 /12); does
  ARP + ICMP + TCP-SYN top-50 fallback.
- `service_scan.sh` runs nmap top-300 plus a curated high-port list (kubelet,
  etcd, docker daemon, ZK, ES/Kibana, Mongo, Redis, MQ, Vault, Consul, Hadoop,
  registries…). `--full` adds `-sV -sC`.
- `creds_reuse.sh` enumerates SSH keys (encrypted vs not), `~/.aws/credentials`,
  `~/.kube/config`, `~/.docker/config.json`, netrc, git-credentials.
- `scan_containers_creds.sh` repeats the credential sweep inside each container.
- `run_ssh_audit.sh` / `parse_ssh_audit.py` audit reachable SSH endpoints for
  weak algorithms / config.

### 4. egress-control-audit

- `egress_check.sh` (read-only): routes, DNS log scrape, established sockets,
  iptables-save / nft list ruleset, container peers; writes `endpoints.json`.
- `suggest_allowlist.sh`: derives a per-(addr,port,proto) allowlist using a
  count threshold; emits `allowlist.suggested.json` and an
  `egress.iptables.rules` drop-in.
- `verify_isolation.sh`: probes whether containers can reach each other and
  reports violations of declared isolation.
- `run_docker_bench.sh` + `parse_docker_bench.py`: Docker CIS Benchmark.
- `apply_egress_iptables.sh`: dry-run by default; `--apply` runs the rules
  with backup + `rollback.sh`; refuses `--policy drop` if your SSH source
  isn't in the allowlist.
- `apply_container_isolation.sh`: dry-run by default; `--apply` adds a
  DOCKER-USER policy that drops bridge-to-bridge except declared pairs.

### 5. audit-report-analyzer

Post-processes a finished report archive (`.tar.gz` / `.tar.zip` / `.zip`) and
generates AI-powered evidence reports.

```bash
# Default — auto-extract, code analysis + AI deep dive
bash skills/audit-report-analyzer/scripts/run.sh --archive /path/to/report.tar.gz

# Custom output directory
bash skills/audit-report-analyzer/scripts/run.sh --archive /path/to/report.tar.gz --output /custom/out

# Code-only, skip AI
bash skills/audit-report-analyzer/scripts/run.sh --archive /path/to/report.tar.gz --no-ai
```

Reads evidence from LinPEAS, gitleaks, TruffleHog, CDK, DeepCE, Peirates,
kube-bench, amicontained.

Outputs:

| File | Description |
|---|---|
| `detailed-audit-evidence.md` | Complete evidence report with raw scanner output |
| `kernel-vulnerability-analysis.md` | Kernel CVE analysis with remediation |
| `detailed-audit-findings.xlsx` | Excel report with FP detection |
| `ai-analysis-report.md` | AI-powered deep analysis and recommendations |
| `audit-summary.json` | JSON summary for automation |

### 6. Windows skills

`windows-audit-orchestrator/scripts/run_all.ps1` calls the four Windows
modules:

- `windows-privesc-check` — WinPEAS, Seatbelt, SharpUp, Watson; each tool
  also runnable individually via `-Tools winpeas,watson` etc.
- `windows-sensitive-scan` — gitleaks + TruffleHog against `C:\Users`,
  `C:\inetpub`, `C:\ProgramData` (configurable via `-Targets`), with FP triage.
- `windows-lateral-movement` — SMB / WinRM / RDP discovery, cached creds,
  Kerberos tickets, domain-trust + local-admin membership, active sessions.
- `windows-egress-control` — Windows Firewall outbound rules, system / IE
  proxy, DNS servers, network isolation state.

Outputs land in `reports\<hostname>-<timestamp>\` mirroring the Linux layout:
each module writes `result.json` + `*.log`, and the orchestrator aggregates
into `summary.json` + `summary.md`.

PowerShell 5.1+ recommended; administrator privileges preferred (some checks
silently skip without them).

## Reports

Every Linux run produces:

```
reports/<host>-<ts>/
  sensitive-info-scan/           result.json + raw.json + per-target gitleaks output
  sensitive-info-scan-trufflehog/result.json
  sensitive-info-scan-containers/result.json
  privesc-escape-check/          host.json + containers/ + les/ cdk/ deepce/ amicontained/ peirates/ trivy/ kube-bench/
  lateral-movement-scan/         live.txt + nmap.* + services.json + creds.json + ssh-audit/
  egress-control-audit/          endpoints.json + allowlist.suggested.json + egress.iptables.rules + isolation/ + docker-bench/
  <module>/report.md             per-module human report (from gen_module_report.py)
  summary.md                     aggregated, human-friendly (from report.py)
  summary.json                   machine-readable
```

`summary.md` has a per-module table + top findings. Re-run
`python3 lib/report.py reports/<host>-<ts>/` to refresh after manual edits, or
`python3 lib/gen_module_report.py reports/<host>-<ts>/` to regenerate the
per-module markdowns.

Additional report generators in `lib/`:

- `generate_detailed_report.py` — long-form evidence Markdown
- `generate_evidence_report.py` — finding-by-finding evidence dump
- `generate_excel_report.py` / `webexcel.py` — XLSX output

## Tooling

`bin/fetch_tools.sh` downloads (and decompresses bundled `.gz` copies of):

- `gitleaks` (v8.21.2, linux/amd64 + linux/arm64)
- `trivy` (v0.71.0)
- `amicontained` (v0.4.9)

Other tools shipped in `bin/` directly: `linpeas.sh`,
`linux-exploit-suggester.sh`, `cdk-linux-{amd64,arm64}`, `deepce.sh`,
`peirates-linux-{amd64,arm64}`, `kube-bench-linux-{amd64,arm64}`,
`docker-bench-security`, `trufflehog-linux-{amd64,arm64}`, `ssh-audit-bin`.

`bin/fetch_all_platforms.sh` fetches every supported arch in one go;
`bin/fetch_windows_tools.ps1` fetches the Windows toolchain.

`nmap` is expected on PATH (warn-not-fail). `python3` and `bash` are required.

## Safety summary

- **Read-only by default.** No firewall rule, file edit, or container command
  runs unless `--apply` is passed (or for the orchestrator, `--egress-apply`
  / `--isolate-apply`).
- Every apply step writes a `rollback.sh` and a backup of the prior state
  into the run directory before changing anything.
- The egress applier refuses `--policy drop` when your SSH source isn't in
  the allowlist.
