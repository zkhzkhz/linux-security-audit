---
name: sensitive-info-scan
description: This skill should be used when the user asks to scan a Linux host or container for hardcoded secrets, credentials, API keys, private keys, or any sensitive data leakage. Triggered by phrases like "scan for secrets", "find leaked credentials", "敏感信息扫描", "gitleaks", "check for hardcoded passwords", or when auditing /etc /home /opt /var/log or container images. Uses gitleaks (with archive support enabled), aggressive directory exclusions for large/virtual filesystems, parallel scanning, and a built-in false-positive triage that filters placeholders, low-entropy hits, and example values.
version: 1.0.0
---

# Sensitive Info Scan

Detects hardcoded secrets on Linux hosts and inside containers using gitleaks, with optimization for large filesystems and a false-positive triage step.

## When to use

- User asks to find hardcoded credentials / API keys / private keys / tokens / DB strings.
- Auditing `/etc`, `/home`, `/opt`, `/root`, `/var/log`, application directories, or container filesystems.
- Need to scan tarballs, zip files, jars, or other archives shipped on the host.

## How to invoke

The script is at `<project>/skills/sensitive-info-scan/scripts/scan.sh`.

```bash
# Default: scan a curated host target list, archive support on, exclude big/virtual dirs
./scan.sh

# Specific directories / files / archives
./scan.sh /etc /opt/myapp /var/backups/dump.tar.gz

# Tune
./scan.sh --max-file-size 20M --jobs 4 --max-archive-depth 3 /opt
```

After scanning, results are auto-triaged:

```bash
./triage.py <run_dir>/raw.json
```

`scan.sh` already calls `triage.py` and writes both `raw.json` (gitleaks output) and
`result.json` (triaged, severity-ranked) into the per-run report directory.

## Scanning strategy

1. **Targets** (`scripts/targets.sh`): default host list is `/etc /home /opt /root /srv /var/log /var/spool /tmp /usr/local`. Skip `/proc /sys /dev /run` and well-known caches/overlays.
2. **Exclusions** (`config/exclude-paths.txt`): regex of dirs gitleaks must not enter — overlay2, containerd, snap, journal, node_modules, .git/objects, vendored deps, browser caches.
3. **Rules** (`config/gitleaks-custom.toml`): merged set of cloud-provider keys, generic API keys, JWT, private keys, DB URLs, git-URL credentials, generic password assignments. Reference rules from the user's `gitleaks.toml` are inlined as-is. Allowlist trims classic test/example values.
4. **Archives**: gitleaks v8.18+ supports `--scan-archives` (zip, tar, tgz, gz, jar, war, ear, apk). Default depth `2`; raise with `--max-archive-depth`.
5. **Per-file size cap**: `--max-target-megabytes` keeps the scanner from chewing on multi-GB log files. Default 10 MB; raise on demand.
6. **Parallelism**: `scan.sh` partitions the target list and runs N gitleaks workers (default `min(nproc/2, 4)`) merging JSONs at the end.
7. **Container mode**: when `LSA_CONTAINER=1`, scope is restricted to typical app dirs and adjusts to whatever shell exists in the container.

## False-positive triage (`triage.py`)

For each gitleaks finding it computes:
- **Placeholder filter**: known dummy values (`AKIAIOSFODNN7EXAMPLE`, `password = changeme`, `xxxx`, `<your-token>`, `example.com`, repeated-character strings).
- **Entropy**: Shannon entropy of the secret; below per-rule floor → `low`.
- **Context boost**: presence of `prod`, `live`, `secret`, neighbouring filename hints (`*.env`, `id_rsa`, `credentials`).
- **File-type weight**: `.md/.txt/test*` halves severity; `.env/.pem/credentials*` doubles it.
- **Rule weight**: private keys / cloud keys score higher than generic password regex.
- **De-duplication**: same `(rule, secret-prefix, file)` collapsed.

Final severity ∈ {critical, high, medium, low, info}, written to `result.json` with the gitleaks original line/column for review.

## Output

```
reports/<host>-<ts>/sensitive-info-scan/
  raw.json          # raw gitleaks output (all findings)
  result.json       # triaged, severity-tagged, dedup
  scan.log          # stderr capture
  targets.txt       # targets actually scanned
```

## Gotchas

- gitleaks `--no-git` is required for filesystem scans; `scan.sh` sets it.
- Archive scanning costs CPU + temp disk; set `--max-archive-depth 1` on tight hosts.
- If gitleaks isn't on PATH, run `<project>/bin/fetch_tools.sh` to install the static binary.
- `result.json` is the canonical output; the orchestrator reads only this.
