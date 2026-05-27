---
name: privesc-escape-check
description: This skill should be used when the user asks to audit a Linux host for local privilege escalation risks, or to inspect a container for breakout / escape risks. Triggers on phrases like "本地提权", "privesc check", "container escape", "容器逃逸", "check SUID", "review sudoers", "check capabilities", "docker socket exposure", or "is this container privileged". Provides three scripts: host_privesc.sh, container_escape.sh, and enter_container.sh (which can use both `docker exec`/`crictl exec`/`nerdctl exec` cp+exec workflows AND `nsenter`-based host-level access).
version: 1.0.0
---

# Privesc & Container Escape Check

Two-pronged audit: local privilege escalation on the host, and container breakout risks. When run from a host that has containers, `enter_container.sh` will scan each container in turn.

## When to use

- "Check this server for privesc paths"
- "Is this container escapable / privileged?"
- "Review SUID / sudoers / cron / capabilities"
- "I have host root, please audit the containers from outside"

## Scripts

### `scripts/host_privesc.sh`

Read-only scan of the host for the usual privesc surfaces. Writes
`reports/.../privesc-escape-check/host.json` and a human log.

What it checks:
- Kernel version + dmesg snippets relevant to known LPE families.
- `find / -perm -4000 -type f` (SUID), `-perm -2000` (SGID), highlighted against
  a known-dangerous list (e.g. `nmap`, `vim.basic`, `find`, `cp`, `tar`, `awk`,
  `python` if SUID, `ar`, `strace`).
- `/etc/sudoers` + `/etc/sudoers.d/*` analysis: NOPASSWD, `ALL=`, dangerous
  commands without password, `env_keep`, `secure_path` issues.
- World-writable files in `$PATH` and writable directories in `$PATH`.
- Cron jobs (system + per-user) with writable scripts or relative paths.
- Systemd unit files writable by non-root, `User=root` units pointing at writable
  binaries.
- File capabilities (`getcap -r /` filtered to dangerous ones).
- `/etc/passwd`/`/etc/shadow`/`/etc/group` permissions, GID 0 / UID 0 anomalies.
- `.ssh` configurations for the current user and root: `authorized_keys`
  contents, command= restrictions, agent forwarding, weak file modes.
- Kernel hardening settings: `kptr_restrict`, `dmesg_restrict`, `unprivileged_userns_clone`,
  `kernel.modules_disabled`, ptrace_scope, core_pattern.
- Active SSH/SUID-net listeners.

### `scripts/container_escape.sh`

Run **inside** the container (or shipped in via `enter_container.sh`). Detects:
- `--privileged` (capabilities = full set, all devices) and individual dangerous
  caps: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`,
  `CAP_NET_ADMIN`, `CAP_SYS_MODULE`.
- AppArmor / SELinux profile: `unconfined` -> alert.
- seccomp mode (`/proc/1/status` `Seccomp:`).
- Mounted host paths: `/`, `/etc`, `/var/run/docker.sock`,
  `/run/containerd/containerd.sock`, `/proc`, `/sys`, `/var/lib/kubelet`,
  any rw bind from outside the container's overlay.
- `/dev/kmsg`, `/dev/disk*`, `/dev/sd*`, `/dev/vd*`, `/dev/mem`, raw devices.
- `cgroupfs` writable (release_agent escape vector).
- Userns + `user_namespaces` config.
- Network mode = host (`/proc/1/net/tcp` matches host listeners).
- PID/IPC mode = host (PID 1 cmdline != container init).
- `kubelet`/`kube-apiserver` reachability + projected service-account token.
- writable `/etc/cron*`, `/etc/sudoers*`, `/etc/passwd`, `/etc/ld.so.preload`.
- presence of build tools (`gcc`, `make`, `nc`, `curl`, `python`) that ease pivoting.

### `scripts/enter_container.sh`

Discovers containers via whichever runtime is present (in priority order):
`docker` → `nerdctl` → `crictl` (containerd) → `podman`. For each container:

1. Tries `docker cp` (or `nerdctl cp` / `crictl cp` if it exists / `podman cp`)
   to drop `container_escape.sh` into `/tmp/.lsa-esc.sh`.
2. Picks the best shell available inside (`bash`, `sh`, `busybox sh`, `dash`).
3. Runs the script with `<runtime> exec` and captures the JSON result back.

It also supports an `nsenter` mode (`--mode nsenter`) that joins the container's
PID namespace from the host without invoking the runtime — useful when the
runtime CLI is broken or absent. nsenter requires host root.

Both modes write per-container JSON into
`reports/.../privesc-escape-check/containers/<id>.json`.

## Usage

```bash
# Audit the host only
./host_privesc.sh

# From inside a container
./container_escape.sh

# From the host: enumerate + audit every container, both modes
./enter_container.sh                  # auto-pick runtime (cp+exec)
./enter_container.sh --mode nsenter   # join namespaces directly
./enter_container.sh --mode both      # try cp+exec first, fall back to nsenter
./enter_container.sh --runtime crictl # force runtime
```

Default invocation uses `cp+exec` first; falls back to `nsenter` if the runtime
cp/exec fails. Pass `--keep` to leave the dropped script in the container for
manual re-runs.

## Output

```
reports/<host>-<ts>/privesc-escape-check/
  host.json                      # host_privesc.sh result
  host.log
  containers/
    <container-id>.json          # one per container
    <container-id>.log
  result.json                    # combined module result for the orchestrator
```

`result.json` shape: aggregates highest-severity findings across host + every
container scanned, sets `status` = warn/error if any critical, lists
`findings` with `where: <host>|<container-id>:<source>` so the orchestrator can
render a single table.

## Gotchas

- `getcap` not available everywhere; falls back to `find / -xdev -exec getcap {} +`
  if needed, otherwise emits a `notes` entry that capability detection was
  skipped.
- Some minimal containers have no shell at all (distroless). In that case
  `enter_container.sh` reports `unscannable: distroless` with whatever can be
  inferred from the runtime config alone (`docker inspect` etc.).
- Read-only by design — these scripts never write to the host or container,
  except for the temp script in `/tmp`. Pass `--keep` if you want it kept.
