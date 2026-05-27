# Container escape vectors quick reference

A short cheat-sheet for what the scripts look for and why each is dangerous.

## Privileged / Capability based

| Vector | What it allows | Detection |
|---|---|---|
| `--privileged` | All caps, all devices, no AppArmor — full host compromise | `CapEff` ≈ `0x3fffffffff`, all of `/dev/*` exposed |
| `CAP_SYS_ADMIN` | Mount, kexec, namespace-ish, many syscalls | bit 21 of `CapEff` |
| `CAP_SYS_PTRACE` | Attach to any host PID if PID ns is shared | bit 19 |
| `CAP_SYS_MODULE` | Load arbitrary kernel modules | bit 16 |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at()` -> read host fs (Shocker) | bit 2 |
| `CAP_NET_ADMIN` | Manipulate routing/iptables of host net | bit 12 |

## Mounted host resources

| Mount | Risk |
|---|---|
| `/var/run/docker.sock` | Trivial host root via `docker run -v / --privileged` from inside |
| `/run/containerd/containerd.sock` | Equivalent for containerd |
| `/host` or `/` bind mount | Direct file-level access to host fs |
| Host `/proc` | `/proc/1/root/` -> host fs walk |
| Host `/etc` rw | Replace `passwd`/`shadow`/cron files |
| `/sys/fs/cgroup` rw + writable `release_agent` | Notify-on-release escape — pre-cgroup-v2 |
| `/dev/disk` / `/dev/sda` / raw block devices | Read host fs by reading the block device |

## Namespace sharing

| Mode | Sign |
|---|---|
| `--pid=host` | `/proc/1/cmdline` is the host init (`systemd`, `init`) |
| `--net=host` | `/proc/1/net/tcp` lists host listeners; same `net` ns inode as PID 1 outside |
| `--ipc=host` | shared IPC with host (low-risk on its own, but combines well) |

## LSM bypasses

| Sign | Risk |
|---|---|
| `Seccomp: 0` in `/proc/1/status` | All syscalls allowed |
| `unconfined` in `/proc/self/attr/current` | AppArmor profile not enforced |

## Kubernetes specifics

- Mounted SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token` — even if
  the container itself is locked down, an over-permissioned SA can mean cluster-wide
  takeover.
- `kubelet`/`kube-apiserver` reachable from the container.
- HostPath PV pointing at sensitive host paths.

## What each script does

- `container_escape.sh`: collects above signals, scores severity, writes `esc.json`.
- `host_privesc.sh`: SUID, sudoers, cron, capabilities, kernel hardening on the host.
- `enter_container.sh`: enumerates containers from the host and runs
  `container_escape.sh` either via `docker cp + exec` (or equivalent for nerdctl /
  crictl / podman) or via `nsenter` joining the container PID namespace.

## Useful one-liners (manual follow-up)

```bash
# All caps for current process
grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status

# All container PIDs from the host
for c in $(docker ps -q); do echo "$c $(docker inspect -f '{{.State.Pid}}' "$c")"; done

# Detect PID ns sharing with host
test "$(readlink /proc/1/ns/pid)" = "$(readlink /proc/$$/ns/pid)" && echo "shared"

# release_agent escape probe (read-only, just checks writability)
mount | grep cgroup
test -w /sys/fs/cgroup/release_agent && echo "WRITABLE release_agent"
```
