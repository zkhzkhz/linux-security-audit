#!/usr/bin/env python3
"""One-shot container escape risk assessment from the host side.

Combines:
  - docker / podman / nerdctl / crictl inspect
  - live /proc/<pid>/status (CapEff bitmap + real UID — entrypoint may setuid)
  - mount + device + namespace + seccomp/apparmor inspection
  - host kernel version

Produces a final verdict (CRITICAL / HIGH / MEDIUM / OK) plus the concrete
escape path(s) that exist right now, not just a generic finding list.

Usage:
    assess_escape.py <container-id-or-name> [--runtime auto|docker|podman|nerdctl|crictl]
                                            [--json]

Exit code:
    0 — OK or MEDIUM
    1 — HIGH or CRITICAL
    2 — could not inspect
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path

# Linux capability bit positions (lowest bit first)
CAP_NAMES = [
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
]

# Caps that grant or near-grant a one-step escape
DANGEROUS_CAPS = {
    "sys_admin":       "mount fs, cgroupfs writes (release_agent escape)",
    "sys_ptrace":      "ptrace any process — with pid=host: inject host PID 1",
    "sys_module":      "init_module: load attacker-supplied kernel module",
    "dac_read_search": "bypass DAC: read any file regardless of perms/owner",
    "net_admin":       "reconfigure host network if net=host",
    "sys_rawio":       "raw I/O on devices",
    "bpf":             "load BPF programs — kernel R/W via JIT bugs",
    "perfmon":         "perf events — kernel info leak",
    "syslog":          "kernel ring buffer (kptr leak)",
}

SENSITIVE_DEVS = {"/dev/mem", "/dev/kmem", "/dev/sda", "/dev/vda", "/dev/nvme0n1"}


def sh(cmd, timeout=10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def detect_runtime() -> str:
    for rt in ("docker", "nerdctl", "podman", "crictl"):
        if sh(["which", rt]).strip():
            return rt
    return ""


def decode_caps(hex_str: str) -> list:
    try:
        v = int(hex_str, 16)
    except Exception:
        return []
    return [n for i, n in enumerate(CAP_NAMES) if v & (1 << i)]


def read_proc_status(pid: int) -> dict:
    out = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")):
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
            elif line.startswith("Uid:"):
                out["Uid"] = line.split()[1:5]
    except Exception:
        pass
    return out


def classify_mount(src: str):
    s = (src or "").rstrip("/")
    if s == "" or s == "/":
        return ("critical", "host root filesystem mounted")
    if "docker.sock" in s:
        return ("critical", "docker socket — spawn privileged container on host")
    if "containerd.sock" in s or "crio.sock" in s:
        return ("critical", "container runtime socket — exec on host")
    if s == "/proc":
        return ("high", "host /proc mounted in container")
    if s == "/sys" or s.startswith("/sys/fs/cgroup"):
        return ("high", "host /sys or cgroupfs mounted")
    if s == "/etc":
        return ("high", "host /etc mounted")
    if s.startswith("/var/lib/kubelet"):
        return ("high", "kubelet state dir — projected SA tokens, pod credentials")
    if s.startswith("/var/lib/docker") or s.startswith("/var/lib/containerd"):
        return ("high", "container runtime data dir")
    if s.startswith("/var/run/secrets/kubernetes"):
        return ("high", "k8s service account secrets")
    if s.startswith("/dev"):
        return ("high", f"host device path {s}")
    if s == "/root" or s.startswith("/home"):
        return ("medium", f"host user home {s}")
    if s.startswith("/var/log"):
        return ("medium", "host logs")
    return None


def inspect_docker_like(rt, cid):
    raw = sh([rt, "inspect", cid])
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return d[0] if isinstance(d, list) else d
    except Exception:
        return None


def inspect_crictl(cid):
    raw = sh(["crictl", "inspect", cid])
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def collect_from_docker(rt: str, cid: str):
    d = inspect_docker_like(rt, cid)
    if not d:
        return None
    state = d.get("State", {}) or {}
    hc = d.get("HostConfig", {}) or {}
    cfg = d.get("Config", {}) or {}
    sec_opts = hc.get("SecurityOpt") or []
    seccomp_unc = any("seccomp=unconfined" in o or "seccomp:unconfined" in o for o in sec_opts)
    apparmor_unc = any("apparmor=unconfined" in o or "apparmor:unconfined" in o for o in sec_opts)
    return {
        "pid": state.get("Pid"),
        "config_user": (cfg.get("User") or ""),
        "privileged": bool(hc.get("Privileged")),
        "host_ns": {
            "pid": hc.get("PidMode", "") == "host",
            "net": hc.get("NetworkMode", "") == "host",
            "ipc": hc.get("IpcMode", "") == "host",
            "uts": hc.get("UTSMode", "") == "host",
            "user": (hc.get("UsernsMode") or "") == "host",
        },
        "cap_add": [c.upper() for c in (hc.get("CapAdd") or [])],
        "cap_drop": [c.upper() for c in (hc.get("CapDrop") or [])],
        "mounts": [{
            "src": m.get("Source", ""),
            "dst": m.get("Destination", ""),
            "rw": bool(m.get("RW", True)),
        } for m in (d.get("Mounts") or [])],
        "devices": [dev.get("PathOnHost", "") for dev in (hc.get("Devices") or [])],
        "seccomp_unconfined": seccomp_unc,
        "apparmor_unconfined": apparmor_unc,
    }


def collect_from_crictl(cid: str):
    d = inspect_crictl(cid)
    if not d:
        return None
    info = d.get("info", {}) or {}
    rspec = info.get("runtimeSpec", {}) or {}
    process = rspec.get("process", {}) or {}
    linux = rspec.get("linux", {}) or {}
    nslist = {ns.get("type") for ns in (linux.get("namespaces") or [])}
    caps = process.get("capabilities", {}) or {}
    eff_set = caps.get("effective") or []
    return {
        "pid": info.get("pid"),
        "config_user": str((process.get("user") or {}).get("uid", "")),
        "privileged": ("CAP_SYS_ADMIN" in eff_set and len(eff_set) > 30),
        "host_ns": {
            "pid": "pid" not in nslist,
            "net": "network" not in nslist,
            "ipc": "ipc" not in nslist,
            "uts": "uts" not in nslist,
            "user": "user" not in nslist,
        },
        "cap_add": [c.replace("CAP_", "").upper() for c in eff_set],
        "cap_drop": [],
        "mounts": [{
            "src": m.get("source", ""),
            "dst": m.get("destination", ""),
            "rw": "ro" not in (m.get("options") or []),
        } for m in (rspec.get("mounts") or [])],
        "devices": [dev.get("path", "") for dev in (linux.get("devices") or [])],
        "seccomp_unconfined": linux.get("seccomp") is None,
        "apparmor_unconfined": (process.get("apparmorProfile", "") in ("", "unconfined")),
    }


def collect(cid: str, runtime: str):
    if runtime == "auto":
        runtime = detect_runtime() or "docker"
    if runtime in ("docker", "podman", "nerdctl"):
        data = collect_from_docker(runtime, cid)
        if not data and sh(["which", "crictl"]).strip():
            data = collect_from_crictl(cid)
            if data:
                runtime = "crictl"
        return data, runtime
    if runtime == "crictl":
        return collect_from_crictl(cid), runtime
    return None, runtime


def assess(cid: str, runtime: str):
    data, runtime = collect(cid, runtime)
    if not data or data.get("pid") is None:
        return None, runtime, f"failed to inspect container {cid}"

    pid = int(data["pid"])
    proc = read_proc_status(pid)
    cap_eff_hex = proc.get("CapEff", "")
    eff_caps = decode_caps(cap_eff_hex)
    real_uid = (proc.get("Uid") or [""])[0]

    findings = []
    escape_paths = []

    is_root = (real_uid == "0") or (data["config_user"].strip() in ("", "0", "root"))

    # --- findings ---
    if data["privileged"]:
        findings.append(("critical", "privileged-container",
                         "--privileged: full caps + all devices"))

    for c in sorted(set(eff_caps) & DANGEROUS_CAPS.keys()):
        findings.append(("critical", f"cap-{c}", DANGEROUS_CAPS[c]))

    for ns, on in data["host_ns"].items():
        if not on:
            continue
        sev_ns = {"pid":"high","net":"high","ipc":"medium","uts":"low","user":"high"}[ns]
        note_ns = {
            "pid":  "shares host PID ns — sees /proc/1/root → host fs path",
            "net":  "shares host net ns — sniff/spoof host traffic, hit localhost services",
            "ipc":  "shares host SysV shm/sem with host processes",
            "uts":  "shares host hostname namespace",
            "user": "no user namespace remap — UID 0 in container == UID 0 on host",
        }[ns]
        findings.append((sev_ns, f"{ns}-host", note_ns))

    for m in data["mounts"]:
        cls = classify_mount(m["src"])
        if cls:
            sev, note = cls
            findings.append((sev, "sensitive-mount",
                             f"{m['src']} → {m['dst']} ({'rw' if m['rw'] else 'ro'}): {note}"))

    for dev in data["devices"]:
        if dev in SENSITIVE_DEVS or dev.startswith(("/dev/sd", "/dev/vd", "/dev/nvme")):
            findings.append(("critical", "raw-device", f"host block/mem device {dev}"))
        elif dev == "/dev/kmsg":
            findings.append(("medium", "device-kmsg", "kernel ring buffer device"))

    if data["seccomp_unconfined"]:
        findings.append(("high", "no-seccomp",
                         "all syscalls open — kernel CVEs reachable without privilege"))
    if data["apparmor_unconfined"]:
        findings.append(("high", "no-apparmor",
                         "no MAC layer; default profile not enforced"))

    if is_root:
        findings.append(("medium", "root-in-container", "container process runs as UID 0"))

    # --- escape paths (correlated, not just one factor) ---
    cap_set = set(eff_caps)
    host_pid = data["host_ns"]["pid"]
    host_net = data["host_ns"]["net"]

    if data["privileged"] or "ALL" in data["cap_add"] or len(cap_set) > 30:
        escape_paths.append(("critical", "PRIVILEGED",
                             "Full caps + devices: release_agent / sysrq / kmod / raw disk write."))

    if "sys_admin" in cap_set:
        escape_paths.append(("critical", "CAP_SYS_ADMIN",
                             "mount/cgroupfs writes: release_agent + core_pattern escape."))

    if "sys_ptrace" in cap_set and host_pid:
        escape_paths.append(("critical", "PTRACE+PID_HOST",
                             "Inject shellcode into a host process (e.g. systemd) — host root."))

    if "sys_module" in cap_set:
        escape_paths.append(("critical", "CAP_SYS_MODULE",
                             "Load attacker-supplied kernel module — host root."))

    if "dac_read_search" in cap_set:
        escape_paths.append(("critical", "CAP_DAC_READ_SEARCH",
                             "Read every file on host fs regardless of perms (combined with any host mount or /proc/1/root)."))

    if is_root and "dac_override" in cap_set and host_pid:
        escape_paths.append(("critical", "ROOT+DAC_OVERRIDE+PID_HOST",
                             "Read host /etc/shadow, SSH keys, kube admin.conf via /proc/1/root/* — pivot to host root."))

    for m in data["mounts"]:
        s = (m["src"] or "").rstrip("/")
        if s == "" or s == "/":
            escape_paths.append(("critical", "HOST_FS_MOUNT",
                                 f"Host root mounted at {m['dst']} ({'rw' if m['rw'] else 'ro'})."))
        elif "docker.sock" in s or "containerd.sock" in s or "crio.sock" in s:
            escape_paths.append(("critical", "RUNTIME_SOCKET",
                                 f"{s} mounted — spawn privileged container or exec on host."))

    if data["seccomp_unconfined"]:
        escape_paths.append(("high", "NO_SECCOMP_KERNEL_CVE",
                             "io_uring / keyctl / userfaultfd / clone3 / bpf all open — root-1-step via unpatched kernel CVE."))

    if host_net and "net_raw" in cap_set:
        escape_paths.append(("high", "NET_HOST+NET_RAW",
                             "Sniff/spoof all host traffic; reach kubelet, docker API, metrics, local DBs on 127.0.0.1."))

    # --- final verdict ---
    has_crit = any(p[0] == "critical" for p in escape_paths)
    high_count = sum(1 for p in escape_paths if p[0] == "high")
    if has_crit:
        verdict = "CRITICAL"
        note = "One-step escape available. Treat container as host-root-equivalent."
    elif high_count >= 2:
        verdict = "HIGH"
        note = "Multiple isolation layers off; not one-step yet, but app compromise or kernel CVE → likely escape."
    elif high_count >= 1:
        verdict = "MEDIUM"
        note = "Hardening gaps; not directly exploitable without additional CVE."
    else:
        verdict = "OK"
        note = "No major escape vectors detected."

    kernel = sh(["uname", "-r"]).strip()

    return {
        "container": cid,
        "runtime": runtime,
        "pid": pid,
        "uid_real": real_uid,
        "config_user": data["config_user"],
        "kernel": kernel,
        "privileged": data["privileged"],
        "host_namespaces": [k for k, v in data["host_ns"].items() if v],
        "cap_eff_hex": cap_eff_hex,
        "caps_effective": eff_caps,
        "sensitive_mounts": [m for m in data["mounts"] if classify_mount(m["src"])],
        "exposed_devices": [d for d in data["devices"]
                            if d not in ("/dev/null","/dev/zero","/dev/full",
                                         "/dev/random","/dev/urandom","/dev/tty")],
        "seccomp_unconfined": data["seccomp_unconfined"],
        "apparmor_unconfined": data["apparmor_unconfined"],
        "findings": [{"severity": s, "id": i, "note": n} for s, i, n in findings],
        "escape_paths": [{"severity": s, "id": i, "note": n} for s, i, n in escape_paths],
        "verdict": verdict,
        "verdict_note": note,
    }, runtime, None


def render_text(r):
    lines = []
    lines.append(f"Container : {r['container']}  (host PID {r['pid']}, runtime {r['runtime']})")
    lines.append(f"Kernel    : {r['kernel']}")
    lines.append(f"User      : config={r['config_user'] or '(default)'}  real-uid={r['uid_real']}")
    lines.append(f"Host NS   : {', '.join(r['host_namespaces']) or 'none'}")
    lines.append(f"CapEff    : {r['cap_eff_hex']}")
    lines.append(f"            {', '.join(r['caps_effective']) or '(none)'}")
    lines.append(f"Seccomp   : {'UNCONFINED' if r['seccomp_unconfined'] else 'enforced'}")
    lines.append(f"AppArmor  : {'UNCONFINED' if r['apparmor_unconfined'] else 'enforced'}")
    if r['privileged']:
        lines.append("Privileged: YES")
    if r['sensitive_mounts']:
        lines.append("Mounts    :")
        for m in r['sensitive_mounts']:
            lines.append(f"  - {m['src']} → {m['dst']} ({'rw' if m['rw'] else 'ro'})")
    if r['exposed_devices']:
        lines.append(f"Devices   : {', '.join(r['exposed_devices'])}")
    lines.append("")
    lines.append("== Findings ==")
    for f in r['findings']:
        lines.append(f"  [{f['severity'].upper():8}] {f['id']:24}  {f['note']}")
    lines.append("")
    if r['escape_paths']:
        lines.append("== Escape paths ==")
        for p in r['escape_paths']:
            lines.append(f"  [{p['severity'].upper():8}] {p['id']:24}  {p['note']}")
        lines.append("")
    lines.append(f"==> VERDICT: {r['verdict']} — {r['verdict_note']}")
    return "\n".join(lines)


def list_containers(runtime: str):
    """Return list of (id, runtime) for all running containers.

    `runtime=auto` enumerates every CLI present on the box and merges results
    (a single container will only show up under the first runtime that owns it
    — duplicate IDs are filtered)."""
    seen = set()
    out = []
    rts = []
    if runtime == "auto":
        for rt in ("docker", "nerdctl", "podman", "crictl"):
            if sh(["which", rt]).strip():
                rts.append(rt)
    else:
        rts = [runtime]
    for rt in rts:
        if rt in ("docker", "podman", "nerdctl"):
            ids = sh([rt, "ps", "-q", "--no-trunc"]).split()
        else:
            ids = sh(["crictl", "ps", "-q"]).split()
        for cid in ids:
            if cid not in seen:
                seen.add(cid)
                out.append((cid, rt))
    return out


def aggregate(results):
    """Build an LSA-style result.json from a list of per-container reports."""
    findings = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    sev_rank = {"CRITICAL": "critical", "HIGH": "high",
                "MEDIUM": "medium", "OK": "info"}
    worst = "OK"
    rank = {"OK": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for r in results:
        v = r["verdict"]
        if rank[v] > rank[worst]:
            worst = v
        sev = sev_rank[v]
        counts[sev] += 1
        # one finding per container, plus one per escape path so summary.md
        # surfaces concrete vectors not just the verdict
        findings.append({
            "severity": sev,
            "title": f"container-{v.lower()}",
            "where": f"{r['runtime']}:{r['container'][:12]}",
            "note": r["verdict_note"],
        })
        for p in r["escape_paths"]:
            findings.append({
                "severity": p["severity"],
                "title": p["id"],
                "where": f"{r['runtime']}:{r['container'][:12]}",
                "note": p["note"],
            })
            counts[p["severity"]] = counts.get(p["severity"], 0) + 1
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 0), reverse=True)
    status = "warn" if worst in ("HIGH", "CRITICAL") else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in counts.items() if v) or "no findings"
    return {
        "module": "privesc-escape-check.assess_escape",
        "status": status,
        "summary": summary,
        "counts": counts,
        "worst_verdict": worst,
        "containers": results,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description="One-shot container escape risk assessment")
    ap.add_argument("container", nargs="?",
                    help="container id or name (omit if using --all)")
    ap.add_argument("--all", action="store_true",
                    help="assess every running container on this host")
    ap.add_argument("--runtime", default="auto",
                    help="docker|podman|nerdctl|crictl|auto (default auto)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--out", default=None,
                    help="write aggregate JSON to file (implies --json semantics for the file)")
    args = ap.parse_args()

    if args.all and args.container:
        print("error: pass either <container> or --all, not both", file=sys.stderr)
        sys.exit(2)
    if not args.all and not args.container:
        ap.print_usage(sys.stderr)
        sys.exit(2)

    if args.all:
        targets = list_containers(args.runtime)
        if not targets:
            print("no running containers found", file=sys.stderr)
            if args.out:
                Path(args.out).write_text(json.dumps({
                    "module": "privesc-escape-check.assess_escape",
                    "status": "ok", "summary": "no containers",
                    "counts": {}, "worst_verdict": "OK",
                    "containers": [], "findings": [],
                }, indent=2, ensure_ascii=False))
            sys.exit(0)
        results = []
        for cid, rt in targets:
            r, _rt, err = assess(cid, rt)
            if err:
                if not args.json:
                    print(f"[skip {cid[:12]}] {err}", file=sys.stderr)
                continue
            results.append(r)
            if not args.json and not args.out:
                print(render_text(r))
                print("-" * 60)
        agg = aggregate(results)
        if args.out:
            Path(args.out).write_text(json.dumps(agg, indent=2, ensure_ascii=False))
            print(f"assess_escape: wrote {args.out} ({agg['summary']}, worst={agg['worst_verdict']})")
        elif args.json:
            print(json.dumps(agg, indent=2, ensure_ascii=False))
        else:
            print(f"==> overall worst: {agg['worst_verdict']} ({agg['summary']})")
        sys.exit(0 if agg["worst_verdict"] in ("OK", "MEDIUM") else 1)

    # single container path
    r, rt, err = assess(args.container, args.runtime)
    if err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(2)
    if args.out:
        Path(args.out).write_text(json.dumps(aggregate([r]), indent=2, ensure_ascii=False))
        print(f"assess_escape: wrote {args.out} (verdict={r['verdict']})")
    elif args.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print(render_text(r))
    sys.exit(0 if r["verdict"] in ("OK", "MEDIUM") else 1)


if __name__ == "__main__":
    main()
