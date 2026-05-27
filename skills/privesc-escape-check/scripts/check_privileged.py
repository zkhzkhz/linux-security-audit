#!/usr/bin/env python3
"""Host-side privileged container detection.

Supports:
  - Docker / Podman / nerdctl (via `docker inspect`)
  - crictl (containerd/CRI-O inspect JSON)
  - kubectl (pod spec securityContext)

Outputs findings JSON to stdout or --out file.
"""
import json
import subprocess
import sys
import argparse
from pathlib import Path


def run(cmd: list[str], timeout=10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def check_docker_inspect(rt: str, container_id: str, label: str) -> list[dict]:
    """Check via docker/podman/nerdctl inspect."""
    raw = run([rt, "inspect", container_id])
    if not raw:
        return []
    try:
        d = json.loads(raw)
        if isinstance(d, list):
            d = d[0]
    except Exception:
        return []

    findings = []
    hc = d.get("HostConfig") or {}

    if hc.get("Privileged"):
        findings.append({"severity": "critical", "title": "privileged-container",
                         "where": f"{label}:hostconfig",
                         "note": "--privileged=true (full host access)"})

    pid_mode = hc.get("PidMode", "")
    if pid_mode == "host":
        findings.append({"severity": "high", "title": "pid-host-mode",
                         "where": f"{label}:hostconfig",
                         "note": "--pid=host (can see/ptrace host processes)"})

    net_mode = hc.get("NetworkMode", "")
    if net_mode == "host":
        findings.append({"severity": "high", "title": "net-host-mode",
                         "where": f"{label}:hostconfig",
                         "note": "--net=host (shares host network stack)"})

    ipc_mode = hc.get("IpcMode", "")
    if ipc_mode == "host":
        findings.append({"severity": "medium", "title": "ipc-host-mode",
                         "where": f"{label}:hostconfig",
                         "note": "--ipc=host (shared memory access)"})

    cap_add = hc.get("CapAdd") or []
    dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                      "DAC_READ_SEARCH", "NET_ADMIN", "ALL"}
    added = set(c.upper() for c in cap_add) & dangerous_caps
    if "ALL" in added:
        findings.append({"severity": "critical", "title": "cap-add-all",
                         "where": f"{label}:hostconfig",
                         "note": "--cap-add=ALL (equivalent to privileged)"})
    elif added:
        for c in sorted(added):
            findings.append({"severity": "high", "title": f"cap-add-{c.lower()}",
                             "where": f"{label}:hostconfig",
                             "note": f"--cap-add={c}"})

    sec_opt = hc.get("SecurityOpt") or []
    for opt in sec_opt:
        if "apparmor=unconfined" in opt or "apparmor:unconfined" in opt:
            findings.append({"severity": "high", "title": "apparmor-disabled",
                             "where": f"{label}:hostconfig",
                             "note": "AppArmor explicitly disabled"})
        if "seccomp=unconfined" in opt or "seccomp:unconfined" in opt:
            findings.append({"severity": "high", "title": "seccomp-disabled",
                             "where": f"{label}:hostconfig",
                             "note": "Seccomp explicitly disabled"})

    devices = hc.get("Devices") or []
    for dev in devices:
        path = dev.get("PathOnHost", "")
        if path in ("/dev/mem", "/dev/kmem", "/dev/sda", "/dev/vda", "/dev/nvme0n1"):
            findings.append({"severity": "critical", "title": "raw-device-mapped",
                             "where": f"{label}:{path}",
                             "note": f"host device {path} mapped into container"})

    return findings


def check_crictl_inspect(container_id: str, label: str) -> list[dict]:
    """Check via crictl inspect (containerd/CRI-O)."""
    raw = run(["crictl", "inspect", container_id])
    if not raw:
        return []
    try:
        d = json.loads(raw)
    except Exception:
        return []

    findings = []
    info = d.get("info", {})
    config = info.get("config", {}) or d.get("status", {}).get("config", {}) or {}

    # Runtime spec — OCI level
    runtime_spec = info.get("runtimeSpec", {})
    process = runtime_spec.get("process", {})
    caps = process.get("capabilities", {})
    eff_caps = set(caps.get("effective", []) + caps.get("bounding", []))

    if "CAP_SYS_ADMIN" in eff_caps and len(eff_caps) > 30:
        findings.append({"severity": "critical", "title": "privileged-container",
                         "where": f"{label}:crictl",
                         "note": "full capabilities detected (privileged)"})
    elif "CAP_SYS_ADMIN" in eff_caps:
        findings.append({"severity": "critical", "title": "cap-sys-admin",
                         "where": f"{label}:crictl",
                         "note": "CAP_SYS_ADMIN in effective caps"})

    # Linux namespaces
    linux = runtime_spec.get("linux", {})
    namespaces = {ns.get("type"): ns for ns in linux.get("namespaces", [])}

    if "pid" not in namespaces:
        findings.append({"severity": "high", "title": "pid-host-mode",
                         "where": f"{label}:crictl",
                         "note": "no PID namespace (host PID)"})
    if "network" not in namespaces:
        findings.append({"severity": "high", "title": "net-host-mode",
                         "where": f"{label}:crictl",
                         "note": "no network namespace (host network)"})
    if "ipc" not in namespaces:
        findings.append({"severity": "medium", "title": "ipc-host-mode",
                         "where": f"{label}:crictl",
                         "note": "no IPC namespace (host IPC)"})

    # Devices
    devices = linux.get("devices", [])
    for dev in devices:
        path = dev.get("path", "")
        if path in ("/dev/mem", "/dev/kmem", "/dev/sda", "/dev/vda", "/dev/nvme0n1"):
            findings.append({"severity": "critical", "title": "raw-device-mapped",
                             "where": f"{label}:{path}",
                             "note": f"device {path} in container"})

    # Seccomp
    seccomp = linux.get("seccomp")
    if seccomp is None:
        findings.append({"severity": "high", "title": "seccomp-disabled",
                         "where": f"{label}:crictl",
                         "note": "no seccomp profile"})

    # AppArmor
    apparmor = process.get("apparmorProfile", "")
    if apparmor == "unconfined" or apparmor == "":
        findings.append({"severity": "high", "title": "apparmor-unconfined",
                         "where": f"{label}:crictl",
                         "note": f"AppArmor profile: {apparmor or 'none'}"})

    return findings


def check_kubectl() -> list[dict]:
    """Check all pods via kubectl for privileged securityContext."""
    raw = run(["kubectl", "get", "pods", "--all-namespaces", "-o", "json"], timeout=15)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []

    findings = []
    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        ns = meta.get("namespace", "")
        pod_name = meta.get("name", "")
        spec = pod.get("spec", {})

        if spec.get("hostPID"):
            findings.append({"severity": "high", "title": "pid-host-mode",
                             "where": f"k8s:{ns}/{pod_name}",
                             "note": "hostPID: true"})
        if spec.get("hostNetwork"):
            findings.append({"severity": "high", "title": "net-host-mode",
                             "where": f"k8s:{ns}/{pod_name}",
                             "note": "hostNetwork: true"})
        if spec.get("hostIPC"):
            findings.append({"severity": "medium", "title": "ipc-host-mode",
                             "where": f"k8s:{ns}/{pod_name}",
                             "note": "hostIPC: true"})

        for vol in spec.get("volumes", []):
            hp = vol.get("hostPath")
            if hp:
                path = hp.get("path", "")
                sensitive = ("/", "/etc", "/var/run/docker.sock",
                             "/var/run/containerd/containerd.sock",
                             "/proc", "/sys")
                if path in sensitive:
                    sev = "critical" if "sock" in path or path == "/" else "high"
                    findings.append({"severity": sev,
                                     "title": "hostpath-sensitive",
                                     "where": f"k8s:{ns}/{pod_name}:vol:{vol.get('name','')}",
                                     "note": f"hostPath: {path}"})

        all_containers = spec.get("containers", []) + spec.get("initContainers", [])
        for c in all_containers:
            cname = c.get("name", "")
            lbl = f"k8s:{ns}/{pod_name}/{cname}"
            sc = c.get("securityContext") or {}

            if sc.get("privileged"):
                findings.append({"severity": "critical", "title": "privileged-container",
                                 "where": lbl,
                                 "note": "securityContext.privileged: true"})

            if sc.get("runAsUser") == 0:
                findings.append({"severity": "medium", "title": "run-as-root",
                                 "where": lbl,
                                 "note": "runAsUser: 0 (explicit root)"})

            caps = (sc.get("capabilities") or {}).get("add") or []
            caps_upper = set(cap.upper() for cap in caps)
            dangerous = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                         "DAC_READ_SEARCH", "NET_ADMIN", "ALL"}
            hit = caps_upper & dangerous
            if "ALL" in hit:
                findings.append({"severity": "critical", "title": "cap-add-all",
                                 "where": lbl,
                                 "note": "capabilities.add: ALL"})
            elif hit:
                for cap in sorted(hit):
                    findings.append({"severity": "high",
                                     "title": f"cap-add-{cap.lower()}",
                                     "where": lbl,
                                     "note": f"capabilities.add: {cap}"})

            if sc.get("allowPrivilegeEscalation") and not sc.get("privileged"):
                findings.append({"severity": "low", "title": "allow-priv-escalation",
                                 "where": lbl,
                                 "note": "allowPrivilegeEscalation: true"})

        pod_sc = spec.get("securityContext") or {}
        if pod_sc.get("runAsUser") == 0:
            findings.append({"severity": "medium", "title": "pod-run-as-root",
                             "where": f"k8s:{ns}/{pod_name}",
                             "note": "pod securityContext.runAsUser: 0"})

    return findings


def detect_runtime() -> str:
    for rt in ["docker", "nerdctl", "podman"]:
        if run(["which", rt]).strip():
            return rt
    return ""


def main():
    p = argparse.ArgumentParser(description="Host-side privileged container check")
    p.add_argument("--runtime", default="auto",
                   help="docker|podman|nerdctl|crictl|kubectl|auto")
    p.add_argument("--out", default=None, help="output JSON path")
    p.add_argument("--container-id", default=None,
                   help="check single container (default: all)")
    args = p.parse_args()

    all_findings = []

    # --- kubectl check (k8s) ---
    if run(["which", "kubectl"]).strip():
        k8s_findings = check_kubectl()
        all_findings.extend(k8s_findings)

    # --- crictl check (containerd/CRI-O without kubectl) ---
    if run(["which", "crictl"]).strip():
        if args.container_id:
            ids = [args.container_id]
        else:
            ids = [x for x in run(["crictl", "ps", "-q"]).strip().split("\n") if x]
        for cid in ids:
            all_findings.extend(check_crictl_inspect(cid, cid[:12]))

    # --- docker/podman/nerdctl check ---
    rt = args.runtime
    if rt == "auto":
        rt = detect_runtime()

    if rt in ("docker", "podman", "nerdctl"):
        if args.container_id:
            ids = [args.container_id]
        else:
            ids = [x for x in run([rt, "ps", "-q"]).strip().split("\n") if x]
        for cid in ids:
            name_raw = run([rt, "inspect", "-f", "{{.Name}}", cid]).strip().lstrip("/")
            label = name_raw or cid[:12]
            all_findings.extend(check_docker_inspect(rt, cid, label))

    # --- dedup ---
    seen = set()
    deduped = []
    for f in all_findings:
        key = f"{f['title']}|{f['where']}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # --- output ---
    counts = {}
    for f in deduped:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    deduped.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)
    status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in counts.items()) or "no findings"

    result = {
        "module": "privesc-escape-check.privileged",
        "status": status,
        "summary": summary,
        "counts": counts,
        "findings": deduped,
    }

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"check_privileged: {args.out} ({summary})")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
