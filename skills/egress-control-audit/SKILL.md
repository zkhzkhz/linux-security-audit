---
name: egress-control-audit
description: This skill should be used when the user asks to audit a Linux host or container fleet for outbound (egress) internet exposure, propose a direction-based allowlist, or apply outbound / inter-container isolation policies. Triggers on phrases like "外网连接控制", "出网白名单", "egress audit", "outbound allowlist", "container isolation", "限制容器之间互访", "iptables egress", or "docker network isolation". Provides four scripts: egress_check.sh (inventory), suggest_allowlist.sh (proposal), apply_egress_iptables.sh (host iptables/nft policy, dry-run by default), apply_container_isolation.sh (per-network rules + DOCKER-USER).
version: 1.0.0
---

# Egress & Container-Isolation Audit

Two outcomes:

1. **Visibility** — what does this host (and each container on it) currently
   reach on the public/private internet? What DNS does it query? What's the
   default-route picture? What firewall rules already exist?
2. **Control** — proposed and (with explicit `--apply`) installed allowlist
   policies for egress and inter-container access.

## When to use

- "Limit this host to only talk to these domains/IPs."
- "Audit which containers can talk to each other; restrict to what's needed."
- "Show me what's currently leaving the box."
- "出网方向白名单 / 容器互访限制"

## Scripts

### `scripts/egress_check.sh`
Read-only. Collects:
- `ip route`, `ip rule`, `ip -6 route`
- Resolved DNS history (where available): `journalctl -u systemd-resolved`,
  `/var/log/syslog` grep, `dnsmasq` log if running.
- Current outbound TCP/UDP sockets (`ss -ntpu state established`).
- nftables / iptables ruleset snapshots (`iptables-save`, `nft list ruleset`).
- For each container (if any runtime is found): its IP, exposed ports, network
  mode, links to other containers.
- Detected target endpoints are aggregated into:
  `endpoints.json` (peer, port, count, last_seen, container)

### `scripts/suggest_allowlist.sh`
Reads `endpoints.json` and produces:
- `allowlist.suggested.json` — proposed allowlist by host process / container.
- `egress.iptables.rules` — drop-in iptables ruleset (dry-run; not applied).
- `docker-network.plan.json` — per-container internal network proposal:
  same-app containers in their own user-defined bridge with `--internal` for
  back-ends, no `bridge` membership for what doesn't need external comms.

Heuristic: any endpoint observed ≥ N times during the sample window is included;
endpoints accessed only once may be transient — flagged for review.

### `scripts/apply_egress_iptables.sh`
Applies the proposed host-side iptables ruleset. Defaults to **dry-run**;
needs `--apply` to actually run `iptables` commands. Adds a backup of the
existing ruleset to `iptables.backup.<ts>.rules` before applying, and writes a
restore command into the run dir.

Policy shape:
```
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -d <allowlisted-CIDR-or-IP> -p tcp --dport <port> -j ACCEPT
... (DNS to whitelisted resolvers) ...
-A OUTPUT -j LOG --log-prefix "EGRESS-DROP "
-A OUTPUT -j REJECT --reject-with icmp-port-unreachable
```
With `--policy drop` it also sets `iptables -P OUTPUT DROP` (use cautiously —
locks you out if SSH return path goes through the policy).

### `scripts/apply_container_isolation.sh`
Two layers of isolation:
1. **Inter-container** via `iptables` `DOCKER-USER` chain — drops all
   container-to-container traffic except for explicit allow-pairs from the
   proposal.
2. **Per-network egress** — for each user-defined Docker network, optionally
   recreate it with `--internal` (no external connectivity) or add filter
   rules on its bridge interface.

Dry-run by default. `--apply` performs the changes; a backup of
DOCKER-USER chain is taken first.

## Usage

```bash
# Step 1: inventory current state (read-only)
./egress_check.sh

# Step 2: produce allowlist proposal (no changes)
./suggest_allowlist.sh

# Step 3: review reports/.../egress-control-audit/{allowlist.suggested.json,egress.iptables.rules}
# then apply if happy:
./apply_egress_iptables.sh                  # dry-run, prints the commands
./apply_egress_iptables.sh --apply --policy drop

# Container side
./apply_container_isolation.sh              # dry-run
./apply_container_isolation.sh --apply
```

## Output

```
reports/<host>-<ts>/egress-control-audit/
  egress_check.log
  routes.txt, sockets.txt, dns.log
  iptables.save, nftables.save
  endpoints.json
  allowlist.suggested.json
  egress.iptables.rules
  docker-network.plan.json
  apply.log                # only when --apply runs
  rollback.sh              # written before --apply
  result.json              # module result
```

## Safety

- `--apply` is required for any change; default is always dry-run.
- A `rollback.sh` is written *before* applying. It runs `iptables-restore <
  iptables.backup.<ts>.rules`.
- On the host, `--policy drop` is the most likely way to lock yourself out:
  the script asks for confirmation before flipping the default policy when
  invoked interactively, and refuses entirely if it detects only a remote SSH
  shell with no whitelist entry for the source IP.

## Gotchas

- Endpoint inventory is point-in-time; run with `--duration 5m` to sample
  multiple times.
- `journald` may not contain DNS history on every distro; the script reports
  which sources were available.
- Inter-container blocking with `DOCKER-USER` only affects traffic that
  traverses `docker0`/bridge; host-mode containers bypass it.
