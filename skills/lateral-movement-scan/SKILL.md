---
name: lateral-movement-scan
description: This skill should be used when the user asks to assess lateral movement / east-west risk from a Linux host or container — discovering live neighbours, scanning their exposed services, and enumerating credentials reusable for pivoting. Triggers on phrases like "横向移动", "lateral movement", "scan the subnet", "nmap the network", "find pivot targets", "credential reuse", or "what can this host reach". Uses nmap for discovery + service scan (top 300 ports plus a curated high-port list) and shell helpers for SSH/AWS/Kube credentials.
version: 1.0.0
---

# Lateral Movement Scan

Assesses what an attacker on this host could reach laterally:

1. **Subnet discovery** — derive subnets from this host's routing table; ARP +
   ICMP + fast-TCP sweep to find live hosts.
2. **Service scan** — nmap top-300 TCP ports plus a high-port list of common
   internal services (admin UIs, DBs, message queues, cluster ports).
3. **Credential reuse** — enumerate keys/credentials present on this host that
   could be reused against the discovered services (SSH keys, `.aws/credentials`,
   `~/.kube/config`, `~/.docker/config.json`, git creds, browser cookies).

Default behaviour is **non-aggressive**: rate-limited, no NSE exploits unless
`--full` is passed.

## When to use

- "From this jumpbox, who else can it reach?"
- "Audit east-west exposure in this VPC subnet."
- "Are SSH keys on this box that grant admin elsewhere?"
- "横向移动评估 / 内网扫描"

## Scripts

- `scripts/discover.sh` — subnet derivation + host discovery; outputs `live.txt`.
- `scripts/service_scan.sh` — nmap top-300 + extra high ports against `live.txt`.
- `scripts/creds_reuse.sh` — finds reusable credentials on this host.
- All three write to the run dir; the orchestrator merges into one
  `result.json` for the module.

## Usage

```bash
# Default: discover + service scan top-300+highs
./discover.sh
./service_scan.sh

# Override subnets (e.g. /16 too big — provide your own list)
./discover.sh 10.0.0.0/24 192.168.10.0/24

# Aggressive mode (NSE default scripts + version detection on all opens)
./service_scan.sh --full

# Just enumerate creds on this host
./creds_reuse.sh
```

## Port set

`top-300` from nmap's `--top-ports 300`, plus this curated extra list (high or
non-default but interesting on internal networks):

```
2049 2375 2376 2379 2380 2381 4243 4244 4789 5000 5044 5601 6443 6379 7001 7077
8001 8009 8086 8088 8089 8161 8200 8500 8761 8888 9000 9001 9042 9090 9091 9092
9100 9200 9300 9418 9999 10250 10255 10256 11211 15672 16379 27017 27018 27019
50070 61613 61616 61617
```

Rationale: kubelet (10250/10255), etcd (2379/2380), docker daemon (2375/2376),
ZK/JMX/JNDI, ES/Kibana, Redis variants, MQ (RabbitMQ/Activemq/Kafka), Hadoop,
docker registry, Vault, Consul, Prometheus exporters, MongoDB.

## Discovery tactics

`discover.sh` does, in order, only what the host can do:

1. ARP scan (if `arp-scan`/`arp` available) for the local layer-2 segment.
2. ICMP ping sweep with nmap (`-sn -PE -PP -PM`).
3. Fast TCP-SYN top-50 sweep against unanswered hosts to catch ICMP-blocked.

It uses `--max-rate 200` by default; tune with `--rate`.

## Credential reuse heuristics

`creds_reuse.sh` enumerates and grades:

- `~/.ssh/id_*` — type, key length, passphrase-protected (`is_encrypted`),
  matching `known_hosts` entries (potential targets), `authorized_keys` if any.
- `~/.aws/credentials`, `~/.aws/config` — profiles, role_arns.
- `~/.kube/config` — clusters and tokens, server URLs that may now be in
  `live.txt`.
- `~/.docker/config.json`, `~/.config/containers/auth.json` — registry creds.
- `~/.netrc`, git credential stores (`.git-credentials`, `~/.config/git`).
- Browser-stored creds are noted but not extracted (out of scope by default).

Each finding is severity-tagged (e.g. unprotected key with broad
`known_hosts` -> high).

## Output

```
reports/<host>-<ts>/lateral-movement-scan/
  live.txt
  discover.log
  nmap.gnmap
  nmap.xml
  services.json          # parsed nmap result
  creds.json             # creds_reuse.sh output
  result.json            # combined module result
```

## Gotchas

- Some environments rate-limit ICMP — TCP-SYN fallback is essential.
- ARP only sees the same L2 segment; cross-segment hosts need ICMP/TCP.
- nmap's `-sV` raises noise (and SoC alerts); reserved for `--full`.
- This skill never attempts password spraying or exploit modules. Use a real
  pentest tool with proper authorization for that.
