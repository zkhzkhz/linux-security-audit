# Container Security Scan

Scan a specific container (Docker or Crictl) for security vulnerabilities using nsenter.

## Description

This skill allows scanning a specific container by name or ID, supporting both Docker and Crictl container runtimes. It uses nsenter to enter the container's namespaces and run security checks.

## Usage

```bash
# Scan Docker container by name
lsa run container-security-scan --runtime docker --container my-container

# Scan Docker container by ID
lsa run container-security-scan --runtime docker --container-id abc123def456

# Scan Crictl container by name
lsa run container-security-scan --runtime crictl --container my-pod-container

# Scan Crictl container by ID
lsa run container-security-scan --runtime crictl --container-id abc123

# Full scan with all modules
lsa run container-security-scan --runtime docker --container my-container --full
```

## Input

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--runtime` | Container runtime: docker or crictl | docker |
| `--container` | Container name to scan | - |
| `--container-id` | Container ID to scan | - |
| `--full` | Run all security modules | false |
| `--timeout` | Scan timeout in seconds | 300 |

## Output Files

| File | Description |
|------|-------------|
| `result.json` | Structured findings in JSON |
| `summary.md` | Human-readable summary |
| `raw.log` | Raw scanner output |

## Scan Modules

When `--full` is specified:

| Module | Description |
|--------|-------------|
| container-escape | Check for escape vectors (caps, mounts, devices) |
| sensitive-scan | Scan for secrets/credentials |
| network-check | Check network exposure |
| process-check | Check running processes |

## Requirements

- Root privileges (for nsenter)
- Docker or crictl installed
- nsenter available

## Examples

```bash
# Quick scan of icagent container
lsa run container-security-scan --runtime docker --container icagent

# Full scan of kube-system pod container
lsa run container-security-scan --runtime crictl --container-id 38ab771d0517 --full

# Scan with custom timeout
lsa run container-security-scan --container myapp --timeout 600
```