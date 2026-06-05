# Audit Report Analyzer

Analyze Linux security audit report archives with AI-powered analysis and generate comprehensive evidence reports.

## Description

This skill takes a compressed audit report archive (tar.gz, tar.zip, zip) and automatically:
1. Extracts to a dedicated directory
2. Runs code-based analysis for structured data
3. Performs AI-powered analysis for deeper insights
4. Generates detailed evidence reports with raw scanner output
5. Creates kernel vulnerability analysis with remediation
6. Produces Excel reports with false positive detection
7. Generates JSON summary for automation

## Usage

```bash
# Basic usage - will trigger AI analysis
lsa run audit-report-analyzer --archive /path/to/report.tar.gz

# With custom output directory
lsa run audit-report-analyzer --archive /path/to/report.tar.gz --output /custom/output/dir

# Skip AI analysis (code only)
lsa run audit-report-analyzer --archive /path/to/report.tar.gz --no-ai
```

## Input

- `--archive` or `-a`: Path to the compressed audit report archive
- `--output` or `-o`: (Optional) Custom output directory
- `--no-ai`: (Optional) Skip AI analysis, code-based only

## Output Files

| File | Description |
|------|-------------|
| `detailed-audit-evidence.md` | Complete evidence report with raw scanner output |
| `kernel-vulnerability-analysis.md` | Detailed kernel CVE analysis with fixes |
| `detailed-audit-findings.xlsx` | Excel report with all findings and FP detection |
| `ai-analysis-report.md` | AI-powered deep analysis and recommendations |
| `audit-summary.json` | JSON summary for automation |

## AI Analysis Capabilities

The AI analysis provides:
- **False Positive Validation**: AI reviews each finding to determine if it's a true positive
- **Risk Prioritization**: Contextual risk scoring based on environment
- **Attack Path Analysis**: Identifies potential attack chains
- **Remediation Prioritization**: Orders fixes by business impact
- **Compliance Mapping**: Maps findings to CIS, NIST, etc.

## Supported Tools

The analyzer extracts evidence from:
- **LinPEAS**: Privilege escalation, kernel CVEs
- **Gitleaks**: Secret/credential detection
- **TruffleHog**: Verified secret detection
- **CDK**: Container escape detection
- **DeepCE**: Container security checks
- **Peirates**: K8s privilege escalation
- **Kube-bench**: CIS Kubernetes benchmark
- **amicontained**: Container introspection

## Requirements

- Python 3.8+
- openpyxl
- jq (for JSON processing)

## Examples

```bash
# Analyze a report archive with AI
lsa run audit-report-analyzer --archive /tmp/audit-report.tar.gz

# Quick code-only analysis
lsa run audit-report-analyzer --archive /tmp/audit-report.tar.gz --no-ai
```
