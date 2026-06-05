# Audit Report Analyzer

Analyze Linux security audit report archives and generate comprehensive evidence reports with AI-powered analysis.

## When to Use

Use this skill when:
- User provides a compressed audit report archive (.tar.gz, .tar.zip, .zip)
- User asks to analyze security scan results
- User wants comprehensive evidence reports from audit data

## Input

- `archive_path`: Path to the compressed audit report archive

## Output

Generates the following files in a dedicated output directory:

| File | Description |
|------|-------------|
| `detailed-audit-evidence.md` | Complete evidence report with raw scanner output |
| `kernel-vulnerability-analysis.md` | Detailed kernel CVE analysis with fixes |
| `detailed-audit-findings.xlsx` | Excel report with all findings and FP detection |
| `audit-summary.json` | JSON summary for automation |

## Steps

1. **Extract Archive**: Extract the compressed archive to a dedicated directory under `/root/linux-security-audit/reports/`

2. **Load Scan Data**: Load results from all scan modules:
   - sensitive-info-scan (Gitleaks, TruffleHog)
   - privesc-escape-check (LinPEAS, CDK, DeepCE, Peirates, Kube-bench)
   - lateral-movement-scan
   - egress-control-audit

3. **Analyze Findings**: 
   - Identify false positives using pattern matching
   - Extract kernel CVE information from LinPEAS output
   - Correlate findings across tools

4. **Generate Reports**:
   - Create detailed evidence report with raw scanner output
   - Create kernel vulnerability analysis with remediation
   - Create Excel report with all findings
   - Create JSON summary

5. **AI Analysis**: Provide deep analysis including:
   - False positive validation
   - Attack path identification
   - Remediation prioritization
   - Compliance mapping

## Example

```
User: 分析下这个报告 /tmp/report.tar.gz

Claude: I'll analyze the audit report archive for you.
[Uses analyze_audit_report skill]
Generated reports in /root/linux-security-audit/reports/report-analysis/
- detailed-audit-evidence.md
- kernel-vulnerability-analysis.md
- detailed-audit-findings.xlsx
- audit-summary.json
```

## Tools Analyzed

- **LinPEAS**: Privilege escalation, kernel CVEs, system misconfigurations
- **Gitleaks**: Secret/credential detection with entropy analysis
- **TruffleHog**: Verified secret detection with API validation
- **CDK**: Container escape detection for K8s
- **DeepCE**: Container security checks
- **Peirates**: K8s privilege escalation paths
- **Kube-bench**: CIS Kubernetes benchmark compliance
- **amicontained**: Container introspection

## False Positive Detection

Automatically identifies false positives from:
- Docker overlay2 system files
- Python stdlib source code
- JDK Eclipse signature files
- Test/example data directories
- Binary files (.mgc, .solv, .db)
- Low entropy strings

## Dependencies

- Python 3.8+
- openpyxl (for Excel generation)
- Standard library only (no external API calls)
