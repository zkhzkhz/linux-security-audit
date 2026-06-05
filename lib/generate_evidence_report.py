#!/usr/bin/env python3
"""
Generate detailed audit report with secret evidence and false positive analysis.
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Default paths (can be overridden via command line)
DEFAULT_SCAN_DIR = Path("/root/linux-security-audit/reports/liteserver-mindie-audit-original/reports/xihe-910b2-prod-node-6-20260604-061752")
DEFAULT_OUTPUT_DIR = Path("/root/linux-security-audit/reports/liteserver-mindie-audit-original")

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def analyze_false_positives(findings):
    """Analyze and categorize false positives."""
    fp_reasons = defaultdict(list)
    real_findings = []

    for f in findings:
        where = f.get("where", "")
        note = f.get("note", "")
        title = f.get("title", "")
        severity = f.get("severity", "")
        is_fp = f.get("is_likely_fp", False)

        # Check FP patterns
        reason = None

        # Go stdlib test data
        if "/usr/local/go/" in where and ("testdata" in where or "test" in where):
            reason = "Go stdlib 测试数据"
        # Docker overlay build artifacts
        elif "/overlay2/" in where and any(x in where for x in ["/usr/lib/", "/usr/local/go/", "/usr/share/"]):
            reason = "Docker 镜像层编译产物"
        # Python test data
        elif "test/" in where or "tests/" in where or "_test.py" in where:
            reason = "Python 测试数据"
        # Low entropy (likely FP)
        elif "entropy=" in note and float(note.split("entropy=")[1].split()[0]) < 3.0:
            reason = "低熵值（可能是误报）"
        # Test fixtures
        elif "fixture" in where.lower() or "example" in where.lower():
            reason = "测试示例数据"
        # Config files with non-secret patterns
        elif title in ["generic-api-key", "jwt", "uri"] and severity in ["low", "medium"]:
            reason = "通用模式误匹配"
        # Already marked as FP
        elif is_fp:
            reason = "自动识别为误报"

        if reason:
            fp_reasons[reason].append(f)
        else:
            real_findings.append(f)

    return real_findings, dict(fp_reasons)

def generate_evidence_report(scan_dir=None, output_dir=None):
    """Generate detailed evidence report."""
    global SCAN_DIR, OUTPUT_DIR
    if scan_dir:
        SCAN_DIR = Path(scan_dir)
    if output_dir:
        OUTPUT_DIR = Path(output_dir)

    lines = []

    # Load summary.json for host info
    host_info = {"host": "unknown", "arch": "unknown"}
    summary_json_path = SCAN_DIR.parent / "summary.json"
    if summary_json_path.exists():
        try:
            summary_data = load_json(summary_json_path)
            host_info["host"] = summary_data.get("host", "unknown")
            host_info["arch"] = summary_data.get("arch", "unknown")
        except:
            pass

    lines.append("# 安全审计证据报告")
    lines.append("")
    lines.append(f"**生成时间：** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**扫描目录：** {SCAN_DIR}")
    lines.append(f"**目标主机：** {host_info['host']} ({host_info['arch']})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Load all module results
    sensitive_result = load_json(SCAN_DIR / "sensitive-info-scan/result.json")
    privesc_result = load_json(SCAN_DIR / "privesc-escape-check/result.json")
    lateral_result = load_json(SCAN_DIR / "lateral-movement-scan/result.json")
    egress_result = load_json(SCAN_DIR / "egress-control-audit/result.json")

    # Summary
    lines.append("## 一、扫描结果总览")
    lines.append("")
    lines.append("| 模块 | 状态 | Critical | High | Medium | Low | 误报数 |")
    lines.append("|------|------|----------|------|--------|-----|--------|")

    for name, data in [
        ("敏感信息扫描", sensitive_result),
        ("提权逃逸检查", privesc_result),
        ("横向移动扫描", lateral_result),
        ("出口控制审计", egress_result),
    ]:
        counts = data.get("counts", {})
        fp = counts.get("likely_fp", 0)
        lines.append(f"| {name} | {data.get('status', 'unknown')} | {counts.get('critical', 0)} | {counts.get('high', 0)} | {counts.get('medium', 0)} | {counts.get('low', 0)} | {fp} |")

    lines.append("")

    # False Positive Analysis
    lines.append("## 二、误报分析")
    lines.append("")

    # Analyze sensitive-info-scan
    real_findings, fp_reasons = analyze_false_positives(sensitive_result.get("findings", []))

    lines.append("### 2.1 敏感信息扫描误报分类")
    lines.append("")
    lines.append("| 误报原因 | 数量 | 说明 |")
    lines.append("|----------|------|------|")

    for reason, items in sorted(fp_reasons.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {reason} | {len(items):,} | 查看具体文件路径确认 |")

    lines.append("")
    lines.append(f"**原始发现数：** {len(sensitive_result.get('findings', [])):,}")
    lines.append(f"**误报数：** {sum(len(v) for v in fp_reasons.values()):,}")
    lines.append(f"**真实发现数：** {len(real_findings):,}")
    lines.append("")

    # Critical findings with evidence
    lines.append("## 三、Critical 级别发现（含证据）")
    lines.append("")

    critical_findings = [f for f in real_findings if f.get("severity") == "critical"]

    lines.append(f"共发现 **{len(critical_findings)}** 个 Critical 级别问题")
    lines.append("")

    for i, f in enumerate(critical_findings[:30], 1):
        lines.append(f"### 3.{i} {f.get('title', 'unknown')}")
        lines.append("")
        lines.append(f"- **严重度：** {f.get('severity', 'unknown')}")
        lines.append(f"- **位置：** `{f.get('where', 'unknown')}`")
        lines.append(f"- **密钥前缀：** `{f.get('secret_prefix', 'N/A')}`")
        lines.append(f"- **评分：** {f.get('note', 'N/A')}")
        lines.append(f"- **误报：** {'是' if f.get('is_likely_fp') else '否'}")
        lines.append("")

    # High severity findings
    lines.append("## 四、High 级别关键发现")
    lines.append("")

    high_findings = [f for f in real_findings if f.get("severity") == "high"]

    # Group by title
    high_by_type = defaultdict(list)
    for f in high_findings:
        high_by_type[f.get("title", "other")].append(f)

    lines.append("### 4.1 按类型分组")
    lines.append("")
    lines.append("| 类型 | 数量 | 说明 |")
    lines.append("|------|------|------|")

    for title, items in sorted(high_by_type.items(), key=lambda x: -len(x[1]))[:20]:
        example = items[0]
        where_example = example.get("where", "")[:60] + "..." if len(example.get("where", "")) > 60 else example.get("where", "")
        lines.append(f"| {title} | {len(items):,} | `{where_example}` |")

    lines.append("")

    # Privilege escalation findings
    lines.append("## 五、提权与容器逃逸发现")
    lines.append("")

    priv_critical = [f for f in privesc_result.get("findings", []) if f.get("severity") == "critical"]

    lines.append(f"### 5.1 Critical 级别 ({len(priv_critical)} 项)")
    lines.append("")
    lines.append("| 类型 | 容器 | 说明 |")
    lines.append("|------|------|------|")

    for f in priv_critical[:30]:
        title = f.get("title", "unknown")
        where = f.get("where", "unknown")
        note = f.get("note", "")[:60]
        lines.append(f"| {title} | `{where[:50]}...` | {note} |")

    lines.append("")

    # Lateral movement findings
    lines.append("## 六、横向移动风险")
    lines.append("")

    lat_high = [f for f in lateral_result.get("findings", []) if f.get("severity") == "high"]

    lines.append(f"### 6.1 K8s Service Account Token 泄露 ({len(lat_high)} 项)")
    lines.append("")
    lines.append("| 容器 | 位置 | Token长度 |")
    lines.append("|------|------|-----------|")

    for f in lat_high[:30]:
        where = f.get("where", "unknown")
        note = f.get("note", "")
        lines.append(f"| `{where[:70]}...` | {note[:20]} |")

    lines.append("")

    # Egress control findings
    lines.append("## 七、出口网络风险")
    lines.append("")

    egress_high = [f for f in egress_result.get("findings", []) if f.get("severity") == "high"]

    lines.append(f"### 7.1 容器出口无限制 ({len(egress_high)} 项)")
    lines.append("")
    lines.append("| 容器 | 目标地址 | 风险说明 |")
    lines.append("|------|----------|----------|")

    for f in egress_high[:30]:
        title = f.get("title", "unknown")
        where = f.get("where", "unknown")
        note = f.get("note", "")[:50]
        lines.append(f"| {title} | `{where}` | {note} |")

    lines.append("")

    # Recommendations
    lines.append("## 八、修复建议")
    lines.append("")

    lines.append("### P0 - 立即处理")
    lines.append("")
    lines.append("| 问题 | 修复建议 |")
    lines.append("|------|----------|")
    lines.append("| 特权容器运行 | 移除 --privileged，使用最小权限 |")
    lines.append("| Docker Socket 可写 | 移除 Docker socket 挂载 |")
    lines.append("| K8s SA Token 泄露 | 限制 ServiceAccount 权限 |")
    lines.append("| 容器出口无限制 | 配置 NetworkPolicy 限制出口 |")
    lines.append("")

    lines.append("### P1 - 高优先级")
    lines.append("")
    lines.append("| 问题 | 修复建议 |")
    lines.append("|------|----------|")
    lines.append("| 私钥文件泄露 | 轮换密钥，限制文件权限 |")
    lines.append("| CAP_SYS_ADMIN 权限 | 移除危险 capability |")
    lines.append("| 容器可访问外网 | 配置白名单出口规则 |")
    lines.append("")

    # Write report
    output_path = OUTPUT_DIR / "detailed-audit-evidence.md"
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"Report written to: {output_path}")

    # Also generate JSON summary
    summary = {
        "generated": datetime.now().isoformat(),
        "scan_dir": str(SCAN_DIR),
        "host": host_info["host"],
        "arch": host_info["arch"],
        "modules": {
            "sensitive-info-scan": {
                "total": len(sensitive_result.get("findings", [])),
                "real": len(real_findings),
                "false_positives": sum(len(v) for v in fp_reasons.values()),
                "fp_reasons": {k: len(v) for k, v in fp_reasons.items()}
            },
            "privesc-escape-check": {
                "critical": len([f for f in privesc_result.get("findings", []) if f.get("severity") == "critical"]),
                "high": len([f for f in privesc_result.get("findings", []) if f.get("severity") == "high"])
            },
            "lateral-movement-scan": {
                "high": len(lat_high)
            },
            "egress-control-audit": {
                "high": len(egress_high)
            }
        }
    }

    json_path = OUTPUT_DIR / "audit-summary.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"Summary JSON written to: {json_path}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_dir = Path(sys.argv[1])
        output_dir = scan_dir.parent
        generate_evidence_report(scan_dir, output_dir)
    else:
        generate_evidence_report()
