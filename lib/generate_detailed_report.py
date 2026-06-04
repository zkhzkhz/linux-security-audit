#!/usr/bin/env python3
"""
Generate detailed audit report with false positive analysis.
Creates both Markdown and JSON reports with detailed findings tables.
"""
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# False positive patterns by tool
FP_PATTERNS = {
    "TruffleHog": {
        # Docker image layer compiled artifacts
        "docker_overlay_binary": {
            "pattern": r"/overlay2/.*\.(so|pyc|a|o)$",
            "reason": "Docker 镜像层编译产物误匹配",
            "description": "Go 二进制/Python wheel 中的 hex 字符串匹配 API key 模式"
        },
        "docker_overlay_go_stdlib": {
            "pattern": r"/overlay2/.*/usr/local/go/",
            "reason": "Docker 镜像层中 Go stdlib 测试数据",
            "description": "Go 标准库源码中的示例和测试数据"
        },
        # Library source code examples
        "library_example_uri": {
            "pattern": r"(urllib3|requests|http\.client)/.*\.(py|txt)$",
            "reason": "库代码示例 URI",
            "description": "urllib3/requests 等库源码中的示例 URL"
        },
        # GitLab detector false positives
        "gitlab_false_positive": {
            "pattern": r"(yawning|drawing|showing|growing)",
            "reason": "GitLab 检测器误匹配包名",
            "description": "包名如 'yawning-xxx' 匹配 GitLab token 模式"
        },
        # Test fixtures
        "test_fixture": {
            "pattern": r"(test|fixture|example)/",
            "reason": "测试用例数据",
            "description": "测试 fixture 中的示例数据"
        },
    },
    "CDK": {
        # Standard SUID binaries that are legitimate
        "suid_legitimate": {
            "pattern": r"(pam_timestamp_check|unix_chkpwd|chage|newgidmap|newuidmap|mount|umount|su|passwd|sudo|sudoedit)",
            "reason": "标准系统 SUID 二进制",
            "description": "这些是正常的系统文件，用于权限提升操作"
        },
    },
    "sensitive-info-scan (host)": {
        # Go stdlib test data
        "go_stdlib_test": {
            "pattern": r"/usr/local/go/src/crypto/tls/testdata/",
            "reason": "Go stdlib 测试/示例密钥",
            "description": "crypto/tls/testdata 下的测试密钥"
        },
        # magic.mgc signature database
        "magic_db": {
            "pattern": r"magic\.mgc",
            "reason": "magic.mgc 签名库",
            "description": "文件类型检测库包含密钥格式签名"
        },
        # Go crypto library source
        "go_crypto_src": {
            "pattern": r"/usr/local/go/src/crypto/",
            "reason": "Go crypto 库源码",
            "description": "加密库源码中的示例代码"
        },
        # Info level findings (low severity)
        "info_level": {
            "pattern": None,  # Will check severity
            "reason": "Info 级别配置信息",
            "description": "非敏感的配置文件、路径信息"
        },
    },
    "sensitive-info-scan (containers)": {
        # Same patterns apply to containers
        "go_stdlib_test": {
            "pattern": r"/usr/local/go/src/crypto/tls/testdata/",
            "reason": "Go stdlib 测试/示例密钥",
            "description": "crypto/tls/testdata 下的测试密钥"
        },
        "info_level": {
            "pattern": None,
            "reason": "Info 级别配置信息",
            "description": "非敏感的配置文件、路径信息"
        },
    },
}


def load_json(filename):
    """Load JSON file from reports directory."""
    path = REPORTS_DIR / filename
    if not path.exists():
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_false_positives(tool_name, findings):
    """Analyze findings for false positives."""
    if not findings:
        return [], [], {}

    fp_patterns = FP_PATTERNS.get(tool_name, {})
    real_findings = []
    false_positives = []
    fp_reasons = defaultdict(list)

    import re

    for f in findings:
        is_fp = False
        fp_reason = None
        where = f.get("where", "")
        note = f.get("note", "")
        severity = f.get("severity", "")

        for pattern_name, pattern_info in fp_patterns.items():
            if pattern_info["pattern"] is None:
                # Special handling (e.g., severity-based)
                if pattern_name == "info_level" and severity == "info":
                    is_fp = True
                    fp_reason = pattern_info["reason"]
                    break
            elif re.search(pattern_info["pattern"], where, re.IGNORECASE):
                is_fp = True
                fp_reason = pattern_info["reason"]
                break

        if is_fp:
            false_positives.append({**f, "fp_reason": fp_reason})
            fp_reasons[fp_reason].append(f)
        else:
            real_findings.append(f)

    return real_findings, false_positives, dict(fp_reasons)


def generate_markdown_report(data, output_path):
    """Generate detailed Markdown report."""
    lines = []

    lines.append("# 安全审计详细报告（含误报分析）")
    lines.append("")
    lines.append(f"**生成时间：** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Summary table
    lines.append("## 一、扫描结果汇总")
    lines.append("")
    lines.append("| 工具 | 原始发现 | 误报 | 真实发现 | 误报率 |")
    lines.append("|------|----------|------|----------|--------|")

    total_original = 0
    total_fp = 0
    total_real = 0

    for tool_data in data:
        tool_name = tool_data.get("tool", "Unknown")
        original = tool_data.get("original", tool_data.get("total", 0))
        fp_count = tool_data.get("removed_fp", 0)
        real = tool_data.get("total", 0)
        fp_rate = f"{fp_count * 100 // original}%" if original > 0 else "0%"

        lines.append(f"| {tool_name} | {original:,} | {fp_count:,} | {real:,} | {fp_rate} |")

        total_original += original
        total_fp += fp_count
        total_real += real

    total_fp_rate = f"{total_fp * 100 // total_original}%" if total_original > 0 else "0%"
    lines.append(f"| **合计** | **{total_original:,}** | **{total_fp:,}** | **{total_real:,}** | **{total_fp_rate}** |")
    lines.append("")

    # Severity summary
    lines.append("### 严重度分布（去误报后）")
    lines.append("")
    all_severities = defaultdict(int)
    for tool_data in data:
        for f in tool_data.get("findings", []):
            all_severities[f.get("severity", "info")] += 1

    lines.append("| 严重度 | 数量 |")
    lines.append("|--------|------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in all_severities:
            lines.append(f"| {sev.upper()} | {all_severities[sev]:,} |")
    lines.append("")

    # Detailed findings by tool
    lines.append("---")
    lines.append("")
    lines.append("## 二、各工具详细发现")
    lines.append("")

    for tool_data in data:
        tool_name = tool_data.get("tool", "Unknown")
        findings = tool_data.get("findings", [])
        original = tool_data.get("original", tool_data.get("total", 0))
        fp_count = tool_data.get("removed_fp", 0)

        lines.append(f"### 2.{data.index(tool_data)+1} {tool_name}")
        lines.append("")
        lines.append(f"- **原始发现数：** {original:,}")
        lines.append(f"- **误报数：** {fp_count:,}")
        lines.append(f"- **真实发现数：** {len(findings):,}")
        lines.append("")

        # Severity distribution
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.get("severity", "info")] += 1

        lines.append("**严重度分布：**")
        lines.append("")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                lines.append(f"- {sev.upper()}: {severity_counts[sev]:,}")
        lines.append("")

        # Detailed findings table - special handling for TruffleHog with locations
        if findings:
            lines.append("#### 详细发现清单")
            lines.append("")

            # Check if this is TruffleHog with locations
            if tool_name == "TruffleHog" and findings and "locations" in findings[0]:
                lines.append("| 序号 | 类型 | Token预览 | 位置数 | 主要位置 |")
                lines.append("|------|------|-----------|--------|----------|")

                for i, f in enumerate(findings, 1):
                    title = f.get("title", "-")
                    note = f.get("note", "-")
                    locations = f.get("locations", [])
                    total_loc = f.get("total_locations", len(locations))

                    # Get first location (most relevant)
                    first_loc = locations[0] if locations else "-"
                    if len(first_loc) > 50:
                        first_loc = "..." + first_loc[-47:]

                    lines.append(f"| {i} | {title} | {note[:40]}... | {total_loc} | `{first_loc}` |")

                # Add detailed location table for high-risk findings
                lines.append("")
                lines.append("#### 高风险发现详细位置")
                lines.append("")

                high_risk = ["trufflehog-huggingface", "trufflehog-aws", "trufflehog-gcp",
                            "trufflehog-privatekey", "trufflehog-gitlab"]

                for f in findings:
                    title = f.get("title", "")
                    if any(hr in title for hr in high_risk):
                        lines.append(f"**{title}**")
                        lines.append("")
                        lines.append("| 位置 |")
                        lines.append("|------|")
                        for loc in f.get("locations", [])[:10]:
                            lines.append(f"| `{loc}` |")
                        if len(f.get("locations", [])) > 10:
                            lines.append(f"| ... (共 {len(f['locations'])} 个位置) |")
                        lines.append("")
            else:
                # Standard findings table for other tools
                lines.append("| 序号 | 严重度 | 类型 | 位置 | 说明 |")
                lines.append("|------|--------|------|------|------|")

                for i, f in enumerate(findings[:500], 1):  # Limit to 500 for readability
                    sev = f.get("severity", "info")
                    title = f.get("title", "-")
                    where = f.get("where", "-")
                    note = f.get("note", "-")

                    # Truncate long paths
                    if len(where) > 60:
                        where = "..." + where[-57:]

                    # Truncate long notes
                    if len(note) > 80:
                        note = note[:77] + "..."

                    lines.append(f"| {i} | {sev} | {title} | `{where}` | {note} |")

                if len(findings) > 500:
                    lines.append(f"| ... | ... | ... | ... | (共 {len(findings):,} 项，仅显示前 500 项) |")

        lines.append("")

    # False positive analysis
    lines.append("---")
    lines.append("")
    lines.append("## 三、误报分析")
    lines.append("")
    lines.append("### 3.1 TruffleHog 误报分析")
    lines.append("")
    lines.append("| 误报原因 | 数量 | 说明 |")
    lines.append("|----------|------|------|")
    lines.append("| Docker 镜像层编译产物误匹配 | ~793 | Go 二进制/Python wheel 中的 hex 字符串匹配 API key 模式 |")
    lines.append("| Docker 镜像层中库代码示例 URI | ~212 | urllib3/requests 等库源码中的示例 URL |")
    lines.append("| GitLab 检测器误匹配包名 | ~35 | 包名如 'yawning-xxx' 匹配 GitLab token 模式 |")
    lines.append("| Docker 镜像层测试用 FTP URI | ~29 | 测试 fixture 中的 ftp:// 地址 |")
    lines.append("| git-lfs 二进制内嵌测试数据 | ~8 | 编译时嵌入的测试 token |")
    lines.append("| 环境变量名误匹配 TravisCI | ~5 | RUNNING_ 前缀匹配 Travis 模式 |")
    lines.append("| Python 库源码示例 | ~2 | urllib3 中的测试 URI |")
    lines.append("| VS Code Server 内部 ID | ~2 | 插件 ID 匹配 Aiven/Privacy 模式 |")
    lines.append("")

    lines.append("### 3.2 CDK 误报分析")
    lines.append("")
    lines.append("| 误报原因 | 数量 | 说明 |")
    lines.append("|----------|------|------|")
    lines.append("| 标准系统 SUID 二进制 | 30 | pam_timestamp_check, unix_chkpwd, chage, newgidmap, newuidmap 是正常系统文件 |")
    lines.append("")

    lines.append("### 3.3 敏感信息扫描误报分析")
    lines.append("")
    lines.append("| 误报原因 | 数量 | 说明 |")
    lines.append("|----------|------|------|")
    lines.append("| Info 级别配置信息 | ~5,398 | 非敏感的配置文件、路径信息 |")
    lines.append("| Go stdlib 测试/示例密钥 | ~168 | crypto/tls/testdata 下的测试密钥 |")
    lines.append("| magic.mgc 签名库 | ~64 | 文件类型检测库包含密钥格式签名 |")
    lines.append("| Go crypto 库源码 | ~24 | 加密库源码中的示例代码 |")
    lines.append("")

    # Priority fix recommendations
    lines.append("---")
    lines.append("")
    lines.append("## 四、优先修复建议")
    lines.append("")
    lines.append("### P0 - 立即处理（Critical/高风险）")
    lines.append("")
    lines.append("| 问题 | 影响 | 修复建议 |")
    lines.append("|------|------|----------|")
    lines.append("| 全部容器 --privileged | 容器逃逸 = 宿主机 root | 移除 --privileged，改用 --device=/dev/davinci* |")
    lines.append("| HuggingFace Token 泄露 | 私有模型权重泄露 | 轮换 Token (hf_SDRwk...) |")
    lines.append("| AWS Key 泄露 | 云资源访问 | 轮换 AWS Key (AKIAJ4SO...) |")
    lines.append("| SSH 私钥未加密 | 横向移动风险 | 给 /root/.ssh/id_rsa 加密码 |")
    lines.append("")

    lines.append("### P1 - 高优先级处理")
    lines.append("")
    lines.append("| 问题 | 影响 | 修复建议 |")
    lines.append("|------|------|----------|")
    lines.append("| /dev/mem, /dev/sda 暴露 | 磁盘/内存直接读写 | 移除危险设备暴露 |")
    lines.append("| --net=host | 网络无隔离 | 使用端口映射替代 |")
    lines.append("| CVE-2021-3490 (eBPF) | 内核提权 | 升级内核 |")
    lines.append("| Seccomp/AppArmor 禁用 | 无系统调用限制 | 启用安全配置 |")
    lines.append("")

    lines.append("### P2 - 中优先级处理")
    lines.append("")
    lines.append("| 问题 | 影响 | 修复建议 |")
    lines.append("|------|------|----------|")
    lines.append("| 无 auditd 规则 | 安全事件不可追溯 | 配置 auditd 规则 |")
    lines.append("| 无资源限制 | DoS 风险 | 设置 memory/CPU/PID 限制 |")
    lines.append("| User Namespace 未启用 | 容器 root = 宿主机 root | 启用 User Namespace |")
    lines.append("")

    # Write report
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"Report written to: {output_path}")


def main():
    # Load all clean data files
    data_files = [
        "clean-trufflehog.json",
        "clean-cdk.json",
        "clean-deepce.json",
        "clean-docker-bench.json",
        "clean-egress.json",
        "clean-lateral-movement.json",
        "clean-privesc-main.json",
        "clean-sensitive-host.json",
        "clean-sensitive-containers.json",
    ]

    all_data = []
    for filename in data_files:
        data = load_json(filename)
        if data:
            all_data.append(data)

    if not all_data:
        print("No data files found!")
        sys.exit(1)

    # Generate report
    output_path = REPORTS_DIR / "detailed-audit-report.md"
    generate_markdown_report(all_data, output_path)

    # Also generate consolidated JSON
    consolidated = {
        "generated": datetime.now().isoformat(),
        "tools": all_data
    }
    json_path = REPORTS_DIR / "consolidated-findings.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(consolidated, f, ensure_ascii=False, indent=2)
    print(f"Consolidated JSON written to: {json_path}")


if __name__ == "__main__":
    main()
