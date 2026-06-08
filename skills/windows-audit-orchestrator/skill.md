# Windows Audit Orchestrator

Windows 系统安全审计统筹器，一键执行所有安全扫描模块。

## Description

自动执行以下扫描模块：
1. **windows-privesc-check** - 提权漏洞扫描
2. **windows-sensitive-scan** - 敏感信息扫描
3. **windows-lateral-movement** - 横向移动风险扫描
4. **windows-egress-control** - 出口网络控制审计

## Usage

```powershell
# 完整审计
.\skills\windows-audit-orchestrator\scripts\run_all.ps1

# 仅运行指定模块
.\skills\windows-audit-orchestrator\scripts\run_all.ps1 -Only privesc

# 指定输出目录
.\skills\windows-audit-orchestrator\scripts\run_all.ps1 -Output C:\audit

# 超时设置
.\skills\windows-audit-orchestrator\scripts\run_all.ps1 -Timeout 900
```

## Output

| 文件 | 说明 |
|------|------|
| `summary.json` | 汇总 JSON 报告 |
| `summary.md` | Markdown 汇总报告 |
| `windows-privesc-check/` | 提权扫描结果 |
| `windows-sensitive-scan/` | 密钥扫描结果 |

## Report Summary

生成的报告包含：
- 各模块状态 (ok/warn/critical)
- 发现数量统计 (critical/high/medium/low)
- 主要发现摘要
- 修复建议

## Requirements

- Windows 10/11 或 Windows Server 2016+
- PowerShell 5.1+
- 管理员权限（推荐）

## Quick Start

```powershell
# 1. 下载工具
.\bin\fetch_windows_tools.ps1

# 2. 运行审计
.\skills\windows-audit-orchestrator\scripts\run_all.ps1

# 3. 查看报告
cat reports\<hostname>-<timestamp>\summary.md
```
