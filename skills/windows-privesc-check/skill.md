# Windows Privilege Escalation Check

Windows 主机提权漏洞扫描模块，检测系统配置错误、权限问题和内核漏洞。

## Description

使用以下工具扫描 Windows 系统的提权向量：

| 工具 | 用途 |
|------|------|
| **WinPEAS** | 全面提权枚举（服务、注册表、计划任务、凭据等） |
| **Seatbelt** | 系统安全配置检查（100+ 检查项） |
| **SharpUp** | 提权漏洞检测（服务劫持、DLL劫持等） |
| **Watson** | 内核漏洞扫描（缺失的 KB 和 CVE） |

## Usage

### PowerShell (推荐)

```powershell
# 完整扫描
.\skills\windows-privesc-check\scripts\run.ps1

# 仅运行特定工具
.\skills\windows-privesc-check\scripts\run.ps1 -Tools winpeas,watson

# 指定输出目录
.\skills\windows-privesc-check\scripts\run.ps1 -Output C:\audit\results

# 超时设置 (秒)
.\skills\windows-privesc-check\scripts\run.ps1 -Timeout 300
```

### 运行单个工具

```powershell
# WinPEAS
.\skills\windows-privesc-check\scripts\run_winpeas.ps1

# Seatbelt
.\skills\windows-privesc-check\scripts\run_seatbelt.ps1

# SharpUp
.\skills\windows-privesc-check\scripts\run_sharpup.ps1

# Watson
.\skills\windows-privesc-check\scripts\run_watson.ps1
```

## Output

| 文件 | 说明 |
|------|------|
| `host.json` | 结构化发现结果 |
| `host.log` | 原始扫描日志 |
| `winpeas_raw.txt` | WinPEAS 原始输出 |
| `seatbelt_raw.txt` | Seatbelt 原始输出 |

## Finding Categories

- **Critical**: 可直接获取 SYSTEM 权限的漏洞
- **High**: 高概率提权向量
- **Medium**: 需要特定条件的提权路径
- **Low**: 信息泄露或辅助信息

## Requirements

- Windows 10/11 或 Windows Server 2016+
- PowerShell 5.1+
- 管理员权限（推荐）

## Tools Location

工具默认存放在 `bin/windows/` 目录：
- `winpeas.exe`
- `seatbelt.exe`
- `sharpup.exe`
- `watson.exe`

使用以下命令下载工具：
```powershell
.\bin\fetch_windows_tools.ps1
```
