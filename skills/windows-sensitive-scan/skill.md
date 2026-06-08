# Windows Sensitive Information Scan

Windows 文件系统密钥扫描模块，检测代码、配置文件中的敏感信息泄露。

## Description

使用 Gitleaks 和 TruffleHog 扫描 Windows 文件系统中的：
- API 密钥和 Token
- 数据库密码
- 私钥证书
- 云服务凭证
- 其他敏感信息

## Usage

### PowerShell

```powershell
# 扫描默认路径
.\skills\windows-sensitive-scan\scripts\scan.ps1

# 扫描指定路径
.\skills\windows-sensitive-scan\scripts\scan.ps1 -Targets C:\Users,C:\Projects

# 自定义输出目录
.\skills\windows-sensitive-scan\scripts\scan.ps1 -Output C:\audit\results

# 禁用误报过滤
.\skills\windows-sensitive-scan\scripts\scan.ps1 -NoTriage

# 限制并发
.\skills\windows-sensitive-scan\scripts\scan.ps1 -Jobs 2
```

## Output

| 文件 | 说明 |
|------|------|
| `result.json` | 过滤后的结构化发现 |
| `raw.json` | 原始扫描结果 |
| `scan.log` | 扫描日志 |

## Default Scan Targets

- `C:\Users` - 用户目录
- `C:\inetpub` - IIS 配置
- `C:\ProgramData` - 应用数据
- 排除：`C:\Windows`, `C:\Program Files`, 缓存目录

## Configuration

扫描排除规则位于 `config/exclude-paths.txt`，支持正则表达式。

## Tools

| 工具 | 用途 |
|------|------|
| Gitleaks | 密钥模式匹配 + 熵值检测 |
| TruffleHog | 验证型密钥检测 |

## Requirements

- Windows 10/11 或 Windows Server 2016+
- PowerShell 5.1+
- Gitleaks/TruffleHog 二进制文件

下载工具：
```powershell
.\bin\fetch_windows_tools.ps1 -Tools gitleaks,trufflehog
```
