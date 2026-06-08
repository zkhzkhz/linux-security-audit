# Windows Egress Control Audit

Windows 系统出口网络控制审计模块，检测外网访问控制配置。

## Description

检测以下出口控制风险：
- **防火墙配置** - Windows Firewall 出站规则
- **代理设置** - 系统代理配置
- **DNS设置** - DNS服务器配置
- **网络隔离** - 网络隔离状态

## Usage

```powershell
# 运行审计
.\skills\windows-egress-control\scripts\audit.ps1

# 指定输出目录
.\skills\windows-egress-control\scripts\audit.ps1 -Output C:\audit
```

## Output

| 文件 | 说明 |
|------|------|
| `result.json` | 结构化发现 |
| `audit.log` | 审计日志 |

## Detection Categories

| 类别 | 检测项 |
|------|--------|
| Firewall | 出站规则、默认策略 |
| Proxy | 系统代理、IE代理设置 |
| DNS | DNS服务器、DNS解析 |
| Isolation | 网络隔离、虚拟网络 |

## Requirements

- Windows 10/11 或 Windows Server 2016+
- PowerShell 5.1+
- 管理员权限（推荐）