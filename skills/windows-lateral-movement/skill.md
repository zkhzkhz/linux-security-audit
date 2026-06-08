# Windows Lateral Movement Scan

Windows 系统横向移动风险扫描模块，检测网络配置、凭据泄露和远程访问风险。

## Description

检测以下横向移动风险：
- **网络发现** - 开放端口、网络共享
- **凭据泄露** - 缓存凭据、保存密码
- **远程访问** - RDP、WinRM、SSH 配置
- **信任关系** - 域信任、本地管理员
- **会话信息** -活跃用户会话

## Usage

```powershell
# 运行扫描
.\skills\windows-lateral-movement\scripts\scan.ps1

# 指定输出目录
.\skills\windows-lateral-movement\scripts\scan.ps1 -Output C:\audit
```

## Output

| 文件 | 说明 |
|------|------|
| `result.json` | 结构化发现 |
| `scan.log` | 扫描日志 |

## Detection Categories

| 类别 | 检测项 |
|------|--------|
| Network | 开放端口、网络共享、防火墙状态 |
| Credentials | 缓存凭据、保存密码、Kerberos票证 |
| RemoteAccess | RDP配置、WinRM状态、SSH服务 |
| Sessions | 用户会话、登录历史 |
| Trust | 域信任、本地管理员成员 |

## Requirements

- Windows 10/11 或 Windows Server 2016+
- PowerShell 5.1+
- 管理员权限（推荐）