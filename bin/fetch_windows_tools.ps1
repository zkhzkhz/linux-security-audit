<#
.SYNOPSIS
    Windows Security Audit Tools Downloader

.DESCRIPTION
    Downloads Windows security auditing tools for the linux-security-audit project.
    Tools: WinPEAS, Seatbelt, SharpUp, Watson, Gitleaks, TruffleHog, Trivy

.PARAMETER Tools
    Specific tools to download (comma-separated). Default: all

.PARAMETER Force
    Force re-download even if tools exist

.PARAMETER Proxy
    Proxy URL for downloads

.EXAMPLE
    .\fetch_windows_tools.ps1
    .\fetch_windows_tools.ps1 -Tools winpeas,seatbelt
    .\fetch_windows_tools.ps1 -Force
#>

param(
    [string]$Tools = "all",
    [switch]$Force,
    [string]$Proxy
)

$ErrorActionPreference = "Stop"

# Tool definitions
$TOOL_DEFS = @{
    "winpeas" = @{
        Url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe"
        File = "winpeas.exe"
        Description = "Windows Privilege Escalation Awesome Script"
    }
    "seatbelt" = @{
        Url = "https://github.com/GhostPack/Seatbelt/releases/download/v1.1.0/Seatbelt.exe"
        File = "seatbelt.exe"
        Description = "Windows Security Enumeration Tool"
    }
    "sharpup" = @{
        Url = "https://github.com/GhostPack/SharpUp/releases/download/v1.0.0/SharpUp.exe"
        File = "sharpup.exe"
        Description = "Windows Privilege Escalation Audit Tool"
    }
    "watson" = @{
        Url = "https://github.com/rasta-mouse/Watson/releases/download/v0.1.0/Watson.exe"
        File = "watson.exe"
        Description = "Windows Kernel Vulnerability Scanner"
    }
    "gitleaks" = @{
        Url = "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_windows_x64.zip"
        File = "gitleaks.exe"
        Description = "Secret Scanner"
        Extract = $true
    }
    "trufflehog" = @{
        Url = "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.4/trufflehog_3.88.4_windows_x64.tar.gz"
        File = "trufflehog.exe"
        Description = "Secret Scanner"
        Extract = $true
    }
    "trivy" = @{
        Url = "https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_windows-64bit.zip"
        File = "trivy.exe"
        Description = "Container Security Scanner"
        Extract = $true
    }
}

# Setup directories
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinDir = Join-Path (Split-Path -Parent $ScriptDir) "windows"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Write-Host "[INFO] Created directory: $BinDir" -ForegroundColor Cyan
}

# Download function
function Download-Tool {
    param(
        [string]$Name,
        [hashtable]$Def
    )

    $TargetPath = Join-Path $BinDir $Def.File

    # Check if already exists
    if ((Test-Path $TargetPath) -and -not $Force) {
        Write-Host "[SKIP] $Name already exists: $TargetPath" -ForegroundColor Yellow
        return
    }

    Write-Host "[INFO] Downloading $Name ($($Def.Description))..." -ForegroundColor Cyan
    Write-Host "       URL: $($Def.Url)"

    try {
        $TempDir = Join-Path $env:TEMP "lsa-download-$(Get-Random)"
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

        $DownloadPath = Join-Path $TempDir (Split-Path $Def.Url -Leaf)

        # Download
        $WebParams = @{
            Uri = $Def.Url
            OutFile = $DownloadPath
            UseBasicParsing = $true
        }
        if ($Proxy) {
            $WebParams["Proxy"] = $Proxy
        }

        Invoke-WebRequest @WebParams

        # Extract if needed
        if ($Def.Extract) {
            Write-Host "[INFO] Extracting $Name..."

            if ($Def.Url -like "*.zip") {
                Expand-Archive -Path $DownloadPath -DestinationPath $TempDir -Force
            }
            elseif ($Def.Url -like "*.tar.gz" -or $Def.Url -like "*.tgz") {
                # Use tar (Windows 10+ has built-in tar)
                tar xzf $DownloadPath -C $TempDir 2>$null
            }

            # Find the executable
            $ExeFile = Get-ChildItem -Path $TempDir -Filter "*.exe" -Recurse | Select-Object -First 1
            if ($ExeFile) {
                Move-Item -Path $ExeFile.FullName -Destination $TargetPath -Force
            }
            else {
                # For gitleaks, the exe might have different name
                $AltExe = Join-Path $TempDir "gitleaks.exe"
                if (Test-Path $AltExe) {
                    Move-Item -Path $AltExe -Destination $TargetPath -Force
                }
                else {
                    Write-Host "[WARN] Could not find executable in archive for $Name" -ForegroundColor Yellow
                    return
                }
            }
        }
        else {
            Move-Item -Path $DownloadPath -Destination $TargetPath -Force
        }

        Write-Host "[OK] Downloaded: $TargetPath" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to download $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if (Test-Path $TempDir) {
            Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Main
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Security Audit Tools Downloader" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Determine which tools to download
$ToolsToDownload = if ($Tools -eq "all") {
    $TOOL_DEFS.Keys
}
else {
    $Tools -split ","
}

foreach ($Tool in $ToolsToDownload) {
    $Tool = $Tool.Trim().ToLower()
    if ($TOOL_DEFS.ContainsKey($Tool)) {
        Download-Tool -Name $Tool -Def $TOOL_DEFS[$Tool]
    }
    else {
        Write-Host "[WARN] Unknown tool: $Tool" -ForegroundColor Yellow
        Write-Host "       Available: $($TOOL_DEFS.Keys -join ', ')"
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Download Complete!" -ForegroundColor Green
Write-Host "Tools directory: $BinDir" -ForegroundColor Green
Write-Host ""

# List downloaded tools
Write-Host "Downloaded tools:" -ForegroundColor Cyan
Get-ChildItem -Path $BinDir -Filter "*.exe" | ForEach-Object {
    $Size = "{0:N0} KB" -f ($_.Length / 1KB)
    Write-Host "  - $($_.Name) ($Size)"
}
