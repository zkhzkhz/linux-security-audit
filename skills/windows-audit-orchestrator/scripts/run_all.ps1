<#
.SYNOPSIS
    Windows Security Audit Orchestrator

.DESCRIPTION
    Runs all Windows security audit modules and generates a summary report.

.PARAMETER Output
    Base output directory for all results

.PARAMETER Only
    Comma-separated list of modules to run (default: all)
    Options: privesc, sensitive, lateral, egress

.PARAMETER Timeout
    Timeout per module in seconds (default: 600)

.PARAMETER SkipToolsCheck
    Skip the tools availability check

.EXAMPLE
    .\run_all.ps1
    .\run_all.ps1 -Only privesc
    .\run_all.ps1 -Output C:\audit -Timeout 900
#>

param(
    [string]$Output = "",
    [string]$Only = "",
    [int]$Timeout = 600,
    [switch]$SkipToolsCheck
)

$ErrorActionPreference = "Continue"

# Setup paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillDir = Split-Path -Parent $ScriptDir
$LSARoot = Split-Path -Parent (Split-Path -Parent $SkillDir)
$BinDir = Join-Path $LSARoot "bin\windows"

# Create output directory
if ($Output -eq "") {
    $HostName = $env:COMPUTERNAME.ToLower()
    $TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Output = Join-Path $LSARoot "reports\$HostName-$TimeStamp"
}

if (-not (Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output -Force | Out-Null
}

$LogFile = Join-Path $Output "orchestrator.log"
$SummaryJson = Join-Path $Output "summary.json"
$SummaryMd = Join-Path $Output "summary.md"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $Color = switch ($Level) {
        "INFO"  { "Cyan" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "OK"    { "Green" }
        default { "White" }
    }
    $Line = "[$Level $TimeStamp] $Message"
    Write-Host $Line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $Line
}

function Test-Tools {
    Write-Log "Checking tool availability..."

    $Tools = @("winpeas", "seatbelt", "sharpup", "watson", "gitleaks")
    $Missing = @()

    foreach ($Tool in $Tools) {
        $ToolPath = Join-Path $BinDir "$Tool.exe"
        if (-not (Test-Path $ToolPath)) {
            $Missing += $Tool
        }
    }

    if ($Missing.Count -gt 0) {
        Write-Log "Missing tools: $($Missing -join ', ')" "WARN"
        Write-Log "Run .\bin\fetch_windows_tools.ps1 to download them" "WARN"
        return $false
    }

    Write-Log "All tools available" "OK"
    return $true
}

function Run-Module {
    param([string]$Module, [string]$Script)

    Write-Log "Running $Module..."

    $ModuleOutput = Join-Path $Output $Module

    try {
        $Process = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-ExecutionPolicy", "Bypass", "-File", $Script, "-Output", $ModuleOutput, "-Timeout", $Timeout `
            -NoNewWindow -PassThru -RedirectStandardOutput (Join-Path $Output "${Module}_stdout.txt") `
            -RedirectStandardError (Join-Path $Output "${Module}_stderr.txt")

        if (-not $Process.WaitForExit($Timeout * 2 * 1000)) {
            $Process.Kill()
            Write-Log "$Module timed out" "WARN"
            return @{status = "timeout"; counts = {}; findings = @()}
        }

        # Read result
        $ResultFile = Join-Path $ModuleOutput "result.json"
        if (-not (Test-Path $ResultFile)) {
            $ResultFile = Join-Path $ModuleOutput "host.json"
        }

        if (Test-Path $ResultFile) {
            $Result = Get-Content $ResultFile -Raw | ConvertFrom-Json
            Write-Log "$Module completed: $($Result.status)" "OK"
            return $Result
        }

        Write-Log "$Module output not found" "WARN"
        return @{status = "error"; counts = {}; findings = @()}
    }
    catch {
        Write-Log "$Module failed: $($_.Exception.Message)" "ERROR"
        return @{status = "error"; counts = {}; findings = @()}
    }
}

function New-SummaryReport {
    param([hashtable]$Results)

    # Count totals
    $TotalCounts = @{critical = 0; high = 0; medium = 0; low = 0}
    foreach ($Module in $Results.Keys) {
        $Counts = $Results[$Module].counts
        if ($Counts) {
            foreach ($Key in @("critical", "high", "medium", "low")) {
                if ($Counts.$Key) {
                    $TotalCounts[$Key] += $Counts.$Key
                }
            }
        }
    }

    # Determine overall status
    $OverallStatus = if ($TotalCounts.critical -gt 0) { "critical" }
                      elseif ($TotalCounts.high -gt 0) { "warn" }
                      else { "ok" }

    # Write JSON summary
    $Summary = @{
        run_dir = $Output
        generated_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        host = $env:COMPUTERNAME
        arch = "amd64"
        modules = @()
    }

    foreach ($Module in $Results.Keys) {
        $Summary.modules += @{
            module = $Module
            status = $Results[$Module].status
            summary = $Results[$Module].summary
            counts = $Results[$Module].counts
        }
    }

    $Summary | ConvertTo-Json -Depth 10 | Set-Content $SummaryJson

    # Write Markdown summary
    $Md = @"
# Windows Security Audit Report

- Run dir: `\$Output`
- Generated: $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
- Host: `\$($env:COMPUTERNAME)` (amd64)

## Module summary

| Module | Status | Summary |
|---|---|---|
"@

    foreach ($Module in $Results.Keys) {
        $Status = $Results[$Module].status
        $SummaryText = $Results[$Module].summary
        $Md += "`n| $Module | $Status | $SummaryText |"
    }

    $Md += @"

## Overall Status: $OverallStatus

- Critical: $($TotalCounts.critical)
- High: $($TotalCounts.high)
- Medium: $($TotalCounts.medium)
- Low: $($TotalCounts.low)
"@

    # Add top findings per module
    foreach ($Module in $Results.Keys) {
        $Findings = $Results[$Module].findings
        if ($Findings -and @($Findings).Count -gt 0) {
            $Md += "`n`n## $Module findings`n"
            $Count = 0
            foreach ($f in @($Findings | Where-Object { -not $_.is_likely_fp } | Select-Object -First 10)) {
                $Md += "`n- [$($f.severity)] **$($f.title)** — `$($f.where)`"
                $Count++
            }
        }
    }

    Set-Content -Path $SummaryMd -Value $Md

    Write-Log "Summary written to $SummaryMd" "OK"
}

# Main
Write-Log "=========================================="
Write-Log "Windows Security Audit Orchestrator"
Write-Log "=========================================="
Write-Log "Output: $Output"
Write-Log "Timeout: ${Timeout}s"

# Check tools
if (-not $SkipToolsCheck -and -not (Test-Tools)) {
    Write-Log "Some tools are missing. Install them first." "WARN"
}

# Determine which modules to run
$ModulesToRun = if ($Only -ne "") {
    $Only -split "," | ForEach-Object { $_.Trim().ToLower() }
}
else {
    @("privesc", "sensitive", "lateral", "egress")
}

$Results = @{}

# Run modules
foreach ($Module in $ModulesToRun) {
    switch ($Module) {
        "privesc" {
            $Script = Join-Path $LSARoot "skills\windows-privesc-check\scripts\run.ps1"
            $Results["windows-privesc-check"] = Run-Module -Module "windows-privesc-check" -Script $Script
        }
        "sensitive" {
            $Script = Join-Path $LSARoot "skills\windows-sensitive-scan\scripts\scan.ps1"
            $Results["windows-sensitive-scan"] = Run-Module -Module "windows-sensitive-scan" -Script $Script
        }
        "lateral" {
            $Script = Join-Path $LSARoot "skills\windows-lateral-movement\scripts\scan.ps1"
            $Results["windows-lateral-movement"] = Run-Module -Module "windows-lateral-movement" -Script $Script
        }
        "egress" {
            $Script = Join-Path $LSARoot "skills\windows-egress-control\scripts\audit.ps1"
            $Results["windows-egress-control"] = Run-Module -Module "windows-egress-control" -Script $Script
        }
        default {
            Write-Log "Unknown module: $Module" "WARN"
        }
    }
}

# Generate summary
Write-Log "Generating summary report..."
New-SummaryReport -Results $Results

Write-Log "=========================================="
Write-Log "Audit Complete"
Write-Log "=========================================="
Write-Log "Summary: $SummaryMd"
Write-Log "OK" "OK"

Write-Output $SummaryMd
