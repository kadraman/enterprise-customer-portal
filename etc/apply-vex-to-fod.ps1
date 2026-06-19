<#
Maps a CycloneDX VEX verdict file to FoD issue audit updates.

Default behavior is dry-run: prints the exact fcli command it would execute.
Use -Apply to execute the update.

Examples:
  pwsh ./etc/apply-vex-to-fod.ps1 -Release "Enterprise Customer Portal:main-backend" -VexFile "./vex/IMPACT_CVE_2025_31651.vex.json" -IssueIds "12345,67890"

  pwsh ./etc/apply-vex-to-fod.ps1 -Release "Enterprise Customer Portal:main-backend" -VexFile "./vex/IMPACT_CVE_2025_31651.vex.json" -IssueIds "12345,67890" -Apply
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Release,

    [Parameter(Mandatory = $true)]
    [string] $VexFile,

    [Parameter(Mandatory = $true)]
    [string] $IssueIds,

    [Parameter(Mandatory = $false)]
    [switch] $Apply,

    [Parameter(Mandatory = $false)]
    [string] $FodSession = "default"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $VexFile)) {
    throw "VEX file not found: $VexFile"
}

$json = Get-Content -LiteralPath $VexFile -Raw | ConvertFrom-Json
if (-not $json.vulnerabilities -or $json.vulnerabilities.Count -eq 0) {
    throw "No vulnerabilities[] entries found in VEX file: $VexFile"
}

$vuln = $json.vulnerabilities[0]
$cveId = [string]$vuln.id
$state = [string]$vuln.analysis.state
$justification = [string]$vuln.analysis.justification
$detail = [string]$vuln.analysis.detail

# Conservative mapping for FoD auditor status.
# We auto-map only states that are typically safe for audit automation.
switch ($state) {
    "not_affected" { $auditorStatus = "Not an Issue" }
    "false_positive" { $auditorStatus = "Not an Issue" }
    "in_triage" { $auditorStatus = "Suspicious" }
    default {
        throw "VEX state '$state' is not auto-mapped by this script. Supported: not_affected, false_positive, in_triage."
    }
}

$mdCompanion = [System.IO.Path]::ChangeExtension($VexFile, ".md")
$mdHint = if (Test-Path -LiteralPath $mdCompanion) { " Report: $mdCompanion" } else { "" }

$comment = @(
    "VEX decision applied.",
    "ID: $cveId",
    "State: $state",
    ($(if ([string]::IsNullOrWhiteSpace($justification)) { "" } else { "Justification: $justification" })),
    ($(if ([string]::IsNullOrWhiteSpace($detail)) { "" } else { "Detail: $detail" })),
    "$mdHint"
) -ne ""

$commentText = ($comment -join " ").Trim()
$escapedComment = $commentText.Replace("'", "''")

$command = "fcli fod issue update --fod-session `"$FodSession`" --release `"$Release`" --issue-ids `"$IssueIds`" --auditor-status `"$auditorStatus`" --comment '$escapedComment' --include-all false"

Write-Host "Using FoD session: $FodSession"
Write-Host "Mapped $cveId ($state) -> auditor status '$auditorStatus'"
Write-Host ""
Write-Host "Command:"
Write-Host $command
Write-Host ""

if (-not $Apply) {
    Write-Host "Dry-run only. Re-run with -Apply to execute."
    exit 0
}

if (-not (Get-Command fcli -ErrorAction SilentlyContinue)) {
    throw "fcli command not found in PATH. Install fcli or run in an environment where fcli is available."
}

Write-Host "Executing update..."
Invoke-Expression $command
Write-Host "Update complete."
