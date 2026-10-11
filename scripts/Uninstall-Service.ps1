#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes the Child Safety Guard service and binaries.

.DESCRIPTION
  Run 'csg teardown' first (it asks for the guardian passphrase, turns enforcement off and removes the firewall rules).
  If rules are still present this script refuses to continue unless -Force is given, so the device is never
  left with orphaned block rules by accident. Configuration under %ProgramData%\ChildSafetyGuard is kept unless
  -PurgeData is given.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'ChildSafetyGuard'),
    [switch]$Force,
    [switch]$PurgeData
)

$ErrorActionPreference = 'Stop'
$serviceName = 'ChildSafetyGuard'

$rules = @(Get-NetFirewallRule -Group 'Child Safety Guard' -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) {
    if (-not $Force) {
        throw "$($rules.Count) firewall rule(s) created by Child Safety Guard are still present. Run 'csg teardown' first, or use -Force to remove them now."
    }
    $rules | Remove-NetFirewallRule
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    sc.exe delete $serviceName | Out-Null
}

if (Test-Path $InstallRoot) { Remove-Item -Recurse -Force $InstallRoot }
if ($PurgeData) {
    $data = Join-Path $env:ProgramData 'ChildSafetyGuard'
    if (Test-Path $data) { Remove-Item -Recurse -Force $data }
}
Write-Host 'Child Safety Guard removed.'
