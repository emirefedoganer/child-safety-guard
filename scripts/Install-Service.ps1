#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs (or updates) the Child Safety Guard Windows service and guardian CLI.

.DESCRIPTION
  Copies the published binaries to %ProgramFiles%\ChildSafetyGuard (writable by administrators only), registers the
  Event Log source, and creates a visible Windows service that:
    - starts automatically with Windows, after the Base Filtering Engine and Windows Firewall services,
    - restarts itself after a crash (5 s, 30 s, 60 s),
    - runs as LocalSystem (required to manage Windows Firewall rules).
  The service does not hide itself: it appears in services.msc and Task Manager as "Child Safety Guard".

  Publish first (from the repository root):
    dotnet publish src/ChildSafetyGuard.Service -c Release -r win-x64 --self-contained false -o artifacts/service
    dotnet publish src/ChildSafetyGuard.Cli     -c Release -r win-x64 --self-contained false -o artifacts/cli
#>
[CmdletBinding()]
param(
    [string]$ServiceArtifacts = (Join-Path $PSScriptRoot '..\artifacts\service'),
    [string]$CliArtifacts     = (Join-Path $PSScriptRoot '..\artifacts\cli'),
    [string]$InstallRoot      = (Join-Path $env:ProgramFiles 'ChildSafetyGuard')
)

$ErrorActionPreference = 'Stop'
$serviceName = 'ChildSafetyGuard'

foreach ($path in @($ServiceArtifacts, $CliArtifacts)) {
    if (-not (Test-Path $path)) { throw "Published files not found at '$path'. Run dotnet publish first (see script help)." }
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host 'Stopping the existing service...'
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

$serviceDir = Join-Path $InstallRoot 'service'
$cliDir     = Join-Path $InstallRoot 'cli'
New-Item -ItemType Directory -Force -Path $serviceDir, $cliDir | Out-Null
Copy-Item -Path (Join-Path $ServiceArtifacts '*') -Destination $serviceDir -Recurse -Force
Copy-Item -Path (Join-Path $CliArtifacts '*')     -Destination $cliDir     -Recurse -Force

if (-not [System.Diagnostics.EventLog]::SourceExists($serviceName)) {
    New-EventLog -LogName Application -Source $serviceName
}

$exe = Join-Path $serviceDir 'ChildSafetyGuard.Service.exe'
if (-not $existing) {
    sc.exe create $serviceName binPath= "`"$exe`"" start= auto obj= LocalSystem DisplayName= "Child Safety Guard" depend= BFE/MpsSvc | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE" }
}
sc.exe description $serviceName "Guardian-managed parental controls: keeps the configured Windows Firewall rules in place and reports network configuration changes. Transparent and local-only." | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null

Start-Service -Name $serviceName
Write-Host ''
Write-Host "Installed. Service status: $((Get-Service $serviceName).Status)"
Write-Host "Guardian tool: $(Join-Path $cliDir 'csg.exe')   (run it from an elevated prompt; start with 'csg setup')"
