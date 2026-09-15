[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmHost,

    [string]$VmUser = 'ubuntu',
    [int]$Port = 54321,
    [string]$KeyFile = "$env:USERPROFILE\.ssh\id_ed25519",
    [switch]$Install
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DestDir     = Join-Path $ProjectRoot 'data\raw'
$RemoteDir   = '/opt/cowrie/var/log/cowrie'

if ($Install) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" " +
               "-VmHost $VmHost -VmUser $VmUser -Port $Port -KeyFile `"$KeyFile`""
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
    $trigger  = New-ScheduledTaskTrigger -Daily -At 3am
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                    -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName 'Cowrie log backup' `
        -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "Tarea programada: 'Cowrie log backup', diaria a las 03:00."
    return
}

$target = Join-Path $DestDir (Get-Date -Format 'yyyy-MM-dd')
New-Item -ItemType Directory -Path $target -Force | Out-Null

& scp -P $Port -i $KeyFile -p -o 'StrictHostKeyChecking=accept-new' `
    "${VmUser}@${VmHost}:${RemoteDir}/cowrie.json*" $target
if ($LASTEXITCODE -ne 0) { throw "scp fallo con codigo $LASTEXITCODE." }

$files = Get-ChildItem $target -File
if ($files.Count -eq 0) { Write-Warning "Sin ficheros."; return }

$totalMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 2)
Write-Host "$($files.Count) ficheros, $totalMB MB, en $target"

$json = Join-Path $target 'cowrie.json'
if (Test-Path $json) {
    Write-Host "cowrie.json: $([System.IO.File]::ReadAllLines($json).Count) eventos"
}
