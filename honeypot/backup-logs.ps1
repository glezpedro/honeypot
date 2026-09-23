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
$LogFile     = Join-Path $DestDir 'backup.log'
$RemoteDir   = '/opt/cowrie/var/log/cowrie'

function Write-Trace([string]$level, [string]$message) {
    $line = "{0}  {1,-5}  {2}" -f (Get-Date -Format 's'), $level, $message
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    Add-Content -Path $LogFile -Value $line -Encoding utf8
    Write-Host $line
}

if ($Install) {
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" " +
               "-VmHost $VmHost -VmUser $VmUser -Port $Port -KeyFile `"$KeyFile`""
    $action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
    $trigger  = New-ScheduledTaskTrigger -Daily -At 3am
    # Reintentos: los fallos observados fueron transitorios y pasaron inadvertidos.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                    -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
                    -RestartCount 4 -RestartInterval (New-TimeSpan -Minutes 20)
    Register-ScheduledTask -TaskName 'Cowrie log backup' `
        -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Trace 'INFO' "tarea programada a diario a las 03:00 con 4 reintentos"
    return
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("cowrie-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    & scp -P $Port -i $KeyFile -p -o 'StrictHostKeyChecking=accept-new' `
        -o 'ConnectTimeout=30' -o 'BatchMode=yes' `
        "${VmUser}@${VmHost}:${RemoteDir}/cowrie.json*" $staging
    $scpExit = $LASTEXITCODE
} catch {
    $scpExit = -1
}

$files = @(Get-ChildItem $staging -File -ErrorAction SilentlyContinue)

if ($scpExit -ne 0 -or $files.Count -eq 0) {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    Write-Trace 'ERROR' "sin descarga desde ${VmUser}@${VmHost}:${Port} (scp=$scpExit, ficheros=$($files.Count))"
    exit 1
}

$target = Join-Path $DestDir (Get-Date -Format 'yyyy-MM-dd')
New-Item -ItemType Directory -Path $target -Force | Out-Null
Move-Item (Join-Path $staging '*') $target -Force
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue

$live = Join-Path $target 'cowrie.json'
$events = if (Test-Path $live) { [System.IO.File]::ReadAllLines($live).Count } else { 0 }
$totalMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 2)

if ($events -eq 0) {
    Write-Trace 'WARN' "$($files.Count) ficheros, $totalMB MB, pero cowrie.json esta vacio: revisa el honeypot"
    exit 2
}

Write-Trace 'OK' "$($files.Count) ficheros, $totalMB MB, cowrie.json con $events eventos"
