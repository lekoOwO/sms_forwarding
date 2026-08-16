[CmdletBinding()]
param(
    [ValidateSet('build', 'flash', 'monitor', 'reconfigure', 'clean', 'fullclean')]
    [string]$Action = 'build',
    [string]$Port = 'COM5',
    [string]$IdfPath = $env:IDF_PATH,
    [string]$IdfToolsPath = $env:IDF_TOOLS_PATH,
    [int]$Jobs = 0
)

$ErrorActionPreference = 'Stop'

$ExpectedIdfVersion = '5.5.4'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = Join-Path $RepoRoot 'build\idf'
$SdkConfig = Join-Path $RepoRoot 'build\sdkconfig'

if ([string]::IsNullOrWhiteSpace($IdfPath)) {
    $IdfPath = 'E:\Espressif\esp-idf-v5.5.4'
}
if ([string]::IsNullOrWhiteSpace($IdfToolsPath)) {
    $IdfToolsPath = 'E:\Espressif\.espressif'
}

$ExportScript = Join-Path $IdfPath 'export.ps1'
if (-not (Test-Path -LiteralPath $ExportScript)) {
    throw "ESP-IDF export script not found: $ExportScript"
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$env:IDF_TOOLS_PATH = $IdfToolsPath
. $ExportScript

$IdfVersionOutput = (& idf.py --version 2>&1) -join "`n"
if ($IdfVersionOutput -notmatch [regex]::Escape($ExpectedIdfVersion)) {
    throw "ESP-IDF $ExpectedIdfVersion is required; got: $IdfVersionOutput"
}

$IdfArgs = @('-B', $BuildDir, '-D', "SDKCONFIG=$SdkConfig")

switch ($Action) {
    'build' {
        idf.py @IdfArgs reconfigure
        if ($Jobs -le 0) {
            $Jobs = [int]$env:NUMBER_OF_PROCESSORS
            if ($Jobs -le 0) { $Jobs = 4 }
        }
        ninja -C $BuildDir -j $Jobs
    }
    'flash' {
        idf.py @IdfArgs -p $Port flash
    }
    'monitor' {
        idf.py @IdfArgs -p $Port monitor
    }
    'reconfigure' {
        idf.py @IdfArgs reconfigure
    }
    'clean' {
        idf.py @IdfArgs clean
    }
    'fullclean' {
        idf.py @IdfArgs fullclean
    }
}
