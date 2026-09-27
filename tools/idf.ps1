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

$ExpectedIdfVersion = '6.0.2'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = Join-Path $RepoRoot 'build\idf'
$SdkConfig = Join-Path $RepoRoot 'build\sdkconfig'
$SdkConfigDefaults = Join-Path $RepoRoot 'sdkconfig.defaults'

if ([string]::IsNullOrWhiteSpace($IdfPath)) {
    $IdfPath = 'E:\Espressif\esp-idf-v6.0.2'
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

function Invoke-CheckedNative {
    param([string]$Command, [string[]]$CommandArgs)
    & $Command @CommandArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$IdfVersionOutput = (Invoke-CheckedNative 'idf.py' @('--version') 2>&1) -join "`n"
if ($IdfVersionOutput -notmatch [regex]::Escape($ExpectedIdfVersion)) {
    throw "ESP-IDF $ExpectedIdfVersion is required; got: $IdfVersionOutput"
}

$IdfArgs = @('-B', $BuildDir, '-D', "SDKCONFIG=$SdkConfig",
    '-D', "SDKCONFIG_DEFAULTS=$SdkConfigDefaults")

function Update-RequiredConfig {
    $lines = @()
    if (Test-Path -LiteralPath $SdkConfig -PathType Leaf) {
        $lines = @(Get-Content -LiteralPath $SdkConfig)
    }
    if (($lines -ccontains 'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y') -and
        ($lines -ccontains 'CONFIG_MBEDTLS_HAVE_TIME_DATE=y')) {
        return
    }
    Write-Host "Regenerating $SdkConfig from ESP-IDF defaults (old file is preserved as .old)"
    Invoke-CheckedNative 'idf.py' ($IdfArgs + @('set-target', 'esp32c3'))
}

function Test-BuildBaseline {
    Invoke-CheckedNative 'python' @((Join-Path $RepoRoot 'tools/check_idf_baseline.py'),
        '--build-dir', $BuildDir)
}

switch ($Action) {
    'build' {
        Update-RequiredConfig
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('reconfigure'))
        if ($Jobs -le 0) {
            $Jobs = [int]$env:NUMBER_OF_PROCESSORS
            if ($Jobs -le 0) { $Jobs = 4 }
        }
        Invoke-CheckedNative 'ninja' @('-C', $BuildDir, '-j', $Jobs)
        Test-BuildBaseline
    }
    'flash' {
        Test-BuildBaseline
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('-p', $Port, 'flash'))
    }
    'monitor' {
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('-p', $Port, 'monitor'))
    }
    'reconfigure' {
        Update-RequiredConfig
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('reconfigure'))
    }
    'clean' {
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('clean'))
    }
    'fullclean' {
        Invoke-CheckedNative 'idf.py' ($IdfArgs + @('fullclean'))
    }
}
