#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs the offline native test suite and optional prevalidated network checks.
.PARAMETER PpkPath
    Optional unencrypted PPK v3 RSA or Ed25519 key used by local parser and network tests.
.PARAMETER Session
    Optional PuTTY display name for a local network integration test.
.PARAMETER User
    SSH username for the optional network integration test.
.PARAMETER HostPrevalidatedByPutty
    Confirms that the optional network target's host key was independently verified.
#>
param(
    [string]$PpkPath = "",
    [string]$Session = "",
    [string]$User = "",
    [switch]$HostPrevalidatedByPutty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BuildRoot = Join-Path $ProjectRoot "build"
$TestOutput = Join-Path $BuildRoot "tests"
$RuntimeRoot = Join-Path $BuildRoot ("test-runtime-" + [Guid]::NewGuid().ToString('N'))
$PluginRoot = Join-Path $RuntimeRoot "plugin"
$TestIni = Join-Path $RuntimeRoot "wincmd.ini"
$sessionDisplayName = "tc-putty-sftp CI " + [Guid]::NewGuid().ToString('N')
$sessionRegistryName = $sessionDisplayName.Replace(' ', '%20')
$sessionRegistryPath = "Software\SimonTatham\PuTTY\Sessions\$sessionRegistryName"
$sessionRegistryCreated = $false

function Invoke-TestExecutable {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Arguments = @()
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Test executable not found: $Path. Run bin\build-tests.ps1 first."
    }
    Write-Host "Running $([IO.Path]::GetFileName($Path))..." -ForegroundColor Cyan
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Path failed with exit code $LASTEXITCODE."
    }
}

try {
    New-Item -ItemType Directory -Force -Path (Join-Path $PluginRoot '64') | Out-Null
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'wfx\sftpplug.wfx') -Destination $PluginRoot
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'wfx\sftpplug.wfx64') -Destination $PluginRoot
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'runtime\libssh2.dll') -Destination $PluginRoot
    Copy-Item -LiteralPath (Join-Path $ProjectRoot 'runtime\64\libssh2.dll') -Destination (Join-Path $PluginRoot '64')
    ("[Configuration]{0}UseIniInProgramDir=7{0}" -f [Environment]::NewLine) |
        Set-Content -LiteralPath $TestIni -Encoding ascii

    $sessionKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sessionRegistryPath)
    if (-not $sessionKey) { throw "Unable to create the isolated PuTTY test session." }
    try {
        $sessionKey.SetValue('HostName', 'example.invalid', [Microsoft.Win32.RegistryValueKind]::String)
        $sessionKey.SetValue('Protocol', 'ssh', [Microsoft.Win32.RegistryValueKind]::String)
        $sessionKey.SetValue('PortNumber', 22, [Microsoft.Win32.RegistryValueKind]::DWord)
        $sessionKey.SetValue('UserName', 'ci-test', [Microsoft.Win32.RegistryValueKind]::String)
    }
    finally {
        $sessionKey.Dispose()
    }
    $sessionRegistryCreated = $true

    foreach ($suffix in @('x86', 'x64')) {
        Invoke-TestExecutable -Path (Join-Path $TestOutput "ppk-diagnostics-$suffix.exe")
        $smokeArguments = if ($PpkPath) { @($PpkPath) } else { @() }
        Invoke-TestExecutable -Path (Join-Path $TestOutput "smoke-$suffix.exe") -Arguments $smokeArguments
        $wfx = if ($suffix -eq 'x86') { Join-Path $PluginRoot 'sftpplug.wfx' } else { Join-Path $PluginRoot 'sftpplug.wfx64' }
        Invoke-TestExecutable -Path (Join-Path $TestOutput "wfx-root-$suffix.exe") -Arguments @($wfx, $TestIni, '--expect', $sessionDisplayName)
    }

    $networkValues = @(@($Session, $User, $PpkPath) | Where-Object { $_ })
    if ($networkValues.Count -gt 0 -or $HostPrevalidatedByPutty) {
        if (-not ($Session -and $User -and $PpkPath -and $HostPrevalidatedByPutty)) {
            throw "Network testing requires -Session, -User, -PpkPath, and -HostPrevalidatedByPutty together."
        }
        Invoke-TestExecutable -Path (Join-Path $TestOutput 'libssh2-ppk-integration-x64.exe') -Arguments @(
            (Join-Path $PluginRoot '64\libssh2.dll'), $Session, '--host-prevalidated-by-putty', $User, $PpkPath
        )
        Invoke-TestExecutable -Path (Join-Path $TestOutput 'wfx-root-x64.exe') -Arguments @(
            (Join-Path $PluginRoot 'sftpplug.wfx64'), $TestIni, '--connect-prevalidated', $Session, $User
        )
    }
}
finally {
    if ($sessionRegistryCreated) {
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sessionRegistryPath, $false)
    }
    $resolvedBuildRoot = [IO.Path]::GetFullPath($BuildRoot).TrimEnd('\') + '\'
    $resolvedRuntime = [IO.Path]::GetFullPath($RuntimeRoot)
    if ($resolvedRuntime.StartsWith($resolvedBuildRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedRuntime).StartsWith('test-runtime-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "All requested tests passed." -ForegroundColor Green
