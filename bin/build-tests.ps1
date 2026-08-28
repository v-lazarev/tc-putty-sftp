#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Builds the native smoke-test executables for x86 and x64.
#>
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$TestOutput = Join-Path $ProjectRoot "build\tests"
$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found. Install Visual Studio with Desktop development with C++."
}

$installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installationPath) {
    throw "A Visual Studio installation with the x86/x64 C++ tools was not found."
}

$vcvars = Join-Path $installationPath "VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path -LiteralPath $vcvars)) {
    throw "vcvarsall.bat was not found at $vcvars"
}

New-Item -ItemType Directory -Force -Path $TestOutput | Out-Null

function Invoke-Compiler {
    param(
        [Parameter(Mandatory)][string]$Architecture,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $objectDirectory = Join-Path $TestOutput "$Architecture-$Name"
    New-Item -ItemType Directory -Force -Path $objectDirectory | Out-Null
    $quotedVcvars = '"' + $vcvars + '"'
    $argumentLine = [string]::Join(' ', $Arguments)
    $command = 'call {0} {1} >nul && cl.exe /nologo /std:c++17 /utf-8 /EHsc /W4 /permissive- /DUNICODE /D_UNICODE /Fo:{2}\ {3}' -f $quotedVcvars, $Architecture, $objectDirectory, $argumentLine

    Write-Host "Building $Name ($Architecture)..." -ForegroundColor Cyan
    & $env:COMSPEC /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "The $Name $Architecture build failed with exit code $LASTEXITCODE."
    }
}

Push-Location $ProjectRoot
try {
    foreach ($architecture in @('x86', 'amd64')) {
        $suffix = if ($architecture -eq 'x86') { 'x86' } else { 'x64' }
        Invoke-Compiler -Architecture $architecture -Name 'smoke' -Arguments @(
            "/Fe:build\tests\smoke-$suffix.exe",
            'tests\smoke_tests.cpp',
            'ppk_v3_rsa.cpp',
            'putty_session_provider.cpp',
            'advapi32.lib',
            'bcrypt.lib',
            'crypt32.lib'
        )
        Invoke-Compiler -Architecture $architecture -Name 'wfx' -Arguments @(
            "/Fe:build\tests\wfx-root-$suffix.exe",
            'tests\wfx_root_smoke.cpp'
        )
        Invoke-Compiler -Architecture $architecture -Name 'ppk-diagnostics' -Arguments @(
            "/Fe:build\tests\ppk-diagnostics-$suffix.exe",
            'tests\ppk_diagnostics_tests.cpp',
            'ppk_v3_rsa.cpp',
            'bcrypt.lib',
            'crypt32.lib'
        )
    }

    Invoke-Compiler -Architecture 'amd64' -Name 'direct' -Arguments @(
        '/Ithird_party\libssh2\include',
        '/Fe:build\tests\libssh2-ppk-integration-x64.exe',
        'tests\libssh2_ppk_integration.cpp',
        'ppk_v3_rsa.cpp',
        'putty_session_provider.cpp',
        'advapi32.lib',
        'bcrypt.lib',
        'crypt32.lib',
        'ws2_32.lib'
    )
}
finally {
    Pop-Location
}

Write-Host "Native test executables are ready in $TestOutput" -ForegroundColor Green
