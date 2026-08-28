#!/usr/bin/env pwsh
<#
.SYNOPSIS
	Builds sftpplug for both Win32 (Release) and x64 (Release) configurations.
.PARAMETER Configuration
	Build configuration: Release or Debug. Defaults to Release.
#>
param(
	[string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Project     = Join-Path $ProjectRoot "sftpplug.vcxproj"

function Find-MSBuild {
	# 1. Explicit override. This must win over PATH when several Visual Studio
	#    toolsets are installed side by side.
	if ($env:MSBUILD_EXE -and (Test-Path $env:MSBUILD_EXE)) {
		return $env:MSBUILD_EXE
	}

	# 2. Already on PATH (CI/CD agents: GitHub Actions, Azure DevOps, etc.)
	$onPath = Get-Command msbuild -ErrorAction SilentlyContinue
	if ($onPath) { return $onPath.Source }

	# 3. vswhere (local Visual Studio installations)
	$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
	if (Test-Path $vswhere) {
		$found = & $vswhere -latest -requires Microsoft.Component.MSBuild `
							-find "MSBuild\**\Bin\MSBuild.exe" 2>$null |
				 Select-Object -First 1
		if ($found -and (Test-Path $found)) { return $found }
	}

	return $null
}

$MSBuild = Find-MSBuild
if (-not $MSBuild) {
	Write-Error "MSBuild not found. Add it to PATH, install Visual Studio, or set MSBUILD_EXE."
	exit 1
}

Write-Host "MSBuild : $MSBuild" -ForegroundColor DarkGray

Write-Host ""
Write-Host "=== Building Win32 | $Configuration ===" -ForegroundColor Cyan
& $MSBuild $Project /t:Rebuild /p:Configuration=$Configuration /p:Platform=Win32 /m /nologo /v:minimal
if ($LASTEXITCODE -ne 0) {
	Write-Error "Win32 build failed."
	exit 1
}

Write-Host ""
Write-Host "=== Building x64 | $Configuration ===" -ForegroundColor Cyan
& $MSBuild $Project /t:Rebuild /p:Configuration=$Configuration /p:Platform=x64 /m /nologo /v:minimal
if ($LASTEXITCODE -ne 0) {
	Write-Error "x64 build failed."
	exit 1
}

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Green
Write-Host "  wfx\sftpplug.wfx    (32-bit)"
Write-Host "  wfx\sftpplug.wfx64  (64-bit)"
