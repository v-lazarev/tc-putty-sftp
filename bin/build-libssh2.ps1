#!/usr/bin/env pwsh
<#
.SYNOPSIS
	Builds the pinned libssh2 submodule with the Windows CNG backend for x86 and x64.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SourceDir = Join-Path $ProjectRoot "third_party\libssh2"
$BuildRoot = Join-Path $ProjectRoot "build"
$RuntimeDir = Join-Path $ProjectRoot "runtime"

function Find-CMake {
	if ($env:CMAKE_EXE -and (Test-Path $env:CMAKE_EXE)) {
		return $env:CMAKE_EXE
	}
	$onPath = Get-Command cmake -ErrorAction SilentlyContinue
	if ($onPath) { return $onPath.Source }

	$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
	if (Test-Path $vswhere) {
		$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.CMake.Project `
			-property installationPath 2>$null | Select-Object -First 1
		if ($installation) {
			$candidate = Join-Path $installation "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
			if (Test-Path $candidate) { return $candidate }
		}
	}
	return $null
}

if (-not (Test-Path (Join-Path $SourceDir "CMakeLists.txt"))) {
	Write-Error "libssh2 submodule is missing. Run: git submodule update --init --recursive"
	exit 1
}

$CMake = Find-CMake
if (-not $CMake) {
	Write-Error "CMake from Visual Studio 2026 was not found."
	exit 1
}

function Build-Architecture([string]$Name, [string]$Platform, [string]$DestinationDirectory) {
	$buildDirectory = Join-Path $BuildRoot "libssh2-$Name"
	Write-Host ""
	Write-Host "=== Configuring libssh2 $Name ===" -ForegroundColor Cyan
	& $CMake -S $SourceDir -B $buildDirectory -G "Visual Studio 18 2026" -A $Platform `
		-DCRYPTO_BACKEND=WinCNG `
		-DBUILD_SHARED_LIBS=ON `
		-DBUILD_STATIC_LIBS=OFF `
		-DBUILD_EXAMPLES=OFF `
		-DBUILD_TESTING=OFF `
		-DLIBSSH2_DISABLE_INSTALL=ON `
		-DENABLE_ZLIB_COMPRESSION=OFF
	if ($LASTEXITCODE -ne 0) { throw "libssh2 $Name configuration failed." }

	Write-Host "=== Building libssh2 $Name ===" -ForegroundColor Cyan
	& $CMake --build $buildDirectory --config Release --target libssh2_shared --parallel
	if ($LASTEXITCODE -ne 0) { throw "libssh2 $Name build failed." }

	$sourceDll = Join-Path $buildDirectory "src\Release\libssh2.dll"
	if (-not (Test-Path $sourceDll)) { throw "Expected output was not produced: $sourceDll" }
	New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
	Copy-Item -LiteralPath $sourceDll -Destination (Join-Path $DestinationDirectory "libssh2.dll") -Force
}

Build-Architecture "x86" "Win32" $RuntimeDir
Build-Architecture "x64" "x64" (Join-Path $RuntimeDir "64")

Write-Host ""
Write-Host "=== libssh2 build complete ===" -ForegroundColor Green
Get-Item (Join-Path $RuntimeDir "libssh2.dll"), (Join-Path $RuntimeDir "64\libssh2.dll") |
	ForEach-Object { Write-Host ("  {0} ({1} bytes, {2})" -f $_.FullName, $_.Length, $_.VersionInfo.FileVersion) }
