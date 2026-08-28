#!/usr/bin/env pwsh
<#
.SYNOPSIS
	Runs build and packaging steps for a full release artifact.
.PARAMETER Configuration
	Build configuration: Release or Debug. Defaults to Release.
.PARAMETER Version
	Optional version string (e.g. "1.2.3" or "v1.2.3"). When provided the
	output zip is named sftpplug-<Version>.zip inside dist\.
	Defaults to the current git tag, or empty (keeps sftpplug.zip).
#>
param(
	[string]$Configuration = "Release",
	[string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BuildScript = Join-Path $PSScriptRoot "build.ps1"
$LibSsh2BuildScript = Join-Path $PSScriptRoot "build-libssh2.ps1"
$PackScript  = Join-Path $PSScriptRoot "pack.ps1"

foreach ($script in @($LibSsh2BuildScript, $BuildScript, $PackScript)) {
	if (-not (Test-Path $script)) {
		Write-Error "Required script not found: $script"
		exit 1
	}
}

if (-not $Version) {
	$tag = git describe --tags --exact-match 2>$null
	if ($LASTEXITCODE -eq 0 -and $tag) { $Version = $tag }
}

Write-Host "=== Release: Build libssh2 ===" -ForegroundColor Cyan
& $LibSsh2BuildScript
if ($LASTEXITCODE -ne 0) {
	Write-Error "libssh2 build step failed."
	exit 1
}

Write-Host ""
Write-Host "=== Release: Build plugin ===" -ForegroundColor Cyan
& $BuildScript -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
	Write-Error "Build step failed."
	exit 1
}

Write-Host ""
Write-Host "=== Release: Pack ===" -ForegroundColor Cyan
& $PackScript -Version $Version
if ($LASTEXITCODE -ne 0) {
	Write-Error "Pack step failed."
	exit 1
}

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ZipName     = if ($Version) { "sftpplug-$Version.zip" } else { "sftpplug.zip" }
$FinalZip    = Join-Path $ProjectRoot "dist\$ZipName"
$ChecksumFile = "$FinalZip.sha256"
$Checksum = (Get-FileHash -Algorithm SHA256 -LiteralPath $FinalZip).Hash
"$Checksum  $ZipName" | Set-Content -LiteralPath $ChecksumFile -Encoding ascii

Write-Host ""
Write-Host "=== Release complete ===" -ForegroundColor Green
Write-Host "  $FinalZip"
Write-Host "  $ChecksumFile"
Write-Host "  SHA-256: $Checksum"

# Emit output path for CI
if ($env:GITHUB_OUTPUT) {
	"RELEASE_ZIP=$FinalZip" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
	"RELEASE_SHA256=$Checksum" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
