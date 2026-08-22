# Install aw-remote-host on Windows: downloads a pinned release binary from
# GitHub Releases, verifies its SHA-256 checksum against the release's
# published checksums.txt, and installs it to %LOCALAPPDATA%\Programs\aw-remote-host.
#
# The PowerShell twin of install.sh — same contract, same verification, same
# transparency guarantee. See README.md.
#
# Usage:
#   irm https://raw.githubusercontent.com/tekflox/aw-remote-host/main/install.ps1 | iex
#   $env:AW_REMOTE_HOST_VERSION='v0.1.0'; irm .../install.ps1 | iex   # pin a version
#
# NOTE: a Windows host is a LEAN link — it registers the machine and serves
# remote exec / file transfer. It does NOT run a workspace: that is a Linux
# container image, so --with-workspace has nothing to install here. Use WSL2
# if you want the full workspace runtime on this machine.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = 'tekflox/aw-remote-host'
$version = if ($env:AW_REMOTE_HOST_VERSION) { $env:AW_REMOTE_HOST_VERSION } else { 'latest' }
$installDir = if ($env:AW_REMOTE_HOST_INSTALL_DIR) {
    $env:AW_REMOTE_HOST_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Programs\aw-remote-host'
}

# TLS 1.2 is not the default on Windows PowerShell 5.1, which is still what a
# stock Windows 10/11 box runs — without this, every github.com call fails
# with an unhelpful "could not create SSL/TLS secure channel".
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($version -eq 'latest') {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
    $version = $release.tag_name
    if (-not $version) {
        throw 'aw-remote-host: could not resolve latest release'
    }
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "aw-remote-host: unsupported architecture $env:PROCESSOR_ARCHITECTURE" }
}

$asset = "aw-remote-host_${version}_windows_${arch}.zip"
$baseUrl = "https://github.com/$repo/releases/download/$version"
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("aw-remote-host-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    Write-Host "aw-remote-host: downloading $asset ($version)"
    $zipPath = Join-Path $tmpDir $asset
    Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $zipPath -UseBasicParsing
    $sumsPath = Join-Path $tmpDir 'checksums.txt'
    Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $sumsPath -UseBasicParsing

    Write-Host 'aw-remote-host: verifying checksum'
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    # checksums.txt is sha256sum output: "<hash>  <filename>".
    $line = Get-Content $sumsPath | Where-Object { $_ -match "\s\*?$([Regex]::Escape($asset))$" }
    if (-not $line) {
        throw "aw-remote-host: $asset not listed in checksums.txt"
    }
    $expected = ($line -split '\s+')[0].ToLower()
    if ($actual -ne $expected) {
        throw "aw-remote-host: checksum mismatch for $asset (expected $expected, got $actual)"
    }

    Write-Host "aw-remote-host: installing to $installDir"
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    # -Force so re-running over an existing install overwrites rather than
    # prompting — this script has to be safe to pipe into iex unattended.
    Expand-Archive -Path $zipPath -DestinationPath $installDir -Force

    $exe = Join-Path $installDir 'aw-remote-host.exe'
    Write-Host "aw-remote-host: installed $(& $exe version)"

    # Add to the USER PATH (not the machine one — this install needs no
    # admin rights and must not require any).
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
        Write-Host "note: added $installDir to your user PATH — open a NEW terminal for it to take effect"
    }
} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
