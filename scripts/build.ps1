<#
    build.ps1 — cross-compile go-data-server to a static Linux binary.

        powershell -ExecutionPolicy Bypass -File scripts\build.ps1

    Output: dist\go-data-server-linux-amd64. Edit $arch for an ARM VPS ("arm64").
    Session-only env: the Go build cache is kept under .cache\ (C: has no room for it).
#>

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $root 'dist'
$arch = 'amd64'

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "'go' is not on PATH. Install Go from https://go.dev/dl/ then re-run."
}

$env:GOCACHE = Join-Path $root '.cache\go-build'
$env:GOOS = 'linux'
$env:GOARCH = $arch
$env:CGO_ENABLED = '0'

New-Item -ItemType Directory -Force $out | Out-Null
$bin = Join-Path $out "go-data-server-linux-$arch"

Push-Location $root
try {
    & go build -trimpath -ldflags '-s -w' -o $bin .
    if ($LASTEXITCODE -ne 0) { throw "go build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

$size = [math]::Round((Get-Item $bin).Length / 1MB, 1)
Write-Host "built $bin ($size MB)"
