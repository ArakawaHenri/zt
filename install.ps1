# One-line installer for zt on Windows (amd64 / arm64).
# Usage: irm https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.ps1 | iex
$ErrorActionPreference = 'Stop'

function Install-Zt {
    # Ensure TLS 1.2+ on Windows PowerShell 5.1.
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        # PowerShell 7+ manages TLS automatically.
    }

    $repo = if ($env:ZT_REPO) { $env:ZT_REPO } else { 'ArakawaHenri/zt' }
    $apiBase = if ($env:ZT_API_BASE) { $env:ZT_API_BASE } else { 'https://api.github.com' }
    $apiBase = $apiBase.TrimEnd('/')
    $downloadBase = if ($env:ZT_DOWNLOAD_BASE) { $env:ZT_DOWNLOAD_BASE } else { 'https://github.com' }
    $downloadBase = $downloadBase.TrimEnd('/')
    $requestedVersion = $env:ZT_VERSION
    $installDir = if ($env:ZT_INSTALL_DIR) {
        $env:ZT_INSTALL_DIR
    } else {
        Join-Path $env:LOCALAPPDATA 'zt\bin'
    }

    # 1. Detect Windows CPU architecture.
    $rawArch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) {
        $rawArch = $env:PROCESSOR_ARCHITEW6432
    }
    switch ($rawArch.ToUpperInvariant()) {
        'AMD64' { $arch = 'amd64' }
        'X64'   { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default {
            throw "Unsupported Windows architecture '$rawArch' (supported: amd64, arm64)."
        }
    }

    # 2. Verify a real Python 3.9+ interpreter (avoiding the Microsoft Store stub).
    # Keep the inline snippet free of quotes so Windows PowerShell 5.1 passes it verbatim.
    $pyCheck = 'import sys; print(sys.version_info[0], sys.version_info[1], sys.version_info[2], sep=chr(46)); raise SystemExit(0 if sys.version_info >= (3, 9) else 2)'
    $pythonDesc = $null
    $candidates = @(
        @{ Exe = 'py';      Prefix = @('-3') },
        @{ Exe = 'python';  Prefix = @() },
        @{ Exe = 'python3'; Prefix = @() }
    )
    foreach ($cand in $candidates) {
        $cmd = Get-Command $cand.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $pyArgs = @($cand.Prefix) + @('-c', $pyCheck)
            $out = & $cmd.Source @pyArgs 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $verText = ([string]($out | Select-Object -First 1)).Trim()
                $pythonDesc = "$($cand.Exe) ($verText)"
                break
            }
        } catch {
            continue
        } finally {
            $ErrorActionPreference = $prevEap
        }
    }
    if (-not $pythonDesc) {
        Write-Host ''
        Write-Host 'zt requires Python 3.9 or later on Windows, but no compatible Python was found.' -ForegroundColor Red
        Write-Host 'Install Python first, then re-run this installer:' -ForegroundColor Yellow
        Write-Host '  winget install Python.Python.3.12'
        Write-Host '  or download from https://www.python.org/downloads/'
        Write-Host ''
        throw 'Python 3.9+ is required.'
    }

    $headers = @{ 'User-Agent' = 'zt-installer' }
    $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ('zt-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        # 3. Resolve latest stable release (or ZT_VERSION).
        if ($requestedVersion) {
            $tag = if ($requestedVersion.StartsWith('v')) { $requestedVersion } else { "v$requestedVersion" }
            $pyzUrl = "$downloadBase/$repo/releases/download/$tag/zt.pyz"
            $sumsUrl = "$downloadBase/$repo/releases/download/$tag/SHA256SUMS"
        } else {
            Write-Host "Checking latest stable release for Windows ($arch)..."
            $release = Invoke-RestMethod -Uri "$apiBase/repos/$repo/releases/latest" -Headers $headers
            if ($release.draft -or $release.prerelease) {
                throw 'Latest GitHub release is not a stable release.'
            }
            $tag = [string]$release.tag_name
            $pyzAsset = $release.assets | Where-Object { $_.name -eq 'zt.pyz' } | Select-Object -First 1
            $sumsAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS' } | Select-Object -First 1
            if (-not $tag -or -not $pyzAsset -or -not $sumsAsset) {
                throw 'Release metadata is missing zt.pyz or SHA256SUMS assets.'
            }
            $pyzUrl = [string]$pyzAsset.browser_download_url
            $sumsUrl = [string]$sumsAsset.browser_download_url
        }

        # 4. Download zt.pyz and SHA256SUMS, then verify SHA256.
        Write-Host "Downloading zt $tag (Windows/$arch, using $pythonDesc)..."
        $pyzTmp = Join-Path $tmpDir 'zt.pyz'
        $sumsTmp = Join-Path $tmpDir 'SHA256SUMS'
        Invoke-WebRequest -Uri $pyzUrl -OutFile $pyzTmp -Headers $headers -UseBasicParsing
        Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsTmp -Headers $headers -UseBasicParsing

        $expected = $null
        foreach ($line in (Get-Content -Path $sumsTmp -Encoding UTF8)) {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Length -ge 2) {
                $fname = $parts[$parts.Length - 1].TrimStart('*', '.', '/')
                if ($fname -eq 'zt.pyz') {
                    $expected = $parts[0].ToLowerInvariant()
                    break
                }
            }
        }
        if (-not $expected) {
            throw 'SHA256SUMS does not contain an entry for zt.pyz.'
        }
        $actual = (Get-FileHash -Path $pyzTmp -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA256 mismatch for zt.pyz (expected $expected, got $actual)."
        }

        # 5. Install zt.pyz and ExecutionPolicy-independent zt.cmd launcher.
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        $pyzDest = Join-Path $installDir 'zt.pyz'
        $cmdDest = Join-Path $installDir 'zt.cmd'
        Copy-Item -Path $pyzTmp -Destination $pyzDest -Force

        $cmdBody = @'
@echo off
setlocal
set "ZT_PYZ=%~dp0zt.pyz"

where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
  if not errorlevel 1 goto :run_py
)

where python >nul 2>nul
if not errorlevel 1 (
  python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
  if not errorlevel 1 goto :run_python
)

where python3 >nul 2>nul
if not errorlevel 1 (
  python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>nul
  if not errorlevel 1 goto :run_python3
)

echo zt: Python 3.9 or later is required on Windows. 1>&2
echo Install it via: winget install Python.Python.3.12 1>&2
echo Or download from: https://www.python.org/downloads/ 1>&2
exit /b 1

:run_py
py -3 "%ZT_PYZ%" %*
exit /b %ERRORLEVEL%

:run_python
python "%ZT_PYZ%" %*
exit /b %ERRORLEVEL%

:run_python3
python3 "%ZT_PYZ%" %*
exit /b %ERRORLEVEL%
'@
        [IO.File]::WriteAllText($cmdDest, $cmdBody.Replace("`n", "`r`n"), [Text.UTF8Encoding]::new($false))

        # 6. Add install directory to User PATH (and current session PATH).
        if ($env:ZT_NO_MODIFY_PATH -ne '1') {
            $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
            $entries = @()
            if ($userPath) {
                $entries = $userPath -split ';' | Where-Object { $_ -ne '' }
            }
            $normTarget = $installDir.TrimEnd('\').ToLowerInvariant()
            $already = $entries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -eq $normTarget }
            if (-not $already) {
                $newPath = if ($entries.Count -gt 0) { ($entries + $installDir) -join ';' } else { $installDir }
                [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
                Write-Host "Added $installDir to your user PATH."
            }
            $sessionEntries = ($env:Path -split ';') | Where-Object { $_ -ne '' }
            if (-not ($sessionEntries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -eq $normTarget })) {
                $env:Path = "$installDir;$env:Path"
            }
        }

        $verOut = & $cmdDest --version
        Write-Host "Installed $(([string]($verOut | Select-Object -First 1)).Trim()) to $installDir"
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            Write-Host ''
            Write-Host 'Next: install and start Docker Desktop (or Podman), then run: zt up'
        }
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-Zt
