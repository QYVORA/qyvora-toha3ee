# toha3ee installer for Windows.
#
# Downloads the latest prebuilt binary for this architecture from the GitHub
# release, verifies its SHA-256 checksum, installs it under
# %LOCALAPPDATA%\Programs\toha3ee\bin and adds that directory to your user
# PATH so `toha3ee` works from any new terminal. Falls back to `go build`
# when no release binary is available yet.
#
# Usage:
#   irm https://raw.githubusercontent.com/qyvora/qyvora-toha3ee/main/scripts/install.ps1 | iex
#
# Options:
#   $env:TOHA3EE_VERSION    pinned release tag, e.g. v0.1.0 (default: latest)
#   $env:TOHA3EE_PREFIX     install directory (default: %LOCALAPPDATA%\Programs\toha3ee)
#   -FromSource             always build from the current checkout instead of downloading

param(
    [switch]$FromSource
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "qyvora/qyvora-toha3ee"
$Bin = "toha3ee"
$Version = $env:TOHA3EE_VERSION
$Prefix = $env:TOHA3EE_PREFIX

if (-not $Prefix) {
    $Prefix = Join-Path $env:LOCALAPPDATA "Programs\toha3ee"
}
$Dest = Join-Path $Prefix "bin"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Green }
function Write-Err($msg) { Write-Host "[!] $msg" -ForegroundColor Red }
function Write-Result($msg) { Write-Host "    $msg" }

function Build-FromSource {
    Write-Step "building $Bin from source..."
    if (-not (Test-Path (Join-Path $PWD "go.mod"))) {
        $cmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $cmd) { Write-Err "git is required to fetch the source"; exit 1 }
        $tmp = Join-Path $env:TEMP "qyvora-toha3ee-src"
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        Write-Step "cloning $Repo..."
        git clone --depth 1 "https://github.com/$Repo" $tmp | Out-Null
        Set-Location $tmp
    }
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) { Write-Err "go is required to build from source"; exit 1 }
    go build -trimpath -ldflags "-s -w" -o (Join-Path $Dest "$Bin.exe") ./cmd/toha3ee
    Write-Step "built $Bin from source"
}

function Install-Icon {
    $candidates = @(
        (Join-Path $PWD "assets\toha3ee.ico"),
        (Join-Path $OutDir "assets\toha3ee.ico")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            Copy-Item $c (Join-Path $Dest "toha3ee.ico") -Force
            Write-Step "installed icon to $(Join-Path $Dest 'toha3ee.ico')"
            return
        }
    }
}

function Install-StartMenuShortcut {
    $ico = Join-Path $Dest "toha3ee.ico"
    if (-not (Test-Path $ico)) { return }
    $startMenu = [Environment]::GetFolderPath("Programs")
    if (-not $startMenu) { return }
    $lnk = Join-Path $startMenu "toha3ee.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = Join-Path $Dest "$Bin.exe"
    $sc.WorkingDirectory = $Dest
    $sc.IconLocation = $ico
    $sc.Description = "network exploitation & MITM framework"
    $sc.Save()
    Write-Step "created Start Menu shortcut $lnk"
}

function Resolve-Latest {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "toha3ee-installer" }
    return $rel.tag_name
}

if ($FromSource) {
    Build-FromSource
}
else {
    if (-not $Version) {
        $Version = Resolve-Latest
    }
    $Os = "windows"
    # gopacket releases amd64 pcap bindings; Windows-on-ARM64 emulates x64.
    $Arch = "amd64"
    $Artifact = "${Bin}_${Os}_${Arch}.zip"
    $Url = "https://github.com/$Repo/releases/download/$Version/$Artifact"
    $Zip = Join-Path $env:TEMP $Artifact
    $OutDir = Join-Path $env:TEMP "toha3ee-extract"

    Write-Step "downloading $Bin $Version (windows/$Arch)..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
        if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
        Expand-Archive -Path $Zip -DestinationPath $OutDir -Force
        $sha = ""
        try {
            $sha = (Invoke-WebRequest -Uri "$Url.sha256" -UseBasicParsing).Content.Trim() -split "\s+" | Select-Object -First 1
        } catch { }
        if ($sha) {
            $actual = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $sha.ToLower()) { Write-Err "checksum mismatch"; exit 1 }
            Write-Step "checksum verified"
        }
        else {
            Write-Step "no checksum published for $Version; skipping verification"
        }
        Copy-Item (Join-Path $OutDir "$Bin.exe") $Dest -Force
        Write-Step "installed $(Join-Path $Dest "$Bin.exe") ($Version)"
        Install-Icon
    }
    catch {
        Write-Step "no prebuilt binary for windows/$Arch at $Version; building from source..."
        Build-FromSource
        Install-Icon
    }
}
else {
    Build-FromSource
    Install-Icon
}

# --- Start Menu ------------------------------------------------------------
Install-StartMenuShortcut

# --- PATH ------------------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Dest*") {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $Dest } else { "$Dest;$userPath" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Step "added $Dest to your user PATH (open a new terminal)"
}
else {
    Write-Step "$Dest is already on your PATH"
}

Write-Result "run 'toha3ee' to start the console."
