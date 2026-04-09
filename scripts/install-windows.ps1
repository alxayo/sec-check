# AgentSec installer for Windows PowerShell.
# Downloads latest release assets, installs core+cli into a venv,
# and copies Copilot skill folders to $HOME\.copilot\skills.

$ErrorActionPreference = "Stop"

$Repo = if ($env:AGENTSEC_REPO) { $env:AGENTSEC_REPO } else { "alxayo/sec-check" }
$VenvDir = if ($env:AGENTSEC_VENV_DIR) { $env:AGENTSEC_VENV_DIR } else { Join-Path $HOME "agentsec-venv" }
$SkillsDir = if ($env:AGENTSEC_SKILLS_DIR) { $env:AGENTSEC_SKILLS_DIR } else { Join-Path $HOME ".copilot\skills" }

function Write-Log {
  param([string]$Message)
  Write-Host "[agentsec-install] $Message"
}

function Get-PythonCommand {
  if (Get-Command py -ErrorAction SilentlyContinue) { return "py" }
  if (Get-Command python -ErrorAction SilentlyContinue) { return "python" }
  throw "Python launcher (py) or python is required"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("agentsec-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
  $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
  Write-Log "Fetching latest release metadata from $Repo"
  $release = Invoke-RestMethod -Uri $apiUrl

  if (-not $release.tag_name) {
    throw "Could not resolve latest release tag"
  }

  Write-Log "Latest release: $($release.tag_name)"

  $coreAsset = $release.assets | Where-Object { $_.name -match '^agentsec_core-.*\.whl$' } | Select-Object -First 1
  $cliAsset = $release.assets | Where-Object { $_.name -match '^agentsec_cli-.*\.whl$' } | Select-Object -First 1
  $assetsAsset = $release.assets | Where-Object { $_.name -match '^agentsec-copilot-assets-.*\.(zip|tar\.gz)$' } | Select-Object -First 1

  if (-not $coreAsset) { throw "Could not find agentsec_core wheel in latest release" }
  if (-not $cliAsset) { throw "Could not find agentsec_cli wheel in latest release" }
  if (-not $assetsAsset) { throw "Could not find copilot assets archive in latest release" }

  $coreFile = Join-Path $tempRoot $coreAsset.name
  $cliFile = Join-Path $tempRoot $cliAsset.name
  $assetsFile = Join-Path $tempRoot $assetsAsset.name

  Write-Log "Downloading core wheel"
  Invoke-WebRequest -Uri $coreAsset.browser_download_url -OutFile $coreFile
  Write-Log "Downloading cli wheel"
  Invoke-WebRequest -Uri $cliAsset.browser_download_url -OutFile $cliFile
  Write-Log "Downloading copilot assets"
  Invoke-WebRequest -Uri $assetsAsset.browser_download_url -OutFile $assetsFile

  $pythonCmd = Get-PythonCommand
  Write-Log "Creating virtual environment at $VenvDir"
  if ($pythonCmd -eq "py") {
    & py -3 -m venv $VenvDir
  } else {
    & python -m venv $VenvDir
  }

  $venvPython = Join-Path $VenvDir "Scripts\python.exe"
  if (-not (Test-Path $venvPython)) {
    throw "Virtualenv python not found at $venvPython"
  }

  Write-Log "Installing agentsec_core"
  & $venvPython -m pip install --upgrade pip | Out-Null
  & $venvPython -m pip install $coreFile

  Write-Log "Installing agentsec_cli"
  & $venvPython -m pip install $cliFile

  $extractDir = Join-Path $tempRoot "assets"
  New-Item -ItemType Directory -Path $extractDir | Out-Null

  if ($assetsFile -like "*.zip") {
    Write-Log "Extracting copilot assets"
    Expand-Archive -Path $assetsFile -DestinationPath $extractDir -Force
  } else {
    throw "Only .zip assets are currently supported by install-windows.ps1"
  }

  $skillsSource = Get-ChildItem -Path $extractDir -Directory -Recurse |
    Where-Object { $_.FullName -match '[\\/]\.github[\\/]skills$' } |
    Select-Object -First 1

  if (-not $skillsSource) {
    throw "Could not find .github/skills in assets archive"
  }

  New-Item -ItemType Directory -Path $SkillsDir -Force | Out-Null
  Write-Log "Copying skills to $SkillsDir"
  Copy-Item -Path (Join-Path $skillsSource.FullName "*") -Destination $SkillsDir -Recurse -Force

  $agentsecExe = Join-Path $VenvDir "Scripts\agentsec.exe"
  if (-not (Test-Path $agentsecExe)) {
    throw "Install completed but agentsec executable was not found at $agentsecExe"
  }

  $version = & $agentsecExe --version
  Write-Log "Installed successfully: $version"

  Write-Host ""
  Write-Host "AgentSec install complete."
  Write-Host ""
  Write-Host "Next steps:"
  Write-Host "1. Activate venv in each shell session:"
  Write-Host "   $VenvDir\Scripts\Activate.ps1"
  Write-Host "2. Verify command:"
  Write-Host "   agentsec --version"
  Write-Host "3. For VS Code extension, set agentsec.pythonPath to:"
  Write-Host "   $venvPython"
  Write-Host "4. Skills were installed to:"
  Write-Host "   $SkillsDir"
}
finally {
  if (Test-Path $tempRoot) {
    Remove-Item -Path $tempRoot -Recurse -Force
  }
}
