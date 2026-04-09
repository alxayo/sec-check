#!/usr/bin/env bash
set -euo pipefail

# AgentSec installer for Linux and macOS.
# Downloads latest release assets, installs core+cli into a venv,
# and copies Copilot skill folders to ~/.copilot/skills.

REPO="${AGENTSEC_REPO:-alxayo/sec-check}"
VENV_DIR="${AGENTSEC_VENV_DIR:-$HOME/agentsec-venv}"
SKILLS_DIR="${AGENTSEC_SKILLS_DIR:-$HOME/.copilot/skills}"

log() {
  printf '[agentsec-install] %s\n' "$*"
}

fail() {
  printf '[agentsec-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
}

download_file() {
  local url="$1"
  local out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi

  fail "Neither curl nor wget is available for downloads"
}

extract_archive() {
  local archive="$1"
  local dest="$2"

  case "$archive" in
    *.zip)
      require_cmd unzip
      unzip -q "$archive" -d "$dest"
      ;;
    *.tar.gz|*.tgz)
      require_cmd tar
      tar -xzf "$archive" -C "$dest"
      ;;
    *)
      fail "Unsupported archive format: $archive"
      ;;
  esac
}

main() {
  require_cmd python3

  local os_name
  os_name="$(uname -s)"
  case "$os_name" in
    Linux|Darwin) ;;
    *) fail "Unsupported OS for this script: $os_name" ;;
  esac

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  local api_url="https://api.github.com/repos/${REPO}/releases/latest"
  local release_json="$tmp_dir/release.json"

  log "Fetching latest release metadata from ${REPO}"
  download_file "$api_url" "$release_json"

  local release_tag
  release_tag="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['tag_name'])" "$release_json")"
  log "Latest release: ${release_tag}"

  local core_url cli_url assets_url
  core_url="$(python3 -c "import json,sys,re; d=json.load(open(sys.argv[1])); a=[x['browser_download_url'] for x in d.get('assets',[])]; print(next((u for u in a if re.search(r'/agentsec_core-.*\\.whl$', u)),''))" "$release_json")"
  cli_url="$(python3 -c "import json,sys,re; d=json.load(open(sys.argv[1])); a=[x['browser_download_url'] for x in d.get('assets',[])]; print(next((u for u in a if re.search(r'/agentsec_cli-.*\\.whl$', u)),''))" "$release_json")"
  assets_url="$(python3 -c "import json,sys,re; d=json.load(open(sys.argv[1])); a=[x['browser_download_url'] for x in d.get('assets',[])]; print(next((u for u in a if re.search(r'/agentsec-copilot-assets-.*\\.(zip|tar\\.gz)$', u)),''))" "$release_json")"

  [[ -n "$core_url" ]] || fail "Could not find agentsec_core wheel in latest release"
  [[ -n "$cli_url" ]] || fail "Could not find agentsec_cli wheel in latest release"
  [[ -n "$assets_url" ]] || fail "Could not find copilot assets archive in latest release"

  local core_file cli_file assets_file
  core_file="$tmp_dir/$(basename "$core_url")"
  cli_file="$tmp_dir/$(basename "$cli_url")"
  assets_file="$tmp_dir/$(basename "$assets_url")"

  log "Downloading core wheel"
  download_file "$core_url" "$core_file"
  log "Downloading cli wheel"
  download_file "$cli_url" "$cli_file"
  log "Downloading copilot assets"
  download_file "$assets_url" "$assets_file"

  log "Creating virtual environment at ${VENV_DIR}"
  python3 -m venv "$VENV_DIR"

  local vpy vpip
  vpy="$VENV_DIR/bin/python"
  vpip="$VENV_DIR/bin/pip"

  [[ -x "$vpy" ]] || fail "Virtualenv python not found at $vpy"
  [[ -x "$vpip" ]] || fail "Virtualenv pip not found at $vpip"

  log "Installing agentsec_core"
  "$vpip" install --upgrade pip >/dev/null
  "$vpip" install "$core_file"

  log "Installing agentsec_cli"
  "$vpip" install "$cli_file"

  log "Extracting copilot assets"
  local assets_extract="$tmp_dir/assets"
  mkdir -p "$assets_extract"
  extract_archive "$assets_file" "$assets_extract"

  local skills_source
  skills_source="$(find "$assets_extract" -type d -path '*/.github/skills' | head -n 1 || true)"
  [[ -n "$skills_source" ]] || fail "Could not find .github/skills in assets archive"

  mkdir -p "$SKILLS_DIR"
  log "Copying skills to ${SKILLS_DIR}"
  cp -R "$skills_source"/* "$SKILLS_DIR"/

  local agentsec_bin="$VENV_DIR/bin/agentsec"
  if [[ -x "$agentsec_bin" ]]; then
    local version
    version="$($agentsec_bin --version 2>/dev/null || true)"
    log "Installed successfully: ${version:-agentsec installed}"
  else
    fail "Install completed but agentsec executable was not found at $agentsec_bin"
  fi

  cat <<EOF

AgentSec install complete.

Next steps:
1. Activate venv in each shell session:
   source "$VENV_DIR/bin/activate"
2. Verify command:
   agentsec --version
3. For VS Code extension, set agentsec.pythonPath to:
   $VENV_DIR/bin/python
4. Skills were installed to:
   $SKILLS_DIR

EOF
}

main "$@"
