#!/usr/bin/env python3
"""
Build & Release Script for AgentSec

Usage:
    python3 scripts/build_release.py <version>

Example:
    python3 scripts/build_release.py 0.2.0

Dependencies:
    pip install build

Actions:
    1. Updates version in:
       - core/pyproject.toml
       - cli/pyproject.toml
       - core/agentsec/__init__.py
       - cli/agentsec_cli/__init__.py
    2. Builds wheels for core and cli
    3. Moves all artifacts to ./dist/ folder
"""

import sys
import os
import re
import shutil
import subprocess
from pathlib import Path

# Paths relative to project root (assuming script runs from root or scripts/)
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
DIST_DIR = PROJECT_ROOT / "dist"

FILES_TO_UPDATE = [
    PROJECT_ROOT / "core/pyproject.toml",
    PROJECT_ROOT / "cli/pyproject.toml",
    PROJECT_ROOT / "core/agentsec/__init__.py",
    PROJECT_ROOT / "cli/agentsec_cli/__init__.py",
    PROJECT_ROOT / "vscode-extension/package.json",
]

def validate_version(version):
    """Ensure version matches Semantic Versioning (X.Y.Z)."""
    pattern = r"^\d+\.\d+\.\d+$"
    if not re.match(pattern, version):
        print(f"Error: Version '{version}' does not match format MAJOR.MINOR.PATCH (e.g., 0.1.0)")
        sys.exit(1)
    return version

def update_file_version(file_path, new_version):
    """Regex replace version string in file."""
    if not file_path.exists():
        print(f"Warning: File not found: {file_path}")
        return

    content = file_path.read_text(encoding="utf-8")
    
    # Matches: version = "0.1.0" (toml) OR __version__ = "0.1.0" (python)
    # We use a specific regex to avoid replacing dependencies or other strings
    
    # 1. TOML version
    if file_path.suffix == ".toml":
        # Replace: version = "..."
        pattern = r'(^version\s*=\s*")([^"]+)(")'
        replacement = f'\\g<1>{new_version}\\g<3>'
        
        # Also update dependency pin in CLI if present
        # dependencies = [ "agentsec-core>=0.1.0", ... ]
        dep_pattern = r'(agentsec-core>=)(\d+\.\d+\.\d+)'
        dep_replacement = f'\\g<1>{new_version}'
        
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        content = re.sub(dep_pattern, dep_replacement, content)

    # 2. Python __init__ version
    elif file_path.suffix == ".py":
        # Replace: __version__ = "..."
        pattern = r'(__version__\s*=\s*")([^"]+)(")'
        replacement = f'\\g<1>{new_version}\\g<3>'
        content = re.sub(pattern, replacement, content)

    # 3. JSON version (package.json)
    elif file_path.suffix == ".json":
        # Replace: "version": "..."
        pattern = r'("version"\s*:\s*")([^"]+)(")'
        replacement = f'\\g<1>{new_version}\\g<3>'
        content = re.sub(pattern, replacement, content, count=1)

    file_path.write_text(content, encoding="utf-8")
    print(f"Updated {file_path.relative_to(PROJECT_ROOT)} -> {new_version}")

def clean_build_artifacts():
    """Remove old build/ and dist/ directories within packages."""
    for package in ["core", "cli"]:
        build_dir = PROJECT_ROOT / package / "build"
        dist_dir = PROJECT_ROOT / package / "dist"
        egg_info = PROJECT_ROOT / package / f"{package.replace('-', '_')}.egg-info" # approximation

        if build_dir.exists(): shutil.rmtree(build_dir)
        if dist_dir.exists(): shutil.rmtree(dist_dir)
        
        # Find exact .egg-info directory
        for item in (PROJECT_ROOT / package).glob("*.egg-info"):
            if item.is_dir():
                shutil.rmtree(item)

def build_package(package_dir):
    """Run `python -m build`."""
    print(f"\nBuilding package: {package_dir.name}...")
    subprocess.run(
        [sys.executable, "-m", "build", str(package_dir.resolve())], 
        check=True,
        stdout=subprocess.DEVNULL  # Keep it quiet unless error
    )

def collect_artifacts():
    """Move all .whl and .tar.gz files to root dist/."""
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir()

    count = 0
    for package in ["core", "cli"]:
        pkg_dist = PROJECT_ROOT / package / "dist"
        if not pkg_dist.exists():
            continue
            
        for artifact in pkg_dist.iterdir():
            shutil.copy(artifact, DIST_DIR / artifact.name)
            print(f"Saved: dist/{artifact.name}")
            count += 1
            
    return count

def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)

    new_version = validate_version(sys.argv[1])
    
    print(f"=== AgentSec Release Builder ({new_version}) ===\n")

    # 1. Update Versions
    print("--- Updating Files ---")
    for file_path in FILES_TO_UPDATE:
        update_file_version(file_path, new_version)

    # 2. Build
    try:
        # Ensure build tool is installed
        subprocess.run([sys.executable, "-m", "pip", "install", "build"], 
                      check=True, stdout=subprocess.DEVNULL)
        
        print("\n--- Cleaning Old Artifacts ---")
        clean_build_artifacts()
        
        print("\n--- Building Packages ---")
        build_package(PROJECT_ROOT / "core")
        build_package(PROJECT_ROOT / "cli")

        # 3. Collect
        print("\n--- Collecting Artifacts ---")
        count = collect_artifacts()
        
        print(f"\n✅ Success! {count} artifacts created in dist/")
        print(f"   To install: pip install dist/*.whl")
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
