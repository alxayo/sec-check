"""
Dynamic discovery of Copilot CLI agentic skills.

The Copilot CLI searches for agentic skills in two locations:
  1. User-level:    ~/.copilot/skills/
  2. Project-level: .copilot/skills/   (relative to the workspace root)

Each skill is a directory containing a SKILL.md file with YAML frontmatter
that describes the skill (name, description) followed by documentation.
The skills typically wrap underlying CLI tools (bandit, trivy, etc.).

This module provides functions to:
  - Discover all skills from both locations
  - Parse the SKILL.md frontmatter to get skill metadata
  - Map each skill to its underlying CLI tool
  - Check whether the underlying tool is installed on the system

Usage:
    >>> from agentsec.skill_discovery import discover_all_skills
    >>> skills = discover_all_skills("/path/to/project")
    >>> for skill in skills:
    ...     status = "✅" if skill["tool_available"] else "⬜"
    ...     print(f"{status} {skill['name']} ({skill['tool_name']})")
"""

import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Set up logging for this module
logger = logging.getLogger(__name__)


# ── Consolidated scanner registry (E1) ───────────────────────────────
# Single source of truth for all known scanning skills.  Each entry maps
# a skill directory name to its underlying CLI tool, the file-type
# relevance info (extensions / filenames), and a human-readable
# description.  Both SKILL_TO_TOOL_MAP and SCANNER_RELEVANCE (previously
# maintained separately in two files) are now derived from this registry.
#
# To add a new scanner, add ONE entry here.  Everything else
# (tool mapping, relevance checks, system-message generation) updates
# automatically.

SCANNER_REGISTRY: dict = {
    "bandit-security-scan": {
        "tool": "bandit",
        "extensions": {".py"},
        "filenames": set(),
        "description": "Python AST security analysis",
    },
    "eslint-security-scan": {
        "tool": "eslint",
        "extensions": {".js", ".jsx", ".ts", ".tsx"},
        "filenames": set(),
        "description": "JavaScript / TypeScript security analysis",
    },
    "shellcheck-security-scan": {
        "tool": "shellcheck",
        "extensions": {".sh", ".bash"},
        "filenames": set(),
        "description": "Shell script security analysis",
    },
    "graudit-security-scan": {
        "tool": "graudit",
        "extensions": None,   # always relevant (multi-language)
        "filenames": None,
        "description": "Pattern-based source code auditing (multi-language)",
    },
    "guarddog-security-scan": {
        "tool": "guarddog",
        "extensions": set(),
        "filenames": {"requirements.txt", "package.json", "package-lock.json"},
        "description": "Supply-chain / malicious package detection",
    },
    "trivy-security-scan": {
        "tool": "trivy",
        "extensions": None,   # always relevant (filesystem scanner)
        "filenames": None,
        "description": "Container, filesystem, and IaC scanning",
    },
    "checkov-security-scan": {
        "tool": "checkov",
        "extensions": {".tf", ".yaml", ".yml"},
        "filenames": {"dockerfile"},
        "description": "Infrastructure-as-Code security scanning",
    },
    "dependency-check-security-scan": {
        "tool": "dependency-check",
        "extensions": set(),
        "filenames": {"requirements.txt", "package.json", "go.mod", "gemfile.lock", "pom.xml"},
        "description": "Dependency CVE scanning",
    },
    "template-analyzer-security-scan": {
        "tool": "template-analyzer",
        "extensions": set(),
        "filenames": set(),
        "description": "ARM/Bicep template security scanning",
    },
}

# Derived views for backward compatibility and convenience.
# SKILL_TO_TOOL_MAP: skill directory name -> CLI binary name
SKILL_TO_TOOL_MAP = {
    name: info["tool"] for name, info in SCANNER_REGISTRY.items()
}

# SCANNER_RELEVANCE: skill name -> {extensions, filenames, description}
# Used by orchestrator.classify_files / is_scanner_relevant.
SCANNER_RELEVANCE = {
    name: {
        "extensions": info["extensions"],
        "filenames": info["filenames"],
        "description": info["description"],
    }
    for name, info in SCANNER_REGISTRY.items()
}

# H1: Set of known scanner command names derived from the registry.
KNOWN_SCANNER_COMMANDS = frozenset(SKILL_TO_TOOL_MAP.values())


# ── Folders to skip during file discovery ───────────────────────────
# Common non-source directories that should not be scanned.
FOLDERS_TO_SKIP: Set[str] = {
    ".git",
    "__pycache__",
    "node_modules",
    ".next",
    "venv",
    ".venv",
    "dist",
    "build",
}


# ── File classification functions (B1) ────────────────────────────
# These live in skill_discovery so both agent.py and orchestrator.py
# can import them without either depending on the other.

def classify_files(
    folder_path: str,
) -> Tuple[Dict[str, int], Set[str], int]:
    """
    Walk the target folder and classify files by extension and name.

    Skips common non-source directories (node_modules, .git, etc.)
    so the classification reflects actual source code.

    This is used by both the orchestrator's scan plan and the agent's
    skip-guidance builder.

    Args:
        folder_path: Directory to walk.

    Returns:
        A 3-tuple of:
        - file_extensions: dict mapping extension (e.g. ".py") to count
        - file_names: set of lowercased filenames found
        - total_files: total number of files
    """
    extension_counts: Dict[str, int] = {}
    filename_set: Set[str] = set()
    total = 0

    for current_dir, subdirs, filenames in os.walk(folder_path):
        subdirs[:] = [d for d in subdirs if d not in FOLDERS_TO_SKIP]

        for filename in filenames:
            total += 1
            extension = os.path.splitext(filename)[1].lower()
            if extension:
                extension_counts[extension] = (
                    extension_counts.get(extension, 0) + 1
                )
            filename_set.add(filename.lower())

    return extension_counts, filename_set, total


def is_scanner_relevant(
    relevance_info: dict,
    file_extensions: Dict[str, int],
    file_names: Set[str],
) -> bool:
    """
    Check whether a scanner is relevant for the discovered files.

    A scanner is relevant if:
    - Its extensions/filenames fields are None (always relevant), or
    - At least one target extension exists in the folder, or
    - At least one target filename exists in the folder.

    Args:
        relevance_info: Entry from SCANNER_RELEVANCE dict.
        file_extensions: Extensions found in the folder.
        file_names:      Filenames found in the folder (lowercased).

    Returns:
        True if the scanner should be included in the scan plan.
    """
    target_extensions = relevance_info.get("extensions")
    target_filenames = relevance_info.get("filenames")

    if target_extensions is None or target_filenames is None:
        return True

    if target_extensions:
        for ext in target_extensions:
            if ext in file_extensions:
                return True

    if target_filenames:
        for target_name in target_filenames:
            if target_name.lower() in file_names:
                return True

    return False


# ── Skill discovery cache (E2) ───────────────────────────────────────
# discover_all_skills() and get_skill_directories() are called multiple
# times during a single scan (CLI display, agent initialise, each
# sub-agent in parallel mode).  Since skill directories don't change
# mid-scan, we cache results with a short TTL to avoid redundant
# filesystem walks and shutil.which() calls.
_CACHE_TTL_SECONDS = 30.0
_skills_cache: dict = {"result": None, "key": None, "time": 0.0}
_dirs_cache: dict = {"result": None, "key": None, "time": 0.0}


def _get_user_skills_dir() -> Path:
    """
    Return the user-level Copilot skills directory.

    The Copilot CLI looks for user-level agentic skills in:
        ~/.copilot/skills/

    Returns:
        Path to the user-level skills directory (may not exist).
    """
    return Path.home() / ".copilot" / "skills"


def _get_project_skills_dir(project_root: str) -> Path:
    """
    Return the project-level Copilot skills directory.

    The Copilot CLI looks for project-level agentic skills in:
        <project_root>/.copilot/skills/

    Args:
        project_root: Absolute path to the project (workspace) root.

    Returns:
        Path to the project-level skills directory (may not exist).
    """
    return Path(project_root) / ".copilot" / "skills"


def _parse_skill_frontmatter(skill_md_path: Path) -> dict:
    """
    Parse the YAML frontmatter from a SKILL.md file.

    SKILL.md files use a YAML frontmatter block delimited by '---' lines
    at the top of the file. Typical fields are 'name' and 'description'.

    We parse the frontmatter manually (line-by-line) instead of requiring
    PyYAML, so this function works even if PyYAML is not installed.

    Args:
        skill_md_path: Full path to the SKILL.md file.

    Returns:
        A dictionary with parsed frontmatter fields. Common keys:
        - "name": Skill name (e.g. "bandit-security-scan")
        - "description": One-line description of the skill
        Returns empty dict if frontmatter could not be parsed.

    Example:
        >>> meta = _parse_skill_frontmatter(Path("~/.copilot/skills/bandit-security-scan/SKILL.md"))
        >>> print(meta["name"])
        'bandit-security-scan'
    """
    try:
        with open(skill_md_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()
    except (FileNotFoundError, PermissionError, OSError) as error:
        logger.debug(f"Could not read {skill_md_path}: {error}")
        return {}

    # Find the frontmatter block (between first and second '---')
    if not lines or lines[0].strip() != "---":
        return {}

    frontmatter_lines = []
    found_end = False

    for line in lines[1:]:
        if line.strip() == "---":
            found_end = True
            break
        frontmatter_lines.append(line)

    if not found_end:
        return {}

    # Parse simple key: value pairs from the frontmatter
    # We handle multi-line values by treating leading whitespace as continuation
    metadata = {}
    current_key = None
    current_value_parts = []

    for line in frontmatter_lines:
        # Check if this is a new key: value pair
        key_value_match = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', line)

        if key_value_match:
            # Save any previous key
            if current_key is not None:
                metadata[current_key] = " ".join(current_value_parts).strip()

            current_key = key_value_match.group(1)
            value = key_value_match.group(2).strip()
            current_value_parts = [value] if value else []

        elif current_key is not None and line.strip():
            # Continuation of a multi-line value
            current_value_parts.append(line.strip())

    # Save the last key
    if current_key is not None:
        metadata[current_key] = " ".join(current_value_parts).strip()

    return metadata


def _derive_tool_name(skill_dir_name: str) -> str:
    """
    Derive the underlying CLI tool name from a skill directory name.

    This is a fallback when the skill is not in SKILL_TO_TOOL_MAP.
    It takes the first segment before '-security-scan', '-scan', or
    the first '-' delimited segment.

    Args:
        skill_dir_name: The directory name (e.g. "bandit-security-scan")

    Returns:
        The guessed tool name (e.g. "bandit")

    Examples:
        >>> _derive_tool_name("bandit-security-scan")
        'bandit'
        >>> _derive_tool_name("my-custom-tool")
        'my-custom-tool'
    """
    # Try removing common suffixes first
    for suffix in ("-security-scan", "-scan"):
        if skill_dir_name.endswith(suffix):
            return skill_dir_name[: -len(suffix)]

    # Fall back to the full directory name (it might be a valid tool name)
    return skill_dir_name


def _discover_skills_in_directory(skills_dir: Path, source_label: str) -> List[dict]:
    """
    Discover all Copilot skills in a single directory.

    Scans the given directory for subdirectories that contain a SKILL.md file,
    parses the frontmatter, maps to the underlying tool, and checks availability.

    Args:
        skills_dir: Path to a skills directory (e.g. ~/.copilot/skills/)
        source_label: Human-readable label for the source ("user" or "project")

    Returns:
        A list of skill dictionaries. Each dict has these keys:
        - "name":           Skill name from frontmatter (or folder name)
        - "description":    One-line description from frontmatter
        - "tool_name":      The underlying CLI tool binary name
        - "tool_available": True if the tool is found on PATH
        - "tool_path":      Full path to the tool binary (or None)
        - "source":         "user" or "project"
        - "skill_dir":      Full path to the skill directory
    """
    discovered_skills = []

    if not skills_dir.is_dir():
        logger.debug(f"Skills directory does not exist: {skills_dir}")
        return discovered_skills

    # Iterate over subdirectories in the skills directory
    try:
        entries = sorted(skills_dir.iterdir())
    except PermissionError:
        logger.warning(f"Permission denied reading: {skills_dir}")
        return discovered_skills

    for entry in entries:
        if not entry.is_dir():
            continue

        # Check for SKILL.md in this subdirectory
        skill_md_path = entry / "SKILL.md"
        if not skill_md_path.is_file():
            logger.debug(f"Skipping {entry.name}: no SKILL.md found")
            continue

        # Parse the frontmatter
        metadata = _parse_skill_frontmatter(skill_md_path)

        # Get the skill name (prefer frontmatter, fall back to dir name)
        skill_name = metadata.get("name", entry.name)

        # Get the description (first sentence only, for brevity)
        raw_description = metadata.get("description", "")
        # Truncate to the first sentence or 100 chars for display
        description = raw_description
        # Find first sentence boundary for a concise display version
        first_period = raw_description.find(".")
        if first_period > 0 and first_period < 120:
            description = raw_description[: first_period + 1]
        elif len(raw_description) > 120:
            description = raw_description[:117] + "..."

        # Determine the underlying tool name
        tool_name = SKILL_TO_TOOL_MAP.get(entry.name)
        if tool_name is None:
            tool_name = _derive_tool_name(entry.name)
            logger.info(
                f"Skill '{skill_name}' not in SCANNER_REGISTRY, "
                f"derived tool name: '{tool_name}'"
            )
        else:
            logger.info(
                f"Skill '{skill_name}' mapped to tool '{tool_name}' via SCANNER_REGISTRY"
            )

        # Check if the tool is available on the system
        tool_path = shutil.which(tool_name)
        tool_available = tool_path is not None

        if tool_available:
            logger.info(
                f"  ✓ Tool '{tool_name}' found at: {tool_path}"
            )
        else:
            logger.warning(
                f"  ✗ Tool '{tool_name}' NOT found on PATH. "
                f"To fix: install '{tool_name}' or add it to PATH. "
                f"Searched via: shutil.which('{tool_name}')"
            )

        skill_info = {
            "name": skill_name,
            "description": description,
            "tool_name": tool_name,
            "tool_available": tool_available,
            "tool_path": tool_path,
            "source": source_label,
            "skill_dir": str(entry),
        }

        discovered_skills.append(skill_info)
        logger.debug(
            f"Discovered skill: {skill_name} "
            f"(tool={tool_name}, available={tool_available})"
        )

    return discovered_skills


def discover_all_skills(project_root: Optional[str] = None) -> List[dict]:
    """
    Discover all Copilot CLI agentic skills from both user and project levels.

    The Copilot CLI searches for skills in two locations:
      1. User-level:    ~/.copilot/skills/
      2. Project-level: <project_root>/.copilot/skills/

    This function scans both directories, parses each skill's SKILL.md
    frontmatter, maps the skill to its underlying CLI tool, and checks
    whether that tool is installed on the system.

    Args:
        project_root: Path to the project root directory.
                      If None, only user-level skills are discovered.

    Returns:
        A list of skill dictionaries, sorted by name. Each dict contains:
        - "name":           Skill name (e.g. "bandit-security-scan")
        - "description":    Short description of the skill
        - "tool_name":      CLI tool binary name (e.g. "bandit")
        - "tool_available": True if the tool is found on PATH
        - "tool_path":      Absolute path to the tool binary, or None
        - "source":         "user" or "project"
        - "skill_dir":      Absolute path to the skill directory

    Example:
        >>> skills = discover_all_skills("/home/user/my-project")
        >>> for skill in skills:
        ...     mark = "✅" if skill["tool_available"] else "⬜"
        ...     print(f"  {mark} {skill['tool_name']:<20} — {skill['description']}")
    """
    # E2: Check cache before doing expensive filesystem work
    cache_key = project_root or "__none__"
    if (
        _skills_cache["key"] == cache_key
        and _skills_cache["result"] is not None
        and (time.time() - _skills_cache["time"]) < _CACHE_TTL_SECONDS
    ):
        return _skills_cache["result"]

    all_skills = []

    # Step 1: Discover user-level skills from ~/.copilot/skills/
    user_skills_dir = _get_user_skills_dir()
    user_skills = _discover_skills_in_directory(user_skills_dir, source_label="user")
    all_skills.extend(user_skills)

    logger.info(
        f"Found {len(user_skills)} user-level skills in {user_skills_dir}"
    )

    # Step 2: Discover project-level skills from <project>/.copilot/skills/
    if project_root is not None:
        project_skills_dir = _get_project_skills_dir(project_root)
        project_skills = _discover_skills_in_directory(
            project_skills_dir, source_label="project"
        )
        all_skills.extend(project_skills)

        logger.info(
            f"Found {len(project_skills)} project-level skills in {project_skills_dir}"
        )

    # Sort by name for consistent display
    all_skills.sort(key=lambda skill: skill["name"])

    # E2: Store in cache
    _skills_cache["result"] = all_skills
    _skills_cache["key"] = cache_key
    _skills_cache["time"] = time.time()

    return all_skills


def get_skill_directories(project_root: Optional[str] = None) -> List[str]:
    """
    Return the list of skill directory paths to pass to SessionConfig.

    The Copilot SDK's ``skill_directories`` parameter tells the CLI
    where to find agentic skills.  This function returns the standard
    locations that exist on disk so they can be passed directly to
    ``SessionConfig(skill_directories=[...])``.

    Args:
        project_root: Path to the project root directory.
                      If None, only user-level paths are returned.

    Returns:
        A list of absolute directory paths that exist on disk.
        May be empty if no skill directories are found.

    Example:
        >>> dirs = get_skill_directories("/home/user/my-project")
        >>> session = await client.create_session(SessionConfig(
        ...     skill_directories=dirs,
        ... ))
    """
    # E2: Check cache before doing filesystem checks
    cache_key = project_root or "__none__"
    if (
        _dirs_cache["key"] == cache_key
        and _dirs_cache["result"] is not None
        and (time.time() - _dirs_cache["time"]) < _CACHE_TTL_SECONDS
    ):
        return _dirs_cache["result"]

    directories: List[str] = []

    # User-level skills: ~/.copilot/skills/
    user_dir = _get_user_skills_dir()
    if user_dir.is_dir():
        directories.append(str(user_dir))

    # Project-level skills: <project_root>/.copilot/skills/
    if project_root is not None:
        project_dir = _get_project_skills_dir(project_root)
        if project_dir.is_dir():
            directories.append(str(project_dir))

    # E2: Store in cache
    _dirs_cache["result"] = directories
    _dirs_cache["key"] = cache_key
    _dirs_cache["time"] = time.time()

    return directories


def get_skill_summary(skills: List[dict]) -> dict:
    """
    Generate a summary of discovered skills.

    This function provides quick statistics for the discovered skills,
    which is useful for the CLI status display.

    Args:
        skills: List of skill dictionaries from discover_all_skills().

    Returns:
        A dictionary with:
        - "total":       Total number of skills discovered
        - "available":   Number of skills whose tool is available
        - "unavailable": Number of skills whose tool is NOT available
        - "user_count":  Number of user-level skills
        - "project_count": Number of project-level skills

    Example:
        >>> skills = discover_all_skills()
        >>> summary = get_skill_summary(skills)
        >>> print(f"Available: {summary['available']}/{summary['total']}")
    """
    total = len(skills)
    available = sum(1 for s in skills if s["tool_available"])
    unavailable = total - available
    user_count = sum(1 for s in skills if s["source"] == "user")
    project_count = sum(1 for s in skills if s["source"] == "project")

    return {
        "total": total,
        "available": available,
        "unavailable": unavailable,
        "user_count": user_count,
        "project_count": project_count,
    }
