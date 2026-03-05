# Consolidation Plan: AgentSec + sec-check → One Repo

**Date**: March 5, 2026
**Target remote**: `https://github.com/alxayo/sec-check.git` (branch: `main`)
**Local repo**: `c:\code\AgentSec` (no remotes configured)

---

## 1. Background & Analysis

### What is sec-check (remote)?

 **VS Code Copilot toolkit** focused on security scanning. It provides:

- **1 custom agent**: `@sechek.security-scanner` — Malicious Code Scanner Agent for deep security analysis
- **8 security scanning skills**: bandit, checkov, dependency-check, eslint, guarddog, shellcheck, graudit, trivy
- **10+ custom prompts**: `/sechek.security-scan`, `/sechek.tools-advisor`, `/sechek.plan-fix`, and targeted scan variants
- **Attack patterns reference**: `.github/.context/` with pattern databases
- **Security research**: `research/techniques/sandboxing.md`, `research/eslint-security-reference.md`
- **Example scan output**: `audit-results/` with 6+ real scan report files demonstrating the toolkit in action

**Repository structure (remote)**:

```
.github/
├── agents/
│   └── sechek.malicious-code-scanner.agent.md
├── skills/
│   ├── bandit-security-scan/
│   ├── checkov-security-scan/
│   ├── dependency-check-security-scan/
│   ├── eslint-security-scan/
│   ├── guarddog-security-scan/
│   ├── shellcheck-security-scan/
│   ├── graudit-security-scan/
│   └── trivy-security-scan/
├── prompts/                        (custom prompt files)
└── .context/                       (attack patterns reference)
research/
├── techniques/sandboxing.md
└── eslint-security-reference.md
audit-results/                      (example scan reports)
media/                              (README images)
README.md
```

### What is AgentSec (local)?

A **standalone CLI/SDK tool** that automates and orchestrates the sec-check skills programmatically. Built with the GitHub Copilot SDK + Microsoft Agent Framework. It provides:

- **SecurityScannerAgent** (`core/agentsec/agent.py`): Per-scan session factory, dynamic system messages, Copilot CLI tool orchestration
- **ParallelScanOrchestrator** (`core/agentsec/orchestrator.py`): 3-phase concurrent sub-agent scanning using asyncio
- **CLI** (`cli/agentsec_cli/main.py`): `agentsec scan <folder>` command with config options
- **Configuration system** (`core/agentsec/config.py`): YAML-based config, CLI overrides, custom system messages
- **Dynamic skill discovery** (`core/agentsec/skill_discovery.py`): `SCANNER_REGISTRY` with file classification and scanner relevance mapping
- **Progress tracking** (`core/agentsec/progress.py`): Real-time progress events with `contextvars.ContextVar` for concurrency safety
- **Session management** (`core/agentsec/session_runner.py`): Activity-based waiting, nudge system, transient error retry
- **Tool health monitoring** (`core/agentsec/tool_health.py`): Stuck detection, error pattern matching, retry loop detection
- **Dev agents**: Implementation and orchestrator agents for Copilot-assisted development
- **Copilot SDK skill**: `.github/skills/copilot-sdk/SKILL.md` for SDK development guidance
- **Architecture docs**: `spec/` with plans and implementation details

**Repository structure (local)**:

```
.github/
├── copilot-instructions.md          (comprehensive dev guide)
├── agents/
│   ├── implementation.agent.md      (dev agent)
│   ├── orchestrator.agent.md        (dev agent)
│   └── context/
│       ├── copilot-sdk-error-handle.md
│       ├── multiple-sessions.md
│       └── persisting-sessions.md
├── skills/
│   └── copilot-sdk/SKILL.md
└── instructions/
    └── copilot-sdk-python.instructions.md
.vscode/
├── copilot-sdk.instructions.md
└── python-copilot-sdk.instructions.md
core/
├── pyproject.toml
├── agentsec/
│   ├── agent.py, config.py, orchestrator.py
│   ├── session_runner.py, session_logger.py
│   ├── skill_discovery.py, tool_health.py
│   ├── progress.py, skills.py
│   └── __init__.py
└── tests/
    ├── test_progress.py
    └── test_skills.py
cli/
├── pyproject.toml
└── agentsec_cli/main.py
spec/
├── plan-agentSec.md
├── implementation-plan.md
├── subagent-orchestration-guide.md
└── custom-skills.md
test-scan/
├── vulnerable_app.py
└── utils.py
README.md
SETUP.md
agentsec.example.yaml
activate.sh
.editorconfig
.env.example
```

### How they relate

These projects are **complementary layers** of the same security scanning system:

| Aspect | sec-check (remote) | AgentSec (local) |
|--------|-------------------|------------------|
| **Purpose** | Define *what* to scan for | Automate *how* to run scans |
| **Interface** | VS Code Copilot (manual) | Standalone CLI + SDK (programmatic) |
| **Key assets** | Skills, prompts, agent definition, attack patterns | Agent engine, orchestrator, CLI, config system |
| **User interaction** | `/sechek.security-scan` in VS Code chat | `agentsec scan ./folder` in terminal |
| **Dependencies** | Security tools (bandit, graudit, etc.) | Copilot SDK + sec-check skills |

AgentSec's `SCANNER_REGISTRY` in `skill_discovery.py` directly references the sec-check skills by name (bandit-security-scan, graudit-security-scan, etc.). After consolidation, these skill definitions will be co-located in the same repo.

---

## 2. Conflict Analysis

### File-level conflict check

| Path | Local | Remote | Conflict? |
|------|-------|--------|-----------|
| `README.md` | Yes | Yes | **YES — manual merge required** |
| `.github/copilot-instructions.md` | Yes | Unknown (verify during merge) | **POSSIBLE — manual merge if exists** |
| `.github/agents/` | 2 files + context/ | 1 file | **NO** — different file names |
| `.github/skills/` | 1 skill (copilot-sdk/) | 8 skills (security scanners) | **NO** — different subdirectory names |
| `.github/prompts/` | Missing | Yes | **NO** — addition only |
| `.github/.context/` | Missing | Yes | **NO** — addition only |
| `.github/instructions/` | Yes | Missing | **NO** — addition only |
| `.vscode/` | Yes | Missing | **NO** — addition only |
| `core/`, `cli/`, `spec/`, `test-scan/` | Yes | Missing | **NO** — addition only |
| `research/`, `audit-results/`, `media/` | Missing | Yes | **NO** — addition only |

**Result**: Only `README.md` is a confirmed conflict. `.github/copilot-instructions.md` may also conflict (needs verification during merge).

### Directory merge detail

**`.github/agents/` — merges cleanly (different filenames)**:
- Local: `implementation.agent.md`, `orchestrator.agent.md`, `context/*.md`
- Remote: `sechek.malicious-code-scanner.agent.md`

**`.github/skills/` — merges cleanly (different subdirectories)**:
- Local: `copilot-sdk/SKILL.md`
- Remote: `bandit-security-scan/`, `checkov-security-scan/`, `dependency-check-security-scan/`, `eslint-security-scan/`, `guarddog-security-scan/`, `shellcheck-security-scan/`, `graudit-security-scan/`, `trivy-security-scan/`

---

## 3. Target Merged Structure

```
.github/
├── copilot-instructions.md          ← MERGED (content from both repos)
├── agents/
│   ├── sechek.malicious-code-scanner.agent.md  ← remote (security scanner agent)
│   ├── implementation.agent.md                 ← local  (dev task agent)
│   ├── orchestrator.agent.md                   ← local  (dev orchestrator agent)
│   └── context/                                ← local  (SDK reference docs)
│       ├── copilot-sdk-error-handle.md
│       ├── multiple-sessions.md
│       └── persisting-sessions.md
├── skills/
│   ├── copilot-sdk/                            ← local  (SDK development skill)
│   │   └── SKILL.md
│   ├── bandit-security-scan/                   ← remote (Python scanner)
│   ├── checkov-security-scan/                  ← remote (IaC scanner)
│   ├── dependency-check-security-scan/         ← remote (SCA scanner)
│   ├── eslint-security-scan/                   ← remote (JS/TS scanner)
│   ├── guarddog-security-scan/                 ← remote (supply chain scanner)
│   ├── shellcheck-security-scan/               ← remote (shell scanner)
│   ├── graudit-security-scan/                  ← remote (multi-language scanner)
│   └── trivy-security-scan/                    ← remote (container/IaC scanner)
├── prompts/                                    ← remote (custom prompts)
├── .context/                                   ← remote (attack patterns)
└── instructions/
    └── copilot-sdk-python.instructions.md      ← local  (Python SDK guide)

.vscode/                                        ← local
├── copilot-sdk.instructions.md
└── python-copilot-sdk.instructions.md

core/                                           ← local  (SDK agent library)
├── pyproject.toml
├── README.md
├── agentsec/
│   ├── __init__.py
│   ├── agent.py                  (SecurityScannerAgent)
│   ├── config.py                 (AgentSecConfig)
│   ├── orchestrator.py           (ParallelScanOrchestrator)
│   ├── session_runner.py         (run_session_to_completion)
│   ├── session_logger.py         (per-session file logging)
│   ├── skill_discovery.py        (SCANNER_REGISTRY, classify_files)
│   ├── tool_health.py            (health monitoring)
│   ├── progress.py               (ProgressTracker)
│   └── skills.py                 (legacy @tool functions)
└── tests/
    ├── test_progress.py
    └── test_skills.py

cli/                                            ← local  (CLI wrapper)
├── pyproject.toml
├── README.md
└── agentsec_cli/
    ├── __init__.py
    └── main.py

spec/                                           ← local  (architecture docs)
├── plan-agentSec.md
├── implementation-plan.md
├── subagent-orchestration-guide.md
├── custom-skills.md
└── consolidation-plan.md           (THIS FILE)

test-scan/                                      ← local  (test data)
├── vulnerable_app.py
└── utils.py

research/                                       ← remote (security research)
├── techniques/
│   └── sandboxing.md
└── eslint-security-reference.md

audit-results/                                  ← remote (example scan reports)
├── scan-results.md
├── scan-tools-recomend.md
├── remediation-tasks.md
├── 001-scan-results.md
├── 002-scan-results.md
├── 002-tools-audit.md
└── 003-no-skills-scan-results.md

media/                                          ← remote (README images)

README.md                                       ← MERGED (unified)
SETUP.md                                        ← local
agentsec.example.yaml                           ← local
activate.sh                                     ← local
.editorconfig                                   ← local
.env.example                                    ← local
.gitignore                                      ← MERGED (patterns from both)
```

---

## 4. Execution Plan

### Phase 1: Preparation (local, safe, reversible)

> **Risk**: None — all operations are local and reversible.

#### Step 1.1: Backup the local repo

```powershell
Copy-Item -Recurse -Force "c:\code\AgentSec" "c:\code\AgentSec-backup"
```

**Verify**: `Test-Path c:\code\AgentSec-backup\.git` returns `True`

#### Step 1.2: Ensure local repo is clean

```powershell
cd c:\code\AgentSec
git status
```

**Expected**: Working tree clean, all changes committed. If not, commit or stash first:

```powershell
git add -A
git commit -m "Pre-consolidation snapshot"
```

#### Step 1.3: Add sec-check as the remote

```powershell
git remote add origin https://github.com/alxayo/sec-check.git
git fetch origin
```

**Verify**: `git remote -v` shows `origin` pointing to `https://github.com/alxayo/sec-check.git`
**Verify**: `git branch -r` shows `origin/main`

#### Step 1.4: Create a working branch

```powershell
git checkout -b consolidation
```

**Verify**: `git branch` shows `* consolidation`

---

### Phase 2: Merge with unrelated histories

> **Risk**: Medium — merge could have conflicts. The `--no-commit` flag gives you a chance to review before committing.

#### Step 2.1: Merge remote main into local

```powershell
git merge origin/main --allow-unrelated-histories --no-commit
```

**Why `--allow-unrelated-histories`**: The two repos share no common ancestor (completely separate git histories). Without this flag, git refuses the merge.

**Why `--no-commit`**: Pauses before committing so you can review the staged result, resolve conflicts, and make manual edits.

**Expected outcome**:
- Most files merge cleanly (additive — different paths)
- `README.md` will show as **CONFLICT** (both repos have this file)
- `.github/copilot-instructions.md` **may** show as CONFLICT if the remote has one

#### Step 2.2: Resolve README.md conflict

Open `README.md` and create a unified version with this structure:

```markdown
# Sec-Check

[Banner image from remote README]

Scan untrusted code for red flags — exfiltration, reverse shells, backdoors,
and supply-chain traps. Available as a VS Code Copilot toolkit AND as a
standalone CLI tool.

## What It Does
(from remote README — toolkit description)

## Components

### VS Code Toolkit
(from remote README — agent, skills table, prompts table, remediation planning)

### Standalone CLI Tool (AgentSec)
(from local README — agentsec scan command, parallel mode, config system)

## Quick Start

### Option A: VS Code Copilot Toolkit
(from remote — /sechek.security-scan, targeted scans, tool workflow)

### Option B: Standalone CLI
(from local — pip install, agentsec scan, config options)

## Repository Structure
(updated to reflect the merged layout from Section 3 of this plan)

## Setup & Development
See [SETUP.md](SETUP.md) for detailed setup instructions.

## Output
(from remote — table showing generated files)

## Limitations
(from remote — pattern-based detection caveats)
```

**Key points**:
- Lead with the sec-check identity (it's the established project with GitHub presence)
- Add AgentSec as a second usage mode, not a replacement
- Update the repository structure section to match the merged layout
- Link to `SETUP.md` for the standalone tool setup details

#### Step 2.3: Resolve .github/copilot-instructions.md (if conflicted)

If the remote has its own `copilot-instructions.md`, merge both with this structure:

```markdown
# Sec-Check — AI Agent Coding Guide

## Part 1: Security Scanning Toolkit
(content from REMOTE copilot-instructions.md — skills usage, prompt guidance,
agent behavior, attack pattern reference)

## Part 2: AgentSec SDK Development
(content from LOCAL copilot-instructions.md — project architecture, critical
development workflows, configuration system, progress tracking, code quality
standards, etc.)
```

If the remote does NOT have one, the local version is added cleanly with no editing needed.

#### Step 2.4: Merge .gitignore

Combine ignore patterns from both repos. The local repo likely has:

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
venv/
.env

# IDE
.vscode/settings.json
```

The remote may have different patterns. Ensure both sets are present in the final file.

---

### Phase 3: Review & verify

> **Risk**: Low — read-only verification steps.

#### Step 3.1: Review the staged merge

```powershell
git status
git diff --cached --stat
```

**Check that ALL of these are present in the staged changes**:

| Source | Path | Check |
|--------|------|-------|
| Remote | `.github/skills/bandit-security-scan/` | `Test-Path .github/skills/bandit-security-scan` |
| Remote | `.github/skills/trivy-security-scan/` | `Test-Path .github/skills/trivy-security-scan` |
| Remote | `.github/agents/sechek.malicious-code-scanner.agent.md` | `Test-Path ".github/agents/sechek.malicious-code-scanner.agent.md"` |
| Remote | `.github/prompts/` | `Test-Path .github/prompts` |
| Remote | `.github/.context/` | `Test-Path ".github/.context"` |
| Remote | `research/` | `Test-Path research` |
| Remote | `audit-results/` | `Test-Path audit-results` |
| Remote | `media/` | `Test-Path media` |
| Local | `.github/skills/copilot-sdk/` | `Test-Path .github/skills/copilot-sdk` |
| Local | `.github/agents/implementation.agent.md` | `Test-Path .github/agents/implementation.agent.md` |
| Local | `.github/agents/context/` | `Test-Path .github/agents/context` |
| Local | `.github/instructions/` | `Test-Path .github/instructions` |
| Local | `.vscode/` | `Test-Path .vscode` |
| Local | `core/agentsec/agent.py` | `Test-Path core/agentsec/agent.py` |
| Local | `cli/agentsec_cli/main.py` | `Test-Path cli/agentsec_cli/main.py` |
| Local | `spec/` | `Test-Path spec` |
| Local | `test-scan/` | `Test-Path test-scan` |

#### Step 3.2: Verify no files were accidentally overwritten

```powershell
# Count files from each source
git diff --cached --name-only | Measure-Object  # Total files added/modified
```

Cross-reference against the file inventories in Section 2 of this plan.

#### Step 3.3: Quick automated sanity check (PowerShell)

```powershell
# Verify all 9 skill directories exist
$skills = @(
    "copilot-sdk", "bandit-security-scan", "checkov-security-scan",
    "dependency-check-security-scan", "eslint-security-scan",
    "guarddog-security-scan", "shellcheck-security-scan",
    "graudit-security-scan", "trivy-security-scan"
)
$skills | ForEach-Object {
    $path = ".github/skills/$_"
    if (Test-Path $path) { Write-Host "OK: $path" }
    else { Write-Host "MISSING: $path" -ForegroundColor Red }
}

# Verify all 3 agent definitions exist
@(
    ".github/agents/sechek.malicious-code-scanner.agent.md",
    ".github/agents/implementation.agent.md",
    ".github/agents/orchestrator.agent.md"
) | ForEach-Object {
    if (Test-Path $_) { Write-Host "OK: $_" }
    else { Write-Host "MISSING: $_" -ForegroundColor Red }
}

# Verify core SDK files exist
@(
    "core/agentsec/agent.py", "core/agentsec/config.py",
    "core/agentsec/orchestrator.py", "core/agentsec/skill_discovery.py",
    "cli/agentsec_cli/main.py"
) | ForEach-Object {
    if (Test-Path $_) { Write-Host "OK: $_" }
    else { Write-Host "MISSING: $_" -ForegroundColor Red }
}
```

---

### Phase 4: Commit the merge

> **Risk**: Low — local commit only.

#### Step 4.1: Stage any manual edits

```powershell
git add README.md
git add .github/copilot-instructions.md   # if manually merged
git add .gitignore                          # if merged
```

#### Step 4.2: Commit

```powershell
git commit -m "Consolidate AgentSec SDK tool into sec-check repo

Merges the standalone Copilot SDK security scanning tool (agent, CLI,
parallel orchestrator) with the sec-check prompt/skill/agent definitions.

- Added: core/ (SDK agent library), cli/ (agentsec command)
- Added: spec/ (architecture docs), test-scan/ (test data)
- Added: .vscode/ instructions, .github/instructions/
- Added: .github/skills/copilot-sdk/ (SDK development skill)
- Added: .github/agents/ (implementation + orchestrator dev agents)
- Preserved: All 8 security scanner skills, prompts, agent, research, audit-results
- Merged: README.md (unified), copilot-instructions.md (combined)
- Merged: .gitignore (combined patterns)"
```

---

### Phase 5: Push to remote

> **Risk**: High — this modifies the remote repository. Requires explicit confirmation.

#### Step 5.1: Push the consolidation branch

```powershell
git push -u origin consolidation
```

This pushes the merge to a new branch on the remote. It does NOT modify `main`.

#### Step 5.2: Merge into main (choose one approach)

**Option A — Create a Pull Request (recommended if collaborating)**:

Go to `https://github.com/alxayo/sec-check/compare/main...consolidation` and create a PR for review.

**Option B — Direct merge (if sole contributor)**:

```powershell
git checkout main
git pull origin main            # ensure local main is up to date
git merge consolidation         # fast-forward or merge commit
git push origin main
```

#### Step 5.3: Clean up

```powershell
# Delete the working branch
git branch -d consolidation
git push origin --delete consolidation

# Remove backup if everything looks good
# Remove-Item -Recurse -Force "c:\code\AgentSec-backup"
```

---

## 5. Post-Merge Verification Checklist

Run these checks after the merge is complete and pushed:

- [ ] **GitHub web UI**: Visit `https://github.com/alxayo/sec-check` and verify the full merged structure is visible
- [ ] **README renders correctly**: Check that the unified README displays properly with images and links
- [ ] **Skills accessible**: Navigate to `.github/skills/` on GitHub — all 9 skills should be listed
- [ ] **Agent definitions**: Navigate to `.github/agents/` — all 3 agent files should be present
- [ ] **Prompts**: Navigate to `.github/prompts/` — all prompt files present
- [ ] **Core module**: Navigate to `core/agentsec/` — all Python files present
- [ ] **CLI module**: Navigate to `cli/agentsec_cli/` — `main.py` present
- [ ] **CLI test** (local): Install and verify the CLI still works:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  pip install -e ./core
  pip install -e ./cli
  agentsec --help
  ```
- [ ] **Unit tests** (local): Run existing tests:
  ```powershell
  cd core
  python -m pytest tests/ -v
  ```
- [ ] **No broken file references**: Verify that paths in `copilot-instructions.md` still point to existing files
- [ ] **Git log**: Run `git log --oneline --graph` to verify both repos' histories are preserved

---

## 6. Post-Merge Recommendations (Future Work)

These are **not part of the merge** but should be addressed afterward:

1. **Update `skill_discovery.py`**: The `SCANNER_REGISTRY` references scanner skills by name. After the merge, these skill definitions are co-located in `.github/skills/`. Consider updating any skill directory paths that reference `~/.copilot/skills/` to use the repo-local `.github/skills/` instead.

2. **Update `copilot-instructions.md` file references**: The "Essential Files to Know" table in the local copilot-instructions references file paths. Verify all paths are correct in the merged repo context.

3. **Add `.github/copilot-instructions.md` cross-references**: If the two copilot-instructions sections reference each other's files, add hyperlinks between them.

4. **Consider a unified project name**: The project currently has two names: "sec-check" / "sechek" (the toolkit) and "AgentSec" (the standalone tool). Consider whether to unify the naming or keep both as distinct product names for different usage modes.

5. **Desktop app**: The local repo has a `desktop/` directory placeholder for a future Electron + FastAPI + Next.js GUI. This is not yet implemented. After merge, ensure the `desktop/backend/` and `desktop/frontend/` structure is preserved if any files exist.

6. **CI/CD**: Consider adding GitHub Actions workflows for:
   - Running `core/tests/` on PRs
   - Linting Python code
   - Publishing `agentsec` CLI to PyPI

---

## 7. Rollback Plan

If something goes wrong at any phase:

| Phase | Rollback |
|-------|----------|
| Phase 1 (Preparation) | Delete and restore from backup: `Remove-Item -Recurse c:\code\AgentSec; Copy-Item -Recurse c:\code\AgentSec-backup c:\code\AgentSec` |
| Phase 2 (Merge) | Abort the merge: `git merge --abort` |
| Phase 3 (Review) | Reset: `git reset --hard HEAD` (before commit) |
| Phase 4 (Commit) | Undo commit: `git reset --soft HEAD~1` |
| Phase 5 (Push) | Force-push original main: `git push origin main --force` (destructive, use with caution) |

---

## 8. Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Merge strategy | `--allow-unrelated-histories` flat merge | Both repos use `.github/` conventions; flat merge keeps them co-located naturally |
| README approach | Unified — one file covering both usage modes | User chose this option; avoids confusion about which README is canonical |
| copilot-instructions | Merged into one comprehensive file | User chose this option; single source of truth for AI coding guidance |
| audit-results | Kept in merged repo | User chose to keep; they serve as example output / documentation |
| Remote name | `origin` → `https://github.com/alxayo/sec-check.git` | Standard convention; local repo had no remotes |
| Git history | Both preserved | `--allow-unrelated-histories` keeps full commit history from both repos |
| Branch strategy | Merge on `consolidation` branch first | Safer than direct merge to main; allows review before pushing |
