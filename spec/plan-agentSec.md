# AgentSec - AI-Powered Security Scanner Specification Plan

## Overview

Build a cross-platform security scanning application using GitHub Copilot SDK (https://github.com/github/awesome-copilot/blob/main/cookbook/copilot-sdk/python/README.md) with dual interfaces: a Python CLI for developers and a Next.js/Electron GUI for broader audiences. The agent will use attached skills (tools) to scan folders for security vulnerabilities, with all processing running locally except LLM inference via GitHub Copilot.

**Architecture**: Monorepo with 3 packages
- `agentsec-core`: Shared Python agent + skills library
- `agentsec-cli`: Command-line interface (distributes via PyPI)
- `agentsec-desktop`: Next.js frontend + Electron wrapper (distributes as native installer)

**Communication Flow**: CLI directly invokes agent → GUI calls FastAPI server → FastAPI invokes same agent → Results stream back via SSE

---

## Implementation Phases

### Phase 1: Core Agent Foundation

**1. Project scaffolding** (*parallel with step 2*)
- Create monorepo structure: `agentsec/` with subdirs `core/`, `cli/`, `desktop/`
- Initialize Python package in `core/` with `pyproject.toml` (dependencies: `agent-framework-core==1.0.0b260107`, `agent-framework-azure-ai==1.0.0b260107`)
- Create virtual environment at workspace root
- Add `.env` template for Azure OpenAI/GitHub Copilot credentials

**2. Agent implementation with skills** (*parallel with step 1*)
- Define security scanner agent in `core/agentsec/agent.py` with system instructions
- Implement built-in skills in `core/agentsec/skills.py` using `@tool` decorator:
  - `list_files(folder_path: str)`: Enumerate files in target directory
  - `analyze_file(file_path: str)`: Analyze a file for security vulnerabilities
  - `generate_report(findings: list)`: Format scan results
- Agent uses **Copilot CLI built-in tools** (bash, skill, view) as its primary scanning mechanism:
  - `bash`: Runs file discovery commands and security scanner CLIs (bandit, graudit, etc.)
  - `skill`: Invokes Copilot CLI agentic skills (bandit-security-scan, graudit-security-scan, etc.)
  - `view`: Reads file contents for manual code inspection
- Directive system message explicitly lists available tools and workflows with safety guardrails
- Stall detection system monitors tool activity and sends nudge messages if the LLM gets stuck
- Configurable scan timeout (default 300s) with partial results returned on timeout

**3. Verification** (*depends on 1, 2*)
- Install dependencies in virtual environment
- Create minimal test script to invoke agent with skills
- Verify agent calls Copilot CLI tools (bash, skill, view) to scan code
- Verify stall detection sends nudge messages when the LLM is inactive
- Verify partial results are captured on timeout

### Phase 2: CLI Interface

**4. CLI entry point** (*depends on 3*)
- Create `cli/agentsec_cli/main.py` with argparse for commands:
  - `agentsec scan <folder>`: Run security scan
  - `agentsec --version`: Show version
- Import agent from `agentsec-core` package
- Stream agent responses to stdout with progress indicators
- Add error handling for missing credentials/invalid paths

**5. CLI packaging** (*depends on 4*)
- Configure `cli/pyproject.toml` for PyPI distribution
- Set up console script entry point: `agentsec = agentsec_cli.main:cli`
- Create `cli/README.md` with installation and usage instructions
- Test installation in clean virtual environment: `pip install -e .`

### Phase 3: GUI Backend (HTTP Server)

**6. FastAPI server** (*depends on 3, parallel with step 7*)
- Create `desktop/backend/server.py` using FastAPI
- Add CORS middleware for Next.js frontend (origins: `localhost:3000`)
- Use `add_agent_framework_fastapi_endpoint()` from `agent_framework.ag_ui` to expose agent at `/api/scan`
- Implement SSE endpoint for streaming scan progress
- Add health check endpoint `/api/health`

**7. Server startup/shutdown scripts** (*depends on 6, parallel with step 6*)
- Create Python script to launch server on dynamic port (finds available port)
- Write port number to temp file for Electron to read
- Implement graceful shutdown handler (SIGTERM/SIGINT)

### Phase 4: GUI Frontend (Next.js/React)

**8. Next.js application scaffolding** (*parallel with step 9*)
- Initialize Next.js project in `desktop/frontend/` using TypeScript
- Configure API proxy to FastAPI backend (environment variable for base URL)
- Set up TailwindCSS for styling
- Create layout components (header, sidebar, main content area)

**9. Scan UI components** (*parallel with step 8*)
- Build `FolderSelector` component (file picker dialog)
- Build `ScanProgress` component (displays streaming results from SSE)
- Build `ResultsPanel` component (table/cards showing security findings)
- Create main scanning page connecting components
- Implement fetch calls to `/api/scan` with SSE handling

**10. Frontend verification** (*depends on 8, 9*)
- Test Next.js dev server (`npm run dev`)
- Manually start FastAPI server in separate terminal
- Verify end-to-end flow: UI → API → Agent → Results streaming back

### Phase 5: Desktop Packaging (Electron)

**11. Electron wrapper** (*depends on 6, 7, 10*)
- Initialize Electron in `desktop/` with `electron-builder` configuration
- Configure main process (`main.js`) to:
  - Start FastAPI server as child process on app launch
  - Read port from temp file and inject into renderer as env var
  - Kill server process on app quit
  - Handle window lifecycle (minimize to tray optional)
- Configure preload script for secure IPC
- Update Next.js to support Electron (static export or custom server)

**12. Build and distribution setup** (*depends on 11*)
- Configure `electron-builder.json` for Windows (NSIS) and macOS (DMG) installers
- Bundle Python with Electron using PyInstaller or embedding portable Python
- Create build scripts: `npm run build:win`, `npm run build:mac`
- Test installers on both platforms (Windows 10+, macOS 12+)

### Phase 6: Documentation and Handoff

**13. Comprehensive documentation** (*parallel with all previous steps, finalized last*)
- Root `README.md`: Project overview, architecture diagram, quick start
- `core/README.md`: Agent architecture, skills development guide
- `cli/README.md`: CLI usage examples, configuration
- `desktop/README.md`: Desktop app build instructions, development workflow
- Create `.env.example` with required Azure OpenAI/GitHub Copilot variables
- Add architecture diagram (ASCII or link to diagram tool)

**14. Development tooling** (*depends on 3, 6*)
- Add VS Code `launch.json` for debugging agent, CLI, and FastAPI server
- Add VS Code `tasks.json` for common operations (start server, run CLI, build desktop)
- Configure AI Toolkit Agent Inspector for tracing (optional but recommended)

---

## Relevant Files to Create

**Core Agent Package:**

- `agentsec/core/agentsec/agent.py` — Define `SecurityScannerAgent` using `Agent()` class with system instructions and tool registration
- `agentsec/core/agentsec/skills.py` — Implement `@tool` decorated functions for file scanning skills: `list_files`, `analyze_file`, `generate_report`
- `agentsec/core/agentsec/config.py` — Configuration management with `AgentSecConfig` class for loading YAML config and CLI overrides
- `agentsec/core/agentsec/progress.py` — Progress tracking with `ProgressTracker` class for real-time scan feedback
- `agentsec/core/agentsec/skill_discovery.py` — Dynamic discovery of Copilot CLI agentic skills from `~/.copilot/skills/` (user) and `.copilot/skills/` (project), with tool availability checking
- `agentsec/core/pyproject.toml` — Python package config with dependencies on `agent-framework-core==1.0.0b260107` and `pyyaml>=6.0`
- `agentsec/core/README.md` — Agent architecture and skills development documentation

**CLI Package:**

- `agentsec/cli/agentsec_cli/main.py` — CLI entry point with argparse, imports agent from core, handles stdin/stdout interaction, supports config file and CLI overrides for system message and prompts
- `agentsec/cli/pyproject.toml` — CLI package configuration for PyPI distribution
- `agentsec/cli/README.md` — CLI installation and usage instructions

**Desktop Package - Backend:**

- `agentsec/desktop/backend/server.py` — FastAPI application using `add_agent_framework_fastapi_endpoint()` pattern from AG-UI samples
- `agentsec/desktop/backend/requirements.txt` — Backend Python dependencies (FastAPI, uvicorn, agent packages)

**Desktop Package - Frontend:**

- `agentsec/desktop/frontend/pages/index.tsx` — Main scan UI page with folder selector, scan button, progress display, results table
- `agentsec/desktop/frontend/components/ScanProgress.tsx` — SSE-connected component showing real-time scan status
- `agentsec/desktop/frontend/components/FolderSelector.tsx` — File picker component for selecting scan target
- `agentsec/desktop/frontend/components/ResultsPanel.tsx` — Display security findings in structured format
- `agentsec/desktop/frontend/package.json` — Next.js dependencies and scripts

**Desktop Package - Electron:**

- `agentsec/desktop/main.js` — Electron main process managing FastAPI subprocess lifecycle and window creation
- `agentsec/desktop/preload.js` — Secure IPC bridge between main and renderer processes
- `agentsec/desktop/electron-builder.json` — Build configuration for Windows/macOS installers with Python bundling
- `agentsec/desktop/package.json` — Electron dependencies and build scripts

**Configuration:**

- `agentsec/.env.example` — Template for Azure OpenAI endpoint, API key, deployment name
- `agentsec/agentsec.example.yaml` — Example YAML configuration file with system_message and initial_prompt settings
- `agentsec/.gitignore` — Ignore venv, node_modules, .env, build artifacts
- `agentsec/README.md` — Root project documentation with architecture overview

**Development Tooling:**

- `agentsec/.vscode/launch.json` — Debug configurations for agent, CLI, and FastAPI server
- `agentsec/.vscode/tasks.json` — Common development tasks (start server, run CLI, build desktop)

**Patterns to Reuse from Microsoft Agent Framework:**
- HTTP hosting pattern: `python/samples/01-get-started/06_host_your_agent.py`
- AG-UI FastAPI integration: `python/packages/ag-ui/agent_framework_ag_ui_examples/server/main.py`
- Tool definition pattern: `python/samples/02-agents/tools/`
- Workflow orchestration (future): `python/samples/03-workflows/parallelism/`

---

## Verification Checklist

**Phase 1 Verification:**
- [x] Run test script importing agent from core package
- [x] Invoke agent with scan prompt for a test folder
- [x] Confirm agent calls Copilot CLI built-in tools (bash, skill, view)
- [x] Verify real security findings returned via scanner invocations
- [x] Verify stall detection sends nudge messages when LLM is inactive
- [x] Verify partial results captured on timeout

**Phase 2 Verification:**
- [x] Install CLI: `pip install -e ./cli`
- [x] Run: `agentsec scan ./test-scan`
- [x] Confirm scan completes without errors (exit code 0)
- [x] Validate output shows real security findings from scanner invocations
- [x] Verify progress indicators (spinner, progress bar, file counts)
- [x] Verify timeout with partial results displays correctly

**Phase 3 Verification:**
- [ ] Start FastAPI server: `python desktop/backend/server.py`
- [ ] Use `curl` or Postman to POST to `/api/scan` with folder path
- [ ] Confirm SSE stream returns scan progress events
- [ ] Verify `/api/health` returns 200 OK

**Phase 4 Verification:**
- [ ] Start Next.js dev server: `cd desktop/frontend && npm run dev`
- [ ] Open browser to `localhost:3000`
- [ ] Select folder, click scan button
- [ ] Confirm progress updates in real-time
- [ ] Verify results displayed in UI table/cards

**Phase 5 Verification:**
- [ ] Build desktop app: `npm run build:win` (on Windows) or `npm run build:mac` (on macOS)
- [ ] Install built application
- [ ] Launch app, confirm FastAPI starts automatically
- [ ] Run scan through desktop UI
- [ ] Verify scan completes successfully
- [ ] Close app, confirm FastAPI process terminated cleanly

**Phase 6 Verification:**
- [ ] Clone repo to clean environment
- [ ] Follow README quick start instructions
- [ ] Confirm CLI installation works: `pip install agentsec` (when published)
- [ ] Confirm desktop development workflow works: `npm install && npm run dev`
- [ ] Test VS Code debugging configs (F5 to debug agent)

**Optional Automated Testing:**
- [ ] Unit tests for skills in `core/tests/`
- [ ] Integration tests for FastAPI endpoints
- [ ] E2E tests for Electron app using Playwright

---

## Technology Stack Decisions

**Backend/Agent:**
- Python 3.10+ with Microsoft Agent Framework (GitHub Copilot SDK)
- `agent-framework-core==1.0.0b260107` (pinned to avoid breaking changes)
- `agent-framework-azure-ai==1.0.0b260107` for Azure OpenAI integration

**CLI:**
- argparse for argument parsing
- rich (optional) for enhanced terminal formatting

**HTTP Server:**
- FastAPI with AG-UI utilities for agent endpoint exposure
- uvicorn as ASGI server
- CORS middleware for Next.js frontend

**Frontend:**
- Next.js 14+ with TypeScript for type safety
- TailwindCSS for styling
- Server-Sent Events (SSE) for real-time progress updates

**Desktop Shell:**
- Electron with electron-builder for packaging
- Child process management for FastAPI server
- Platform-specific installers (NSIS for Windows, DMG for macOS)

**LLM Inference:**
- Azure OpenAI or GitHub Copilot (cloud service)
- Credentials stored in `.env` file
- Supports OpenAI-compatible endpoints (future: local LLMs via Ollama)

**State Management:**
- In-memory for prototype
- Future enhancement: SQLite for scan history persistence

---

## Architecture Decisions

**Monorepo Structure:**
- Single git repository with separate packages for maintainability
- Shared core package reduces code duplication
- Independent versioning for CLI and Desktop

**Agent-as-Server Pattern:**
- FastAPI wraps agent for HTTP access (proven pattern from AG-UI)
- Both CLI and Desktop use same agent implementation
- Server endpoint handles streaming via SSE

**Process Isolation:**
- Electron spawns FastAPI as subprocess, not embedded
- Easier debugging with language separation
- Clean shutdown handling on app quit

**Distribution Strategy:**
- PyPI for CLI: `pip install agentsec`
- Native installers for Desktop: Windows (NSIS), macOS (DMG)
- Separate packages allow targeted distribution

**Scanning Approach — Copilot CLI Built-in Tools:**
- The agent leverages Copilot CLI's built-in tools (`bash`, `skill`, `view`) as its primary scanning mechanism
- `bash` runs file discovery commands and can invoke security scanner CLIs directly (bandit, graudit, etc.)
- `skill` invokes pre-configured Copilot CLI agentic skills for structured security scanning
- `view` reads file contents for manual code inspection by the LLM
- A highly directive system message guides the LLM through a structured scanning workflow
- Safety guardrails in the system message prevent the LLM from executing scanned code or following prompt injection attempts

**Stall Detection & Nudge System:**
- The `scan()` method polls every 5 seconds instead of using a single blocking wait
- If no tool activity occurs for 30 seconds (configurable via `STALL_DETECTION_SECONDS`), a nudge message is sent
- Two types of nudges: redirect nudge (if no security scanners invoked yet) and progress nudge (if stuck after scanning)
- Maximum 2 nudges per scan to avoid spamming the LLM
- Partial results are captured and returned on timeout instead of discarding all work

**Dynamic Skill Discovery:**
- Copilot CLI agentic skills are auto-discovered from two locations: `~/.copilot/skills/` (user-level) and `<project>/.copilot/skills/` (project-level)
- Each skill directory contains a `SKILL.md` with YAML frontmatter (name, description)
- Skills are mapped to their underlying CLI tools via `SKILL_TO_TOOL_MAP` with a fallback heuristic
- Tool availability is verified at runtime using `shutil.which()` — no hardcoded tool lists
- Both user-level and project-level skills are shown in the CLI with availability status

**Cross-Platform Considerations:**
- Python virtual environments work identically on Windows/macOS
- Electron handles OS-specific windowing and installers
- File paths use `pathlib` for platform independence
- FastAPI server uses dynamic port finding to avoid conflicts

---

## Scope Definition

**Included in MVP:**
- ✅ Monorepo setup with core, CLI, and desktop packages
- ✅ Agent with built-in skills (list_files, analyze_file, generate_report)
- ✅ **Real security scanning** via Copilot CLI built-in tools (bash, skill, view) — invokes real security scanners (bandit, graudit, trivy, etc.) via the `skill` tool and `bash`
- ✅ **Directive prompt engineering** — System message explicitly lists available tools, scanning workflows, and safety guardrails to guide the LLM
- ✅ **Stall detection & nudge system** — Monitors tool activity every 5s; sends nudge messages (max 2) if the LLM is inactive for 30s
- ✅ **Configurable scan timeout** — Default 300s, caller-overridable; partial results returned on timeout instead of just an error
- ✅ **Safety guardrails** — System message prevents execution of scanned code, blocks dangerous commands, and defends against prompt injection from analyzed code
- ✅ CLI interface with argparse and stdout streaming
- ✅ Configuration system (YAML config file + CLI overrides)
- ✅ Customizable system message and initial prompt
- ✅ External prompt file support
- ✅ **Progress tracking system** — Real-time feedback on files being scanned
- ✅ **Dynamic skill discovery** — Automatically discovers Copilot CLI agentic skills from `~/.copilot/skills/` (user-level) and `<project>/.copilot/skills/` (project-level), maps each skill to its underlying CLI tool (bandit, trivy, checkov, etc.), and checks tool availability on the system
- ✅ Next.js GUI with folder selection and results display
- ✅ Electron wrapper with FastAPI subprocess management
- ✅ Basic documentation (README files, .env.example, agentsec.example.yaml)
- ✅ Development tooling (VS Code launch configs)

**Excluded (Future Enhancements):**
- ❌ Workflow orchestration for parallel scanning across file types
- ❌ SQLite persistence for scan history
- ❌ Telemetry/tracing with Application Insights
- ❌ Approval workflows UI for critical operations
- ❌ Multi-language scanning (Python, JavaScript, Docker, YAML)
- ❌ Plugin system for extensibility
- ❌ Advanced UI features (filtering, export to PDF/JSON, dashboards)
- ❌ Automated CI/CD pipeline for releases
- ❌ Code signing for installers

**Prototype Simplifications:**
- Basic UI without advanced features
- No authentication/authorization (local app only)
- No network features (future: remote scanning, team sharing)

---

## Risk Assessment

**Technical Risks:**

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Python bundling with Electron increases app size | High | Medium | Use PyInstaller to create minimal Python bundle; accept 150-200MB app size as acceptable for desktop |
| Cross-platform Python subprocess management | Medium | High | Test thoroughly on Windows/macOS; use platform-specific process handling; implement robust error handling |
| SSE streaming issues in Electron | Low | Medium | Use proven AG-UI SSE patterns; fallback to polling if needed |
| Virtual environment conflicts | Medium | Low | Use workspace-local venv; clear documentation on environment setup |

**Process Risks:**

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Scope creep with real security scanners | High | High | Stick to mock implementations for MVP; defer real scanning to Phase 2 |
| Electron complexity slows development | Medium | Medium | Start with Next.js dev mode; add Electron wrapper last |
| Documentation becomes outdated | Medium | Low | Update docs in parallel with implementation; use README checkboxes |

---

## Success Criteria

**Functional Requirements:**
- ✅ CLI can scan a folder and display real security findings in terminal
- ✅ Desktop app can scan a folder and display security findings in GUI
- ✅ Both interfaces use the same agent implementation
- ✅ Desktop app starts/stops FastAPI server automatically
- ✅ Real-time progress updates via SSE in desktop app
- ✅ Cross-platform: Works on Windows 10+ and macOS 12+

**Non-Functional Requirements:**
- ✅ Installation: CLI via pip, Desktop via native installer
- ✅ Performance: Scan initiation within 2 seconds
- ✅ Reliability: Graceful error handling for missing credentials
- ✅ Usability: Clear README with quick start instructions
- ✅ Maintainability: Monorepo with shared core package

**Developer Experience:**
- ✅ VS Code debugging works for all components
- ✅ Virtual environment setup is documented and reproducible
- ✅ Development workflow is smooth (npm scripts, Python scripts)

---

## Timeline Estimate

**Phase 1: Core Agent Foundation** (3-5 days)
- Day 1-2: Project scaffolding, virtual environment, basic agent
- Day 3-4: Implement skills, test agent invocation
- Day 5: Verification and fixes

**Phase 2: CLI Interface** (2-3 days)
- Day 6-7: CLI implementation with argparse
- Day 8: Packaging, documentation, testing

**Phase 3: GUI Backend** (3-4 days)
- Day 9-10: FastAPI server with AG-UI endpoint
- Day 11-12: SSE streaming, health checks, testing

**Phase 4: GUI Frontend** (5-7 days)
- Day 13-15: Next.js scaffolding, UI components
- Day 16-18: SSE integration, styling, testing
- Day 19: End-to-end verification

**Phase 5: Desktop Packaging** (4-6 days)
- Day 20-22: Electron setup, subprocess management
- Day 23-25: Python bundling, installer creation
- Day 26: Cross-platform testing

**Phase 6: Documentation** (2-3 days)
- Day 27-28: README files, architecture diagrams
- Day 29: VS Code tooling, final verification

**Total Estimate: 19-28 days** (4-6 weeks for one developer, 2-3 weeks for a small team)

---

## Next Steps After Approval

1. **Create monorepo structure** in `c:\code\AgentSec`
2. **Initialize Python virtual environment** at workspace root
3. **Install Agent Framework dependencies** (pinned versions)
4. **Implement core agent** with 2-3 mock skills
5. **Verify agent functionality** with test script
6. **Proceed with CLI implementation** (Phase 2)

Would you like me to begin implementation starting with Phase 1?
