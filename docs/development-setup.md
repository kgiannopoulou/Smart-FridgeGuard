# Smart-FridgeGuard — Development Environment

**Phase:** 1 – Planning, architecture and simulation
**Step:** 4 – Prepare the development environment
**Status:** Done (2026-11-14)

---

## 1. Tools

| Technology | Purpose | Version used | Where it is configured |
|------------|---------|--------------|------------------------|
| Python | Main programming language | 3.14 locally (3.12+ supported; CI tests 3.12 and 3.13) | `pyproject.toml` → `requires-python` |
| VS Code | Development environment | 1.145 | `.vscode/` |
| Git / GitHub | Version control, CI | Git 2.47, GitHub Actions | `.gitignore`, `.github/workflows/ci.yml` |
| pandas | Event and data analysis | 3.1 | `pyproject.toml` |
| SQLite | Database | 3.50 (Python standard library `sqlite3`) | nothing to install |
| Streamlit | Dashboard | 1.67 | `app.py` |
| Plotly | Charts and visualisation | 7.1 | `pyproject.toml` |
| pytest | Testing | 9.2 | `pyproject.toml` → `[tool.pytest.ini_options]` |

Supporting libraries, already listed in the architecture (docs/architecture.md §9):

| Library | Purpose |
|---------|---------|
| PyYAML | Reading `config/*.yaml` and `scenarios/*.yaml` |
| pydantic | Event schema validation |
| Jinja2 | Incident report templates |
| ruff | Linting and formatting (dev only) |
| pytest-cov | Test coverage (dev only) |

## 2. First-time setup

Prerequisites: Python 3.12 or newer, Git, VS Code.

```powershell
# 1. Clone
git clone https://github.com/kgiannopoulou/Smart-FridgeGuard.git
cd Smart-FridgeGuard

# 2. Create and activate the virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1          # Windows PowerShell
# source .venv/bin/activate         # Linux / macOS

# 3. Install the project (editable) with development tools
python -m pip install --upgrade pip
pip install -e ".[dev]"
# (or: pip install -r requirements.txt, then run the scripts from the repository root)

# 4. Create your local secrets file (never committed)
copy .env.example .env               # cp .env.example .env on Linux / macOS

# 5. Verify the environment
python -m fridgeguard check-env
pytest
```

Expected output of the environment check:

```
[OK] Python 3.14.7 (need >= 3.12)
[OK] pandas 3.1.1
[OK] streamlit 1.67.0
[OK] plotly 7.1.0
[OK] pytest 9.2.0
[OK] yaml 6.0.3
[OK] pydantic 2.14.3
[OK] jinja2 3.1.6
[OK] fpdf 2.9.0
[OK] SQLite 3.50.4 (JSON + triggers OK)
[OK] project folders (13) present

11/11 checks passed
```

The SQLite check does more than confirm SQLite exists: it creates a table, uses the JSON
functions and confirms that a trigger blocks an `UPDATE`. The storage design depends on
those features (append-only events, JSON payloads).

## 3. Everyday commands

| Task | Command |
|------|---------|
| Run tests | `pytest` |
| Tests with coverage | `pytest --cov=fridgeguard` |
| Lint | `ruff check .` |
| Format | `ruff format .` |
| Environment check | `python -m fridgeguard check-env` |
| Start the dashboard | `streamlit run app.py` → http://localhost:8501 |

## 4. VS Code

Open the folder in VS Code and accept the recommended extensions prompt.

| File | What it does |
|------|--------------|
| `.vscode/settings.json` | Uses `.venv` as the interpreter, enables pytest in the Testing panel, formats with ruff on save. |
| `.vscode/extensions.json` | Recommends Python, Pylance, Ruff, SQLite Viewer, YAML and Markdown Mermaid extensions. |
| `.vscode/launch.json` | Debug configurations: *Streamlit dashboard* and *fridgeguard check-env*. |

If VS Code does not pick up the interpreter: `Ctrl+Shift+P` → *Python: Select Interpreter* →
`.venv\Scripts\python.exe`.

## 5. Project folders

Summary of the full layout in [architecture.md §8](architecture.md#8-repository-layout).

```
Smart-FridgeGuard/
├── .github/workflows/ci.yml   # CI: lint, env check, tests on Python 3.12 and 3.13
├── .vscode/                   # editor settings, extensions, debug configs
├── app.py                     # Streamlit SOC dashboard entry point
├── simulator.py … notifications.py   # root entry points for the CLI commands
├── config/                    # *.yaml: devices, users, detection, correlation, ...
├── scenarios/                 # system test plan TC-01..TC-10
├── fridgeguard/               # main Python package (CLI: python -m fridgeguard)
├── dashboard/views/           # one file per dashboard page
├── templates/                 # report templates
├── tests/                     # pytest test suite
├── data/                      # SQLite database (git-ignored)
├── reports/                   # generated reports (git-ignored)
├── logs/                      # operational log (git-ignored)
├── docs/                      # all documentation
├── screenshots/               # dashboard screenshots
├── requirements.txt           # pip install -r requirements.txt
├── .env.example               # template for local secrets
└── pyproject.toml             # dependencies and tool configuration
```

## 6. Security practices for the environment (NFR-6)

- `.env` is git-ignored; only `.env.example` with empty values is committed.
- `data/` and `reports/` are git-ignored, so generated databases and reports never reach GitHub.
- `.venv/` is git-ignored and recreated from `pyproject.toml`.
- CI runs with read-only repository permissions (`permissions: contents: read`).

## 7. Troubleshooting

| Problem | Fix |
|---------|-----|
| `Activate.ps1 cannot be loaded because running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ModuleNotFoundError: fridgeguard` | Activate `.venv` and run `pip install -e ".[dev]"` again. |
| Streamlit port 8501 in use | `streamlit run app.py --server.port 8502` |
| VS Code Testing panel is empty | Select the `.venv` interpreter, then *Testing → Refresh*. |
