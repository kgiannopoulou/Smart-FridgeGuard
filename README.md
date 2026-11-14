# Smart-FridgeGuard

[![CI](https://github.com/kgiannopoulou/Smart-FridgeGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/kgiannopoulou/Smart-FridgeGuard/actions/workflows/ci.yml)

Security monitoring for a fleet of smart refrigerators, built on **ThingsBoard Edge**.
The system simulates refrigerators and user activity, detects suspicious behaviour,
raises security alerts, stores events and produces incident investigation reports.

## Architecture

![Architecture](docs/architecture.svg)

Three simulated refrigerators feed a Python event generator; a detection and correlation
engine classifies events and raises alerts, everything is stored in SQLite, and a Streamlit
SOC dashboard supports alert triage and incident investigation.

## Project status

| Phase | Step | Deliverable | Status |
|-------|------|-------------|--------|
| 1 – Planning, architecture and simulation | 1. Define the project requirements | [requirements.md](requirements.md) | Done |
| | 2. Research the threat and build a threat model | [threat-model.md](threat-model.md) | Done |
| | 3. Design the system architecture | [docs/architecture.md](docs/architecture.md), [diagram](docs/architecture.svg) | Done |
| | 4. Prepare the development environment | [docs/development-setup.md](docs/development-setup.md), venv, project folders, CI | Done |

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m fridgeguard check-env
pytest
streamlit run dashboard/app.py
```

Full instructions: [docs/development-setup.md](docs/development-setup.md).

## Documentation

- [Requirements](requirements.md): functional and non-functional requirements, detection rules, traceability
- [Threat model](threat-model.md): assets, entry points, threat actors, STRIDE analysis, MITRE ATT&CK for ICS mapping, risk rating, defensive controls
- [Architecture](docs/architecture.md): components, data flow, event schema, SQLite schema, detection engine design, configuration, tech stack, security design
- [Development setup](docs/development-setup.md): tools, virtual environment, VS Code, project folders, everyday commands
