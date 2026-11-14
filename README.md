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
| | 5. Build the refrigerator simulation engine | `fridgeguard/simulator/`, [docs/simulation.md](docs/simulation.md) | Done |
| | 6. Build the user and activity simulator | `fridgeguard/generator/`, [docs/simulation.md](docs/simulation.md) | Done |
| 2 – Cybersecurity detection engine | 7. Build the event logging system | `fridgeguard/storage/`, [docs/event-database.md](docs/event-database.md) | Done |

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

## Run the simulation

```powershell
python -m fridgeguard simulate --realtime --speed 60        # live, until Ctrl+C
python -m fridgeguard simulate --duration 3d --show activity # 3 days of data, fast
```

Three refrigerators with different operating ranges follow a thermal model (thermostat,
door openings, sensor noise). Fictional users (`store_manager`, `maintenance_tech`,
`system_admin`, `unknown_user`) log in, change settings and occasionally behave
suspiciously. Role-based access control and a maintenance window decide what is allowed.
All events go to the console, `data/events.jsonl` and the SQLite event database
`data/fridgeguard.db`. See [docs/simulation.md](docs/simulation.md).

## Query the event database

```powershell
python -m fridgeguard events stats
python -m fridgeguard events list --status suspicious
python -m fridgeguard events list --type SETPOINT_CHANGE --device FRIDGE-001
python -m fridgeguard events verify                          # re-check SHA-256 hashes
```

Temperature telemetry and security audit events (logins, setpoint and configuration
changes with user, source IP, previous/new value and status) are stored in separate
append-only tables. See [docs/event-database.md](docs/event-database.md).

## Documentation

- [Requirements](requirements.md): functional and non-functional requirements, detection rules, traceability
- [Threat model](threat-model.md): assets, entry points, threat actors, STRIDE analysis, MITRE ATT&CK for ICS mapping, risk rating, defensive controls
- [Architecture](docs/architecture.md): components, data flow, event schema, SQLite schema, detection engine design, configuration, tech stack, security design
- [Development setup](docs/development-setup.md): tools, virtual environment, VS Code, project folders, everyday commands
- [Simulation](docs/simulation.md): refrigerator thermal model, reading format, users and roles, authentication, authorization, activity events
- [Event database](docs/event-database.md): telemetry vs. security audit events, event fields and types, status, integrity, CLI and SQL access
