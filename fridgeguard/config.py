"""Loading of YAML configuration files from ``config/``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


def load_yaml(name: str, config_dir: Path | None = None) -> dict[str, Any]:
    path = (config_dir or CONFIG_DIR) / name
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def load_dotenv(path: Path | None = None, environ: dict[str, str] | None = None) -> list[str]:
    """Load ``KEY=VALUE`` lines from ``.env`` into the environment without overriding
    variables that are already set. Returns the names that were loaded (never values)."""
    import os

    env = os.environ if environ is None else environ
    path = path or PROJECT_ROOT / ".env"
    if not path.exists():
        return []
    loaded = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().removeprefix("export ").strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value or value.startswith("#"):
            value = value.split("#", 1)[0].strip()  # unquoted: drop an inline comment
        if key and key not in env:
            env[key] = value
            loaded.append(key)
    return loaded
