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
