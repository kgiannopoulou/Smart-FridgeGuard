"""A fleet of simulated refrigerators at one site."""

from __future__ import annotations

import random
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fridgeguard.config import load_yaml
from fridgeguard.models import BASELINE, Event
from fridgeguard.simulator.fridge import Fridge, FridgeSpec
from fridgeguard.timeutil import TimeWindow


class Fleet:
    def __init__(
        self, specs: list[FridgeSpec], rng: random.Random, tz: ZoneInfo, opening: TimeWindow
    ):
        if len({s.device_id for s in specs}) != len(specs):
            raise ValueError("device IDs must be unique")
        self.rng = rng
        self.tz = tz
        self.opening = opening
        self.fridges: dict[str, Fridge] = {s.device_id: Fridge(s, rng) for s in specs}
        # ground-truth label per device, set by scenarios that change the physics
        self.scenario_labels: dict[str, str] = {}

    @classmethod
    def from_config(cls, rng: random.Random, config_dir: Path | None = None) -> Fleet:
        cfg = load_yaml("devices.yaml", config_dir)
        site = cfg["site"]
        tz = ZoneInfo(site["timezone"])
        hours = site["opening_hours"]
        opening = TimeWindow(hours["start"], hours["end"], tz)
        defaults = cfg.get("defaults", {})
        specs = [FridgeSpec.from_config(d, defaults) for d in cfg["devices"]]
        return cls(specs, rng, tz, opening)

    def __getitem__(self, device_id: str) -> Fridge:
        return self.fridges[device_id]

    def __iter__(self):
        return iter(self.fridges.values())

    @property
    def device_ids(self) -> list[str]:
        return list(self.fridges)

    def tick(self, now: datetime, dt_s: float) -> list[Event]:
        """Advance every fridge by ``dt_s`` and return one reading per online fridge."""
        store_open = self.opening.contains(now)
        events = []
        for fridge in self.fridges.values():
            fridge.step(dt_s, store_open)
            if fridge.offline:
                continue  # an offline device sends nothing (detected later by DR-8)
            label = self.scenario_labels.get(fridge.device_id, BASELINE)
            events.append(fridge.reading_event(now, self.rng, label))
        return events
