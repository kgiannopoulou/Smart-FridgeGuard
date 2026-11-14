"""Physics-based refrigerator model (Phase 1, Step 5).

Temperature is not drawn at random. Each cabinet follows a simple thermal model:

* heat leaks in from the room:      dT/dt = +leak * (ambient - T)
  (the leak is several times larger while the door is open)
* the compressor removes heat:      dT/dt = -cooling   while it runs
* a thermostat with hysteresis switches the compressor on above
  ``setpoint + hysteresis/2`` and off below ``setpoint - hysteresis/2``
* the sensor adds small Gaussian noise and reports with 0.1 °C resolution.

This produces the familiar slow sawtooth around the setpoint (for example
3.2 -> 3.4 -> 3.1 -> 4.0 -> 4.2 °C) and realistic reactions to door openings,
setpoint changes and compressor failures.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fridgeguard.models import TELEMETRY_TEMPERATURE, Event, make_event

SUBSTEP_S = 5.0  # integration step; small enough for the thermostat to react correctly

STATUS_OK = "ok"
STATUS_DOOR_OPEN = "door_open"
STATUS_OUT_OF_RANGE = "out_of_range"
STATUS_COMPRESSOR_FAULT = "compressor_fault"
STATUS_OFFLINE = "offline"


@dataclass(frozen=True)
class FridgeSpec:
    device_id: str
    name: str
    location: str
    device_type: str
    setpoint_c: float
    safe_min_c: float
    safe_max_c: float
    hysteresis_c: float
    leak_per_min: float
    cooling_c_per_min: float
    ambient_c: float = 22.0
    door_leak_factor: float = 8.0
    sensor_noise_c: float = 0.1
    door_opens_per_hour: float = 0.0
    firmware_version: str = "1.0.0"
    alarm_delay_min: int = 15
    allowed_ips: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, raw: dict[str, Any], defaults: dict[str, Any]) -> FridgeSpec:
        merged = {**defaults, **raw}
        merged["allowed_ips"] = tuple(merged.get("allowed_ips", ()))
        known = cls.__dataclass_fields__
        unknown = set(merged) - set(known)
        if unknown:
            raise ValueError(f"{raw.get('device_id')}: unknown device settings {sorted(unknown)}")
        spec = cls(**merged)
        spec.validate()
        return spec

    def validate(self) -> None:
        if not self.safe_min_c < self.safe_max_c:
            raise ValueError(f"{self.device_id}: safe_min_c must be below safe_max_c")
        if not self.safe_min_c <= self.setpoint_c <= self.safe_max_c:
            raise ValueError(f"{self.device_id}: setpoint must be inside the safe range")
        # The compressor must be able to beat the heat leak at the setpoint.
        heat_in = self.leak_per_min * (self.ambient_c - self.setpoint_c)
        if self.cooling_c_per_min <= heat_in:
            raise ValueError(f"{self.device_id}: cooling too weak to hold the setpoint")


class Fridge:
    """One simulated refrigerator with mutable configuration and physical state."""

    def __init__(self, spec: FridgeSpec, rng: random.Random):
        self.spec = spec
        self.rng = rng
        # configuration (changed through the activity simulator, Step 6)
        self.setpoint_c = spec.setpoint_c
        self.alarm_low_c = spec.safe_min_c
        self.alarm_high_c = spec.safe_max_c
        self.defrost_interval_h = 8
        self.firmware_version = spec.firmware_version
        # physical state
        half = spec.hysteresis_c / 2
        self.temperature_c = spec.setpoint_c + rng.uniform(-half, half)
        self.ambient_c = spec.ambient_c
        self.compressor_on = rng.random() < 0.5
        self.door_open_s = 0.0  # seconds the door stays open from now
        self.compressor_fault = False
        self.offline = False
        self.last_reading_c: float | None = None

    @property
    def device_id(self) -> str:
        return self.spec.device_id

    @property
    def door_open(self) -> bool:
        return self.door_open_s > 0

    # ---- fault / scenario controls -------------------------------------------------
    def open_door(self, seconds: float) -> None:
        self.door_open_s = max(self.door_open_s, seconds)

    def set_compressor_fault(self, fault: bool) -> None:
        self.compressor_fault = fault
        if fault:
            self.compressor_on = False

    def set_offline(self, offline: bool) -> None:
        self.offline = offline

    # ---- configuration ---------------------------------------------------------------
    def get_setting(self, parameter: str) -> Any:
        return getattr(self, parameter)

    def apply_setting(self, parameter: str, value: Any) -> None:
        if parameter not in CONFIG_PARAMETERS:
            raise KeyError(f"unknown configuration parameter: {parameter}")
        setattr(self, parameter, value)

    # ---- physics ---------------------------------------------------------------------
    def step(self, dt_s: float, store_open: bool) -> None:
        """Advance the physical model by ``dt_s`` seconds."""
        if store_open and not self.door_open and self.spec.door_opens_per_hour > 0:
            if self.rng.random() < self.spec.door_opens_per_hour * dt_s / 3600:
                self.open_door(self.rng.uniform(15, 90))

        # slow random walk of the room temperature, kept within ±1.5 °C
        self.ambient_c += self.rng.gauss(0, 0.02) * (dt_s / 60)
        self.ambient_c = min(
            max(self.ambient_c, self.spec.ambient_c - 1.5), self.spec.ambient_c + 1.5
        )

        remaining = dt_s
        while remaining > 0:
            h = min(SUBSTEP_S, remaining)
            self._substep(h)
            remaining -= h

    def _substep(self, h: float) -> None:
        spec = self.spec
        leak = spec.leak_per_min / 60
        if self.door_open:
            leak *= spec.door_leak_factor
            self.door_open_s = max(0.0, self.door_open_s - h)

        self.temperature_c += leak * (self.ambient_c - self.temperature_c) * h

        half = spec.hysteresis_c / 2
        if self.compressor_fault:
            self.compressor_on = False
        elif self.temperature_c > self.setpoint_c + half:
            self.compressor_on = True
        elif self.temperature_c < self.setpoint_c - half:
            self.compressor_on = False

        if self.compressor_on:
            self.temperature_c -= spec.cooling_c_per_min / 60 * h

    # ---- readings --------------------------------------------------------------------
    def read_sensor(self) -> float:
        noisy = self.temperature_c + self.rng.gauss(0, self.spec.sensor_noise_c)
        self.last_reading_c = round(noisy, 1)
        return self.last_reading_c

    def status(self, reading_c: float) -> str:
        if self.offline:
            return STATUS_OFFLINE
        if self.compressor_fault:
            return STATUS_COMPRESSOR_FAULT
        if not self.spec.safe_min_c <= reading_c <= self.spec.safe_max_c:
            return STATUS_OUT_OF_RANGE
        if self.door_open:
            return STATUS_DOOR_OPEN
        return STATUS_OK

    def reading_event(self, ts: datetime, rng: random.Random, scenario: str) -> Event:
        temp = self.read_sensor()
        return make_event(
            rng,
            TELEMETRY_TEMPERATURE,
            self.device_id,
            ts,
            payload={
                "temperature_c": temp,
                "setpoint_c": round(self.setpoint_c, 1),
                "expected_min_c": self.spec.safe_min_c,
                "expected_max_c": self.spec.safe_max_c,
                "status": self.status(temp),
                "door_open": self.door_open,
                "compressor_on": self.compressor_on,
            },
            scenario=scenario,
        )


# Configuration parameters that users may change (Step 6) and their types.
CONFIG_PARAMETERS: dict[str, type] = {
    "setpoint_c": float,
    "alarm_low_c": float,
    "alarm_high_c": float,
    "defrost_interval_h": int,
    "firmware_version": str,
}
