"""Step 5: refrigerator simulation engine."""

import random
from datetime import UTC, datetime, timedelta

import pytest

from fridgeguard.models import TELEMETRY_TEMPERATURE
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.simulator.fridge import (
    STATUS_COMPRESSOR_FAULT,
    STATUS_OUT_OF_RANGE,
    Fridge,
    FridgeSpec,
)

START = datetime(2026, 11, 16, 4, 0, tzinfo=UTC)
FRIDGE_SPEC = dict(
    device_id="TEST-1",
    name="test",
    location="lab",
    device_type="fridge",
    setpoint_c=4.0,
    safe_min_c=2.0,
    safe_max_c=8.0,
    hysteresis_c=1.0,
    leak_per_min=0.01,
    cooling_c_per_min=0.5,
)


def run_fleet(fleet: Fleet, minutes: int):
    events, t = [], START
    for _ in range(minutes):
        events += fleet.tick(t, 60)
        t += timedelta(minutes=1)
    return events


def readings(events, device_id):
    return [e for e in events if e.device_id == device_id]


def test_fleet_has_three_fridges_with_different_ranges(fleet):
    assert fleet.device_ids == ["FRIDGE-001", "FRIDGE-002", "FRIDGE-003"]
    ranges = {(f.spec.safe_min_c, f.spec.safe_max_c, f.spec.device_type) for f in fleet}
    assert len(ranges) == 3


def test_reading_contains_required_fields(fleet):
    event = fleet.tick(START, 60)[0]
    assert event.event_type == TELEMETRY_TEMPERATURE
    assert event.ts_device == "2026-11-16T04:00:00.000Z"
    assert event.device_id == "FRIDGE-001"
    for key in ("temperature_c", "expected_min_c", "expected_max_c", "setpoint_c", "status"):
        assert key in event.payload
    assert event.hash.startswith("sha256:")


def test_one_reading_per_device_per_tick(fleet):
    events = run_fleet(fleet, 10)
    assert len(events) == 30
    for device_id in fleet.device_ids:
        times = [e.ts_device for e in readings(events, device_id)]
        assert times == sorted(times) and len(set(times)) == 10


def test_temperatures_stay_in_expected_range_over_a_day(fleet):
    events = run_fleet(fleet, 24 * 60)
    for fridge in fleet:
        temps = [e.payload["temperature_c"] for e in readings(events, fridge.device_id)]
        assert fridge.spec.safe_min_c <= min(temps)
        assert max(temps) <= fridge.spec.safe_max_c
        mean = sum(temps) / len(temps)
        assert abs(mean - fridge.spec.setpoint_c) < 0.5


def test_fluctuations_are_gradual_not_random(fleet):
    """Consecutive readings change smoothly (no jumps across the whole range)."""
    events = run_fleet(fleet, 6 * 60)
    for fridge in fleet:
        temps = [e.payload["temperature_c"] for e in readings(events, fridge.device_id)]
        steps = [abs(b - a) for a, b in zip(temps, temps[1:], strict=False)]
        assert max(steps) < 2.0
        assert sum(steps) / len(steps) < 0.5
        assert len(set(temps)) > 5  # but it is not constant either


def test_compressor_cycles_with_hysteresis():
    fridge = Fridge(FridgeSpec(**FRIDGE_SPEC), random.Random(1))
    states = []
    for _ in range(120):
        fridge.step(60, store_open=False)
        states.append(fridge.compressor_on)
    switches = sum(a != b for a, b in zip(states, states[1:], strict=False))
    assert switches >= 4


def test_door_open_warms_the_cabinet():
    fridge = Fridge(FridgeSpec(**FRIDGE_SPEC), random.Random(1))
    fridge.temperature_c = 4.0
    fridge.set_compressor_fault(False)
    before = fridge.temperature_c
    fridge.open_door(600)
    fridge.step(300, store_open=False)
    assert fridge.temperature_c > before + 1.5


def test_compressor_fault_drifts_out_of_range():
    fridge = Fridge(FridgeSpec(**FRIDGE_SPEC), random.Random(1))
    fridge.set_compressor_fault(True)
    for _ in range(180):
        fridge.step(60, store_open=False)
    reading = fridge.read_sensor()
    assert reading > 8.0
    assert fridge.status(reading) == STATUS_COMPRESSOR_FAULT
    fridge.set_compressor_fault(False)
    assert fridge.status(reading) == STATUS_OUT_OF_RANGE


def test_setpoint_change_moves_the_temperature():
    fridge = Fridge(FridgeSpec(**FRIDGE_SPEC), random.Random(1))
    fridge.apply_setting("setpoint_c", 7.0)
    for _ in range(120):
        fridge.step(60, store_open=False)
    assert 6.0 < fridge.temperature_c < 8.0


def test_offline_fridge_sends_no_readings(fleet):
    fleet["FRIDGE-002"].set_offline(True)
    events = fleet.tick(START, 60)
    assert [e.device_id for e in events] == ["FRIDGE-001", "FRIDGE-003"]


def test_same_seed_gives_same_readings():
    a = run_fleet(Fleet.from_config(random.Random(7)), 30)
    b = run_fleet(Fleet.from_config(random.Random(7)), 30)
    assert [e.to_dict() for e in a] == [e.to_dict() for e in b]


@pytest.mark.parametrize(
    "change, message",
    [
        ({"setpoint_c": 12.0}, "inside the safe range"),
        ({"safe_min_c": 9.0}, "below safe_max_c"),
        ({"cooling_c_per_min": 0.1}, "cooling too weak"),
    ],
)
def test_invalid_device_specs_are_rejected(change, message):
    with pytest.raises(ValueError, match=message):
        FridgeSpec.from_config({**FRIDGE_SPEC, **change}, {})


def test_unknown_device_setting_is_rejected():
    with pytest.raises(ValueError, match="unknown device settings"):
        FridgeSpec.from_config({**FRIDGE_SPEC, "colour": "white"}, {})
