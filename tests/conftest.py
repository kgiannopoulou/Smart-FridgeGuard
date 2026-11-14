import random
from datetime import UTC, datetime

import pytest

from fridgeguard.generator.auth import AuthService, UserDirectory
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.sinks import ListSink

# Monday 16 Nov 2026, 06:30 Athens time (inside the maintenance window)
IN_WINDOW = datetime(2026, 11, 16, 4, 30, tzinfo=UTC)
# Tuesday 17 Nov 2026, 03:00 Athens time (outside the maintenance window)
OFF_HOURS = datetime(2026, 11, 17, 1, 0, tzinfo=UTC)


@pytest.fixture
def rng():
    return random.Random(1234)


@pytest.fixture
def fleet(rng):
    return Fleet.from_config(rng)


@pytest.fixture
def sink():
    return ListSink()


@pytest.fixture
def directory_and_passwords(rng):
    directory, passwords, cfg = UserDirectory.from_config(rng, iterations=1000)
    return directory, passwords, cfg


@pytest.fixture
def auth(directory_and_passwords, fleet, rng, sink):
    directory, _, cfg = directory_and_passwords
    return AuthService.from_config(directory, cfg, fleet, rng, sink.emit)


@pytest.fixture
def passwords(directory_and_passwords):
    return directory_and_passwords[1]
