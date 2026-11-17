"""Simulated authentication, authorization and activity logging (Phase 1, Step 6).

* Users and roles come from ``config/users.yaml``.
* Passwords are generated at start-up, hashed with PBKDF2-HMAC-SHA256 and only the
  hash is kept by the device. The plain values live in memory with the simulated
  people who "remember" them; they are never written to events, logs or disk (NFR-6).
* Every login, logout and configuration change is emitted as an event with a
  timestamp, the claimed user identity, role, source IP and authorization result.
* Role-based access control decides whether a configuration change is applied.
  Changes are also checked against the maintenance window, so an authorized
  technician working at 03:00 can be told apart from planned maintenance.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fridgeguard.config import load_yaml
from fridgeguard.models import (
    AUTH_LOGIN_FAILURE,
    AUTH_LOGIN_SUCCESS,
    AUTH_LOGOUT,
    BASELINE,
    CONFIG_CHANGE,
    Event,
    make_event,
)
from fridgeguard.simulator.fleet import Fleet
from fridgeguard.simulator.fridge import CONFIG_PARAMETERS
from fridgeguard.timeutil import TimeWindow

# Which permission each configuration parameter needs.
PARAMETER_PERMISSIONS = {
    "setpoint_c": "change_setpoint",
    "alarm_low_c": "change_alarm_thresholds",
    "alarm_high_c": "change_alarm_thresholds",
    "defrost_interval_h": "change_defrost",
    "firmware_version": "update_firmware",
}

# Physical limits the controller accepts for numeric settings.
PARAMETER_LIMITS = {
    "setpoint_c": (-30.0, 15.0),
    "alarm_low_c": (-40.0, 20.0),
    "alarm_high_c": (-40.0, 30.0),
    "defrost_interval_h": (1, 48),
}

RESULT_APPLIED = "applied"
RESULT_DENIED = "denied"
RESULT_REJECTED = "rejected"


# ---- passwords -----------------------------------------------------------------------
class PasswordHasher:
    def __init__(self, iterations: int = 100_000):
        self.iterations = iterations

    def hash(self, password: str, salt: bytes) -> str:
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iterations)
        return digest.hex()

    def verify(self, password: str, salt: bytes, expected_hash: str) -> bool:
        return hmac.compare_digest(self.hash(password, salt), expected_hash)


def generate_password(rng: random.Random, length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


# ---- users and roles -----------------------------------------------------------------
@dataclass(frozen=True)
class Role:
    name: str
    permissions: frozenset[str]
    description: str = ""


@dataclass
class User:
    username: str
    full_name: str
    role: str
    login_method: str = "password"
    known_ips: tuple[str, ...] = ()
    registered: bool = True
    salt: bytes = b""
    password_hash: str = field(default="", repr=False)


@dataclass(frozen=True)
class Session:
    session_id: str
    username: str
    role: str
    device_id: str
    source_ip: str
    started: datetime


class UserDirectory:
    """Registered accounts (as stored on the device) plus the unregistered actors."""

    def __init__(self, users: list[User], roles: dict[str, Role], hasher: PasswordHasher):
        self.users = {u.username: u for u in users}
        self.roles = roles
        self.hasher = hasher

    @classmethod
    def from_config(
        cls,
        rng: random.Random,
        iterations: int = 100_000,
        config_dir: Path | None = None,
    ) -> tuple[UserDirectory, dict[str, str], dict[str, Any]]:
        """Build the directory.

        Returns ``(directory, remembered_passwords, raw_config)``. The passwords
        dictionary represents what each simulated person knows; only the activity
        simulator holds it.
        """
        cfg = load_yaml("users.yaml", config_dir)
        roles = {
            name: Role(name, frozenset(r.get("permissions", [])), r.get("description", ""))
            for name, r in cfg["roles"].items()
        }
        hasher = PasswordHasher(iterations)
        users, remembered = [], {}
        for raw in cfg["users"]:
            user = User(
                username=raw["username"],
                full_name=raw.get("full_name", raw["username"]),
                role=raw["role"],
                login_method=raw.get("login_method", "password"),
                known_ips=tuple(raw.get("known_ips", ())),
                registered=raw.get("registered", True),
            )
            if user.registered:
                if user.role not in roles:
                    raise ValueError(f"{user.username}: unknown role {user.role}")
                password = generate_password(rng)
                user.salt = rng.randbytes(16)
                user.password_hash = hasher.hash(password, user.salt)
                remembered[user.username] = password
            users.append(user)
        return cls(users, roles, hasher), remembered, cfg

    def get(self, username: str) -> User | None:
        return self.users.get(username)

    def account(self, username: str) -> User | None:
        """A registered account, or None (unknown or unregistered username)."""
        user = self.users.get(username)
        return user if user and user.registered else None

    def has_permission(self, role: str, permission: str) -> bool:
        r = self.roles.get(role)
        return bool(r and permission in r.permissions)


# ---- authentication service ----------------------------------------------------------
class AuthService:
    """The device-side login and configuration interface, emitting audit events."""

    def __init__(
        self,
        directory: UserDirectory,
        fleet: Fleet,
        maintenance_window: TimeWindow,
        rng: random.Random,
        emit: Callable[[Event], None],
    ):
        self.directory = directory
        self.fleet = fleet
        self.maintenance_window = maintenance_window
        self.rng = rng
        self.emit = emit
        self.sessions: dict[str, Session] = {}

    @classmethod
    def from_config(
        cls,
        directory: UserDirectory,
        users_cfg: dict[str, Any],
        fleet: Fleet,
        rng: random.Random,
        emit: Callable[[Event], None],
    ) -> AuthService:
        mw = users_cfg["maintenance_window"]
        window = TimeWindow(mw["start"], mw["end"], fleet.tz, mw.get("days"))
        return cls(directory, fleet, window, rng, emit)

    @property
    def tz(self) -> ZoneInfo:
        return self.fleet.tz

    def in_maintenance_window(self, ts: datetime) -> bool:
        return self.maintenance_window.contains(ts)

    # -- login / logout --
    def login(
        self,
        ts: datetime,
        username: str,
        password: str,
        device_id: str,
        source_ip: str,
        *,
        method: str = "password",
        scenario: str = BASELINE,
    ) -> Session | None:
        self._check_device(device_id)
        account = self.directory.account(username)
        if account is None:
            reason = "unknown_user"
        elif not self.directory.hasher.verify(password, account.salt, account.password_hash):
            reason = "bad_password"
        else:
            reason = None

        if reason:
            self.emit(
                make_event(
                    self.rng,
                    AUTH_LOGIN_FAILURE,
                    device_id,
                    ts,
                    actor=username,
                    source_ip=source_ip,
                    payload={
                        "method": method,
                        "reason": reason,
                        "role": account.role if account else None,
                        "within_maintenance_window": self.in_maintenance_window(ts),
                    },
                    scenario=scenario,
                )
            )
            return None

        session = Session(
            session_id=f"S-{self.rng.getrandbits(32):08x}",
            username=username,
            role=account.role,
            device_id=device_id,
            source_ip=source_ip,
            started=ts,
        )
        self.sessions[session.session_id] = session
        self.emit(
            make_event(
                self.rng,
                AUTH_LOGIN_SUCCESS,
                device_id,
                ts,
                actor=username,
                source_ip=source_ip,
                payload={
                    "method": method,
                    "role": account.role,
                    "session_id": session.session_id,
                    "within_maintenance_window": self.in_maintenance_window(ts),
                },
                scenario=scenario,
            )
        )
        return session

    def logout(self, ts: datetime, session: Session, *, scenario: str = BASELINE) -> None:
        if self.sessions.pop(session.session_id, None) is None:
            return
        self.emit(
            make_event(
                self.rng,
                AUTH_LOGOUT,
                session.device_id,
                ts,
                actor=session.username,
                source_ip=session.source_ip,
                payload={
                    "role": session.role,
                    "session_id": session.session_id,
                    "session_s": round((ts - session.started).total_seconds()),
                },
                scenario=scenario,
            )
        )

    # -- configuration changes --
    def change_config(
        self,
        ts: datetime,
        session: Session,
        parameter: str,
        new_value: Any,
        *,
        change_source: str = "local_panel",
        scenario: str = BASELINE,
        enforce_rbac: bool = True,
    ) -> str:
        """Try to change a setting on the session's device. Returns the result.

        ``enforce_rbac=False`` models a compromised controller (threat T-4) that applies
        a change although the role lacks the permission. The audit event still records
        ``authorized: false``, which is what detection relies on.
        """
        if session.session_id not in self.sessions:
            raise ValueError("session is not active")
        if parameter not in CONFIG_PARAMETERS:
            raise KeyError(f"unknown configuration parameter: {parameter}")

        fridge = self.fleet[session.device_id]
        old_value = fridge.get_setting(parameter)
        permission = PARAMETER_PERMISSIONS[parameter]
        authorized = self.directory.has_permission(session.role, permission)

        if not authorized and enforce_rbac:
            result = RESULT_DENIED
        elif not self._valid_value(parameter, new_value):
            result = RESULT_REJECTED
        else:
            new_value = CONFIG_PARAMETERS[parameter](new_value)
            fridge.apply_setting(parameter, new_value)
            result = RESULT_APPLIED

        self.emit(
            make_event(
                self.rng,
                CONFIG_CHANGE,
                session.device_id,
                ts,
                actor=session.username,
                source_ip=session.source_ip,
                payload={
                    "parameter": parameter,
                    "old_value": old_value,
                    "new_value": new_value,
                    "change_source": change_source,
                    "result": result,
                    "role": session.role,
                    "permission": permission,
                    "authorized": authorized,
                    "within_maintenance_window": self.in_maintenance_window(ts),
                    "session_id": session.session_id,
                },
                scenario=scenario,
            )
        )
        return result

    # -- helpers --
    def _check_device(self, device_id: str) -> None:
        if device_id not in self.fleet.fridges:
            raise KeyError(f"unknown device: {device_id}")

    @staticmethod
    def _valid_value(parameter: str, value: Any) -> bool:
        if parameter == "firmware_version":
            return isinstance(value, str) and all(p.isdigit() for p in value.split("."))
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return False
        low, high = PARAMETER_LIMITS[parameter]
        return low <= numeric <= high
