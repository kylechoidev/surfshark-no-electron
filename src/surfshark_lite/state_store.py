"""Persistent daemon state store (`state.json`: desired state, last cluster, home location)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from surfshark_lite.fsutil import atomic_write_json, read_json_secure


@dataclass(frozen=True)
class Desired:
    connected: bool = False
    target_query: str | None = None
    cluster_id: str | None = None
    revision: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "Desired":
        if not isinstance(d, dict):
            return cls()
        return cls(
            connected=bool(d.get("connected", False)),
            target_query=d.get("target_query") if isinstance(d.get("target_query"), str) else None,
            cluster_id=d.get("cluster_id") if isinstance(d.get("cluster_id"), str) else None,
            revision=int(d.get("revision", 0)) if isinstance(d.get("revision"), int) else 0,
        )


@dataclass(frozen=True)
class HomeLocation:
    lat: float
    lon: float
    country_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "lat": round(self.lat, 1),
            "lon": round(self.lon, 1),
            "country_code": self.country_code,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "HomeLocation | None":
        if not isinstance(d, dict):
            return None
        try:
            lat = round(float(d["lat"]), 1)
            lon = round(float(d["lon"]), 1)
            cc = d.get("country_code")
            return cls(lat=lat, lon=lon, country_code=cc if isinstance(cc, str) else None)
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True)
class PersistedState:
    schema: int = 1
    desired: Desired = Desired()
    last_cluster: str | None = None
    home_location: HomeLocation | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "desired": self.desired.to_dict(),
            "last_cluster": self.last_cluster,
            "home_location": self.home_location.to_dict() if self.home_location else None,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "PersistedState":
        if not isinstance(d, dict):
            return cls()
        last_c = d.get("last_cluster")
        return cls(
            schema=1,
            desired=Desired.from_dict(d.get("desired")),
            last_cluster=last_c if isinstance(last_c, str) else None,
            home_location=HomeLocation.from_dict(d.get("home_location")),
        )


class StateStore:
    """Manages reading and atomic writing of state.json."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._state = PersistedState()

    def load(self) -> PersistedState:
        raw = read_json_secure(self.path, check_perms=False)
        self._state = PersistedState.from_dict(raw)
        return self._state

    def get(self) -> PersistedState:
        return self._state

    def save(self, state: PersistedState) -> PersistedState:
        self._state = state
        atomic_write_json(self.path, state.to_dict(), mode=0o600)
        return self._state

    def update(
        self,
        *,
        desired: Desired | None = None,
        last_cluster: str | None = None,
        home_location: HomeLocation | None = None,
    ) -> PersistedState:
        next_state = PersistedState(
            schema=1,
            desired=desired if desired is not None else self._state.desired,
            last_cluster=last_cluster if last_cluster is not None else self._state.last_cluster,
            home_location=home_location if home_location is not None else self._state.home_location,
        )
        return self.save(next_state)
