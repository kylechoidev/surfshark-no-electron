"""Tunnel driver protocol, specifications, and observation data structures."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Literal, Protocol


@dataclass(frozen=True)
class PeerSpec:
    public_key: str
    endpoint: str                         # "IPv4:port" (pre-resolved)
    endpoint_host: str                    # original hostname, for display/diagnostics
    allowed_ips: tuple[str, ...]
    keepalive: int = 25
    preshared_key: str | None = None

    def redacted(self) -> dict[str, Any]:
        return {
            "public_key": self.public_key,
            "endpoint": self.endpoint,
            "endpoint_host": self.endpoint_host,
            "allowed_ips": list(self.allowed_ips),
            "keepalive": self.keepalive,
            "has_preshared_key": bool(self.preshared_key),
        }


@dataclass(frozen=True)
class TunnelSpec:
    cluster_id: str
    cluster_host: str
    iface: str
    private_key: str
    address4: str
    address6: str | None
    dns4: tuple[str, ...]
    mtu: int | None
    fwmark: int
    table: int
    rule_priority_base: int
    lan_bypass: Literal["connected", "lan"]
    cleanweb: bool
    profile_scope: Literal["private", "system"]
    peers: tuple[PeerSpec, ...]

    def redacted(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_host": self.cluster_host,
            "iface": self.iface,
            "address4": self.address4,
            "address6": self.address6,
            "dns4": list(self.dns4),
            "mtu": self.mtu,
            "fwmark": self.fwmark,
            "table": self.table,
            "rule_priority_base": self.rule_priority_base,
            "lan_bypass": self.lan_bypass,
            "cleanweb": self.cleanweb,
            "profile_scope": self.profile_scope,
            "peers": [p.redacted() for p in self.peers],
        }


@dataclass(frozen=True)
class Observation:
    up: bool
    owner: Literal["self", "surfsharkd", "foreign", "none"]
    iface: str | None
    peer_pubkey: str | None
    endpoint: str | None
    nm_state: str | None
    since: float | None
    detail: str = ""
    cluster_id_hint: str | None = None


@dataclass(frozen=True)
class DriverCaps:
    peer_replace: bool
    psk: bool
    adopt: bool
    dns_reapply: bool


class TunnelDriver(Protocol):
    name: str

    def probe(self) -> tuple[bool, str]: ...
    def caps(self) -> DriverCaps: ...
    def current(self) -> Observation: ...
    def up(self, spec: TunnelSpec, cancel: threading.Event) -> Observation: ...
    def replace_peer(self, spec: TunnelSpec, cancel: threading.Event, force_reset: bool = False) -> Observation: ...
    def down(self, cancel: threading.Event, takeover_foreign: bool = False) -> Observation: ...
    def set_listener(self, cb: Callable[[Observation], None]) -> None: ...
    def close(self) -> None: ...
