"""Verified wire schema for Surfshark's official surfsharkd.sock Unix RPC daemon.

Ground-truth verified in Phase 0 (Gate G8) from /opt/Surfshark/resources/dist/resources/surfsharkd.js
and live socket probing against $XDG_RUNTIME_DIR/surfsharkd.sock.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# NMActiveConnectionState values reported by surfsharkd getState
NM_ACTIVE_STATE_UNKNOWN = 0
NM_ACTIVE_STATE_ACTIVATING = 1
NM_ACTIVE_STATE_ACTIVATED = 2
NM_ACTIVE_STATE_DEACTIVATING = 3
NM_ACTIVE_STATE_DEACTIVATED = 4

# NMDeviceState values reported by surfsharkd getState
NM_DEVICE_STATE_ACTIVATED = 100

DEFAULT_ANYCAST_IP = "172.16.0.36"
DEFAULT_ANYCAST_PUB = "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo="


@dataclass(frozen=True)
class SurfsharkdState:
    connectivity: int = 0
    ipv6_active_connection_state: int = 0
    ipv6_device_state: int = 0
    wg_active_connection_state: int = 0
    wg_device_state: int = 0
    wg_exists: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SurfsharkdState:
        return cls(
            connectivity=int(data.get("connectivity", 0) or 0),
            ipv6_active_connection_state=int(data.get("ipv6_active_connection_state", 0) or 0),
            ipv6_device_state=int(data.get("ipv6_device_state", 0) or 0),
            wg_active_connection_state=int(data.get("wg_active_connection_state", 0) or 0),
            wg_device_state=int(data.get("wg_device_state", 0) or 0),
            wg_exists=bool(data.get("wg_exists", False)),
        )

    @property
    def is_activated(self) -> bool:
        return (
            self.wg_exists
            and self.wg_active_connection_state == NM_ACTIVE_STATE_ACTIVATED
            and self.wg_device_state == NM_DEVICE_STATE_ACTIVATED
        )

    @property
    def is_activating(self) -> bool:
        return self.wg_active_connection_state == NM_ACTIVE_STATE_ACTIVATING


def build_rpc_request(method: str, params: list[Any] | None = None) -> bytes:
    """Encode a newline-delimited JSON RPC request frame."""
    import json

    payload = {
        "method": method,
        "params": params if params is not None else [],
    }
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def build_add_connection_params(
    *,
    domain_ipv4: str,
    pub_b64: str,
    priv_b64: str,
    cleanweb: bool,
    mtu_safe: bool,
    anycast_pub: str = DEFAULT_ANYCAST_PUB,
    anycast_ip: str = DEFAULT_ANYCAST_IP,
    ifname: str = "wg",
) -> list[Any]:
    return [
        ifname,
        {
            "domain": domain_ipv4,
            "pub": pub_b64,
            "priv": priv_b64,
            "cleanweb": bool(cleanweb),
            "mtuSafe": bool(mtu_safe),
            "anycastPub": anycast_pub or DEFAULT_ANYCAST_PUB,
            "anycastIp": anycast_ip or DEFAULT_ANYCAST_IP,
        },
    ]


def build_replace_peer_params(
    *,
    domain_ipv4: str,
    pub_b64: str,
    priv_b64: str,
) -> list[Any]:
    return [
        {
            "domain": domain_ipv4,
            "priv": priv_b64,
            "pub": pub_b64,
        }
    ]
