"""Surfshark WireGuard profile constants (verified in Phase 0 G5/G6/G7) and TunnelSpec builder."""

from __future__ import annotations

from typing import Any

from surfshark_lite.catalog import Cluster
from surfshark_lite.tunnel.base import PeerSpec, TunnelSpec

# Verified in Phase 0 (docs/GROUND_TRUTH.md)
WG_CLIENT_ADDRESS4 = "10.14.0.2/16"                         # G6
WG_ULA_ADDRESS6 = "fd7d:76ee:e68f:a993::2/128"              # G6 / §8.6
WG_ULA_PREFIX6 = "fd7d:76ee:e68f::/48"                      # §8.5
WG_PORT = 51820                                             # G6 (0xca6c)
WG_FWMARK_DEFAULT = 300000                                  # G6 (0x493e0)
WG_TABLE_DEFAULT = 300000                                   # G6
WG_MTU_SAFE = 1280                                          # G6 (0x500)
WG_MTU_NORMAL = 1360                                        # G6 (0x550)
WG_KEEPALIVE_S = 25                                         # G6

# G7: CleanWeb DNS lists from surfsharkd.js (eJ vs eK)
DNS4_STANDARD: tuple[str, ...] = (
    "162.252.172.57",
    "149.154.159.92",
    "151.236.14.64",
)
DNS4_CLEANWEB: tuple[str, ...] = (
    "151.236.14.64",
    "203.21.66.129",
    "79.127.185.11",
)

# G5: Auxiliary / Anycast control-plane peer
AUX_PEER_HOST = "wgs.prod.surfshark.com"
AUX_PEER_ALLOWED_IP = "172.16.0.36/32"
AUX_PEER_DEFAULT_PUBKEY = "o07k/2dsaQkLLSR0dCI/FUd3FLik/F/HBBcOGUkNQGo="


def build_spec(
    cluster: Cluster,
    private_key: str,
    server_ip: str,
    settings: dict[str, Any],
    *,
    aux_ip: str | None = None,
    aux_pubkey: str | None = None,
    preshared_key: str | None = None,
    keepalive_override: int | None = None,
) -> TunnelSpec:
    """Construct a complete TunnelSpec from resolved cluster, keys, pre-resolved IPs, and settings."""
    if not cluster.pubkey:
        raise ValueError(f"Cluster {cluster.hostname} has no WireGuard public key")

    cleanweb = bool(settings.get("cleanweb", False))
    ipv6_guard = bool(settings.get("ipv6_guard", True))
    dns4 = DNS4_CLEANWEB if cleanweb else DNS4_STANDARD
    keepalive = keepalive_override if keepalive_override is not None else WG_KEEPALIVE_S

    allowed_ips: tuple[str, ...] = ("0.0.0.0/0", "::/0") if ipv6_guard else ("0.0.0.0/0",)

    main_peer = PeerSpec(
        public_key=cluster.pubkey,
        endpoint=f"{server_ip}:{WG_PORT}",
        endpoint_host=cluster.hostname,
        allowed_ips=allowed_ips,
        keepalive=keepalive,
        preshared_key=preshared_key,
    )

    peers: list[PeerSpec] = [main_peer]
    if aux_ip and aux_pubkey:
        peers.append(
            PeerSpec(
                public_key=aux_pubkey,
                endpoint=f"{aux_ip}:{WG_PORT}",
                endpoint_host=AUX_PEER_HOST,
                allowed_ips=(AUX_PEER_ALLOWED_IP,),
                keepalive=keepalive,
            )
        )

    mtu_setting = settings.get("mtu")
    mtu = int(mtu_setting) if isinstance(mtu_setting, int) else WG_MTU_SAFE
    lan_bypass = settings.get("lan_bypass", "lan")
    if lan_bypass not in ("connected", "lan"):
        lan_bypass = "lan"
    scope = settings.get("profile_scope", "private")
    if scope not in ("private", "system"):
        scope = "private"

    return TunnelSpec(
        cluster_id=cluster.id,
        cluster_host=cluster.hostname,
        iface=str(settings.get("interface_name") or "surfshark_lite"),
        private_key=private_key,
        address4=WG_CLIENT_ADDRESS4,
        address6=WG_ULA_ADDRESS6 if ipv6_guard else None,
        dns4=dns4,
        mtu=mtu,
        fwmark=int(settings.get("fwmark", WG_FWMARK_DEFAULT)),
        table=int(settings.get("route_table", WG_TABLE_DEFAULT)),
        rule_priority_base=int(settings.get("rule_priority_base", 30000)),
        lan_bypass=lan_bypass,
        cleanweb=cleanweb,
        profile_scope=scope,
        peers=tuple(peers),
    )
