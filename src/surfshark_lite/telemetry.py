"""Kernel/tunnel telemetry collector and 7-state security verdict engine (§9.4)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from surfshark_lite.egress import EgressReport
from surfshark_lite.netprobe import parse_wg_dump, read_proc_net_dev, run_cmd, run_ip_json
from surfshark_lite.tunnel import routing
from surfshark_lite.tunnel.base import Observation, TunnelSpec


class Verdict(str, Enum):
    PROTECTED = "PROTECTED"
    HANDSHAKE_PENDING = "HANDSHAKE_PENDING"
    ROUTING_DEGRADED = "ROUTING_DEGRADED"
    STALE_HANDSHAKE = "STALE_HANDSHAKE"
    LEAK_SUSPECTED = "LEAK_SUSPECTED"
    EXPOSED = "EXPOSED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class WgHandshakeInfo:
    latest_handshake_epoch: int | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    source: str = "unavailable"  # "wg" | "proc_net_dev" | "unavailable"


@dataclass(frozen=True)
class TelemetrySnapshot:
    verdict: Verdict
    reason: str
    tunnel_up: bool
    iface: str | None
    iface_up: bool
    tunnel_age_s: float | None
    latest_handshake_epoch: int | None
    handshake_age_s: float | None
    rx_bytes: int
    tx_bytes: int
    drifts: tuple[routing.Drift, ...] = ()
    dns_configured: tuple[str, ...] = ()
    dns_ok: bool = True
    egress: EgressReport | None = None
    baseline_ip: str | None = None
    expected_country_code: str | None = None
    collected_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "tunnel_up": self.tunnel_up,
            "iface": self.iface,
            "iface_up": self.iface_up,
            "tunnel_age_s": round(self.tunnel_age_s, 1) if self.tunnel_age_s is not None else None,
            "latest_handshake_epoch": self.latest_handshake_epoch,
            "handshake_age_s": round(self.handshake_age_s, 1) if self.handshake_age_s is not None else None,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "drifts": [d.to_dict() for d in self.drifts],
            "dns_configured": list(self.dns_configured),
            "dns_ok": self.dns_ok,
            "egress": self.egress.to_dict() if self.egress else None,
            "baseline_ip": self.baseline_ip,
            "expected_country_code": self.expected_country_code,
            "collected_at": self.collected_at,
        }


def read_wg_stats(
    iface: str,
    primary_peer_pubkey: str | None = None,
) -> WgHandshakeInfo:
    """Read WireGuard handshake and traffic counters via `wg show <iface> dump` or `/proc/net/dev`."""
    rc, out, _ = run_cmd(["wg", "show", iface, "dump"], timeout=1.5)
    if rc == 0 and out.strip():
        parsed = parse_wg_dump(out)
        peers = parsed.get("peers") or []
        chosen = None
        if primary_peer_pubkey:
            for p in peers:
                if p.get("public_key") == primary_peer_pubkey:
                    chosen = p
                    break
        if chosen is None and peers:
            chosen = peers[0]
        if chosen is not None:
            hs = int(chosen.get("latest_handshake") or 0)
            return WgHandshakeInfo(
                latest_handshake_epoch=hs if hs > 0 else None,
                rx_bytes=int(chosen.get("rx_bytes") or 0),
                tx_bytes=int(chosen.get("tx_bytes") or 0),
                source="wg",
            )

    proc_counters = read_proc_net_dev(iface)
    if proc_counters is not None:
        rx, tx = proc_counters
        return WgHandshakeInfo(
            latest_handshake_epoch=None,
            rx_bytes=rx,
            tx_bytes=tx,
            source="proc_net_dev",
        )
    return WgHandshakeInfo()


def check_iface_up(iface: str, ip_runner: Callable[[list[str]], Any] = run_ip_json) -> bool:
    links = ip_runner(["addr", "show", "dev", iface])
    if not isinstance(links, list) or not links:
        return False
    entry = links[0]
    if not isinstance(entry, dict):
        return False
    flags = entry.get("flags") or []
    return "UP" in flags or entry.get("operstate") in ("UP", "UNKNOWN")


def check_dns_config(expected_dns: tuple[str, ...], resolv_path: Path = Path("/etc/resolv.conf")) -> tuple[tuple[str, ...], bool]:
    """Inspect /etc/resolv.conf; if systemd-resolved stub (127.0.0.53) is active, consider DNS delegated."""
    if not expected_dns:
        return (), True
    try:
        text = resolv_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return (), True

    nameservers: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                nameservers.append(parts[1])

    if not nameservers:
        return (), True

    # systemd-resolved stub resolver handles per-link DNS with priority -50
    if "127.0.0.53" in nameservers or "127.0.0.1" in nameservers:
        return tuple(nameservers), True

    has_expected = any(ns in expected_dns for ns in nameservers)
    return tuple(nameservers), has_expected


def evaluate_verdict(
    *,
    tunnel_up: bool,
    iface_up: bool,
    tunnel_age_s: float | None,
    handshake_age_s: float | None,
    handshake_source: str,
    rx_bytes: int,
    drifts: tuple[routing.Drift, ...],
    dns_ok: bool,
    egress: EgressReport | None,
    baseline_ip: str | None,
    expected_country_code: str | None,
    handshake_pending_grace_s: float = 20.0,
    stale_handshake_threshold_s: float = 180.0,
) -> tuple[Verdict, str]:
    """Deterministic 10-step security verdict evaluation (§9.4)."""
    # 1. Tunnel or interface down
    if not tunnel_up or not iface_up:
        return Verdict.EXPOSED, "VPN tunnel is not active"

    # 2. Policy routing or table drift
    if drifts:
        return Verdict.ROUTING_DEGRADED, drifts[0].message

    # 3 & 4. WireGuard handshake freshness
    if handshake_source == "wg":
        if handshake_age_s is None:
            if tunnel_age_s is not None and tunnel_age_s < handshake_pending_grace_s:
                return Verdict.HANDSHAKE_PENDING, "Waiting for initial WireGuard handshake"
            return Verdict.STALE_HANDSHAKE, "No WireGuard handshake completed"
        if handshake_age_s > stale_handshake_threshold_s:
            return (
                Verdict.STALE_HANDSHAKE,
                f"WireGuard handshake is stale ({int(handshake_age_s)}s > {int(stale_handshake_threshold_s)}s)",
            )
    else:
        # When `wg` CLI is unprivileged/unavailable, infer initial handshake from rx_bytes or egress
        if rx_bytes <= 0 and egress is None:
            if tunnel_age_s is not None and tunnel_age_s < handshake_pending_grace_s:
                return Verdict.HANDSHAKE_PENDING, "Waiting for initial tunnel traffic"
            return Verdict.STALE_HANDSHAKE, "Zero tunnel RX bytes and no egress verification"

    # 5. Egress IP leak check against pre-connect baseline or Surfshark secured flag
    if egress is not None:
        if egress.secured is False:
            return Verdict.LEAK_SUSPECTED, "Surfshark egress check reports connection is not secured"
        if baseline_ip and egress.ip and egress.ip == baseline_ip:
            return (
                Verdict.LEAK_SUSPECTED,
                f"Egress IP ({egress.ip}) matches pre-VPN baseline IP",
            )

    # 6. Country mismatch check
    if egress is not None and expected_country_code and egress.country_code:
        if egress.country_code.upper() != expected_country_code.upper():
            return (
                Verdict.LEAK_SUSPECTED,
                f"Egress country ({egress.country_code}) does not match target ({expected_country_code.upper()})",
            )

    # 7. DNS configuration check
    if not dns_ok:
        return Verdict.ROUTING_DEGRADED, "System DNS configuration does not include tunnel DNS servers"

    # 8. Egress verification availability
    if egress is None or not egress.ip:
        return Verdict.UNVERIFIED, "Tunnel active and routed, but egress IP check has not completed"

    # 9. All checks passed
    return Verdict.PROTECTED, f"Protected via {egress.ip} ({egress.country_code or 'VPN'})"


def collect_snapshot(
    obs: Observation,
    spec: TunnelSpec | None,
    egress: EgressReport | None,
    baseline_ip: str | None = None,
    expected_country_code: str | None = None,
    now: float | None = None,
    ip_runner: Callable[[list[str]], Any] = run_ip_json,
) -> TelemetrySnapshot:
    """Gather kernel, WireGuard, routing, DNS, and egress signals into a TelemetrySnapshot."""
    ts_now = now if now is not None else time.time()
    iface = obs.iface or (spec.iface if spec else None)

    if not obs.up or not iface:
        return TelemetrySnapshot(
            verdict=Verdict.EXPOSED,
            reason="VPN tunnel is disconnected",
            tunnel_up=False,
            iface=iface,
            iface_up=False,
            tunnel_age_s=None,
            latest_handshake_epoch=None,
            handshake_age_s=None,
            rx_bytes=0,
            tx_bytes=0,
            egress=egress,
            baseline_ip=baseline_ip,
            expected_country_code=expected_country_code,
            collected_at=ts_now,
        )

    iface_up = check_iface_up(iface, ip_runner=ip_runner)
    drifts: tuple[routing.Drift, ...] = ()
    dns_cfg: tuple[str, ...] = ()
    dns_ok = True
    primary_pub = obs.peer_pubkey

    if spec is not None:
        drifts = tuple(routing.verify(spec, ip_runner=ip_runner))
        dns_cfg, dns_ok = check_dns_config(spec.dns4)
        if not primary_pub and spec.peers:
            primary_pub = spec.peers[0].public_key

    wg = read_wg_stats(iface, primary_peer_pubkey=primary_pub)
    tunnel_age_s = max(0.0, ts_now - obs.since) if obs.since else None
    hs_age_s = (
        max(0.0, ts_now - wg.latest_handshake_epoch)
        if wg.latest_handshake_epoch is not None and wg.latest_handshake_epoch > 0
        else None
    )

    verdict, reason = evaluate_verdict(
        tunnel_up=obs.up,
        iface_up=iface_up,
        tunnel_age_s=tunnel_age_s,
        handshake_age_s=hs_age_s,
        handshake_source=wg.source,
        rx_bytes=wg.rx_bytes,
        drifts=drifts,
        dns_ok=dns_ok,
        egress=egress,
        baseline_ip=baseline_ip,
        expected_country_code=expected_country_code,
    )

    return TelemetrySnapshot(
        verdict=verdict,
        reason=reason,
        tunnel_up=obs.up,
        iface=iface,
        iface_up=iface_up,
        tunnel_age_s=tunnel_age_s,
        latest_handshake_epoch=wg.latest_handshake_epoch,
        handshake_age_s=hs_age_s,
        rx_bytes=wg.rx_bytes,
        tx_bytes=wg.tx_bytes,
        drifts=drifts,
        dns_configured=dns_cfg,
        dns_ok=dns_ok,
        egress=egress,
        baseline_ip=baseline_ip,
        expected_country_code=expected_country_code,
        collected_at=ts_now,
    )
