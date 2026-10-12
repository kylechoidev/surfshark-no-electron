"""Pure, side-effect-free L0–L5 watchdog recovery ladder (§9.5)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any

from surfshark_lite.telemetry import Verdict


class WatchdogLevel(IntEnum):
    L0_HEALTHY = 0
    L1_REVERIFY_EGRESS = 1
    L2_REAPPLY_POKE = 2
    L3_FAILOVER_SAME_COUNTRY = 3
    L4_FULL_RECONNECT = 4
    L5_TERMINAL_FAULT = 5


@dataclass(frozen=True)
class WatchdogState:
    level: WatchdogLevel = WatchdogLevel.L0_HEALTHY
    level_entered_at: float = 0.0
    healthy_since: float | None = None
    last_action_at: float = 0.0
    consecutive_steps: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": int(self.level),
            "level_name": self.level.name,
            "level_entered_at": self.level_entered_at,
            "healthy_since": self.healthy_since,
            "last_action_at": self.last_action_at,
            "consecutive_steps": self.consecutive_steps,
        }


@dataclass(frozen=True)
class WatchdogDecision:
    next_state: WatchdogState
    action: str  # "none" | "probe_egress" | "reapply_poke" | "failover_cluster" | "full_reconnect" | "enter_fault"
    reason: str


# Minimum dwell time (seconds) before escalating from level N to N+1
ESCALATION_DWELL_S: dict[WatchdogLevel, float] = {
    WatchdogLevel.L0_HEALTHY: 0.0,
    WatchdogLevel.L1_REVERIFY_EGRESS: 8.0,
    WatchdogLevel.L2_REAPPLY_POKE: 15.0,
    WatchdogLevel.L3_FAILOVER_SAME_COUNTRY: 20.0,
    WatchdogLevel.L4_FULL_RECONNECT: 25.0,
    WatchdogLevel.L5_TERMINAL_FAULT: 60.0,
}

HEALTHY_RESET_HYSTERESIS_S = 30.0


def step_watchdog(
    state: WatchdogState,
    verdict: Verdict,
    now: float,
    *,
    desired_connected: bool = True,
) -> WatchdogDecision:
    """Pure state transition function mapping (WatchdogState, Verdict, now) -> WatchdogDecision."""
    if not desired_connected:
        return WatchdogDecision(
            next_state=WatchdogState(level=WatchdogLevel.L0_HEALTHY, level_entered_at=now),
            action="none",
            reason="Desired state is disconnected",
        )

    if verdict == Verdict.HANDSHAKE_PENDING:
        return WatchdogDecision(
            next_state=state,
            action="none",
            reason="Initial handshake within grace period",
        )

    if verdict == Verdict.PROTECTED:
        h_since = state.healthy_since if state.healthy_since is not None else now
        if state.level == WatchdogLevel.L0_HEALTHY:
            return WatchdogDecision(
                next_state=replace(state, healthy_since=h_since),
                action="none",
                reason="Tunnel healthy",
            )
        if (now - h_since) >= HEALTHY_RESET_HYSTERESIS_S:
            return WatchdogDecision(
                next_state=WatchdogState(
                    level=WatchdogLevel.L0_HEALTHY,
                    level_entered_at=now,
                    healthy_since=h_since,
                    last_action_at=state.last_action_at,
                    consecutive_steps=0,
                ),
                action="none",
                reason="Sustained PROTECTED verdict for 30s; watchdog reset to L0",
            )
        return WatchdogDecision(
            next_state=replace(state, healthy_since=h_since),
            action="none",
            reason=f"Recovering ({int(now - h_since)}s / {int(HEALTHY_RESET_HYSTERESIS_S)}s hysteresis)",
        )

    # Unhealthy verdict: clear healthy_since
    dwell = now - state.level_entered_at if state.level_entered_at > 0 else 9999.0
    min_dwell = ESCALATION_DWELL_S.get(state.level, 10.0)
    if state.level != WatchdogLevel.L0_HEALTHY and dwell < min_dwell:
        return WatchdogDecision(
            next_state=replace(state, healthy_since=None),
            action="none",
            reason=f"Waiting at {state.level.name} ({dwell:.1f}s < {min_dwell:.1f}s dwell)",
        )

    # Determine target escalation level
    if state.level == WatchdogLevel.L0_HEALTHY:
        if verdict == Verdict.UNVERIFIED:
            target = WatchdogLevel.L1_REVERIFY_EGRESS
        elif verdict in (Verdict.ROUTING_DEGRADED, Verdict.STALE_HANDSHAKE):
            target = WatchdogLevel.L2_REAPPLY_POKE
        elif verdict == Verdict.LEAK_SUSPECTED:
            target = WatchdogLevel.L1_REVERIFY_EGRESS
        else:  # EXPOSED when desired_connected=True
            target = WatchdogLevel.L4_FULL_RECONNECT
    else:
        next_int = min(int(state.level) + 1, int(WatchdogLevel.L5_TERMINAL_FAULT))
        target = WatchdogLevel(next_int)

    action_map = {
        WatchdogLevel.L1_REVERIFY_EGRESS: "probe_egress",
        WatchdogLevel.L2_REAPPLY_POKE: "reapply_poke",
        WatchdogLevel.L3_FAILOVER_SAME_COUNTRY: "failover_cluster",
        WatchdogLevel.L4_FULL_RECONNECT: "full_reconnect",
        WatchdogLevel.L5_TERMINAL_FAULT: "enter_fault",
    }
    action = action_map.get(target, "none")

    new_state = WatchdogState(
        level=target,
        level_entered_at=now,
        healthy_since=None,
        last_action_at=now,
        consecutive_steps=state.consecutive_steps + 1,
    )
    return WatchdogDecision(
        next_state=new_state,
        action=action,
        reason=f"Escalated to {target.name} due to {verdict.value}",
    )
