"""Policy routing planner (`plan`), libnm rule converter (`nm_rules`), and kernel verifier (`verify`)."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, Callable

from surfshark_lite.netprobe import run_ip_json
from surfshark_lite.tunnel.base import TunnelSpec
from surfshark_lite.tunnel.profile import AUX_PEER_ALLOWED_IP, WG_ULA_PREFIX6

RT_TABLE_MAIN = 254


@dataclass(frozen=True)
class PlannedRule:
    family: int                           # socket.AF_INET or socket.AF_INET6
    priority: int
    table: int
    to_prefix: str | None = None          # e.g. "10.0.0.0/8"
    fwmark: int | None = None
    fwmask: int | None = None
    invert: bool = False
    suppress_prefixlength: int | None = None
    description: str = ""


@dataclass(frozen=True)
class Drift:
    family: str
    kind: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"family": self.family, "kind": self.kind, "message": self.message}


def _has_aux_peer(spec: TunnelSpec) -> bool:
    for p in spec.peers:
        if AUX_PEER_ALLOWED_IP in p.allowed_ips:
            return True
    return False


def plan(spec: TunnelSpec, family: int = socket.AF_INET) -> list[PlannedRule]:
    """Return deterministic policy routing rules for IPv4 or IPv6 per §8.5."""
    b = spec.rule_priority_base
    t = spec.table
    rules: list[PlannedRule] = []

    if family == socket.AF_INET:
        if spec.lan_bypass == "lan":
            # Keep tunnel subnet inside tunnel table despite 10/8 bypass
            rules.append(
                PlannedRule(
                    family=socket.AF_INET,
                    priority=b + 0,
                    table=t,
                    to_prefix="10.14.0.0/16",
                    description="tunnel internal subnet",
                )
            )
            if _has_aux_peer(spec):
                rules.append(
                    PlannedRule(
                        family=socket.AF_INET,
                        priority=b + 1,
                        table=t,
                        to_prefix=AUX_PEER_ALLOWED_IP,
                        description="anycast control peer",
                    )
                )
            lan_ranges = (
                (b + 10, "10.0.0.0/8", "RFC1918 10/8 bypass"),
                (b + 11, "172.16.0.0/12", "RFC1918 172.16/12 bypass"),
                (b + 12, "192.168.0.0/16", "RFC1918 192.168/16 bypass"),
                (b + 13, "169.254.0.0/16", "link-local bypass"),
                (b + 14, "224.0.0.0/4", "multicast mDNS/SSDP bypass"),
            )
            for prio, cidr, desc in lan_ranges:
                rules.append(
                    PlannedRule(
                        family=socket.AF_INET,
                        priority=prio,
                        table=RT_TABLE_MAIN,
                        to_prefix=cidr,
                        description=desc,
                    )
                )

        rules.append(
            PlannedRule(
                family=socket.AF_INET,
                priority=b + 20,
                table=RT_TABLE_MAIN,
                suppress_prefixlength=0,
                description="preserve main specific routes",
            )
        )
        rules.append(
            PlannedRule(
                family=socket.AF_INET,
                priority=b + 21,
                table=t,
                fwmark=spec.fwmark,
                fwmask=0xFFFFFFFF,
                invert=True,
                description="tunnel default route for unmarked traffic",
            )
        )
        return rules

    if family == socket.AF_INET6:
        if not spec.address6:
            return []
        if spec.lan_bypass == "lan":
            rules.append(
                PlannedRule(
                    family=socket.AF_INET6,
                    priority=b + 0,
                    table=t,
                    to_prefix=WG_ULA_PREFIX6,
                    description="tunnel ULA prefix",
                )
            )
            rules.append(
                PlannedRule(
                    family=socket.AF_INET6,
                    priority=b + 10,
                    table=RT_TABLE_MAIN,
                    to_prefix="fc00::/7",
                    description="IPv6 ULA bypass",
                )
            )
            rules.append(
                PlannedRule(
                    family=socket.AF_INET6,
                    priority=b + 11,
                    table=RT_TABLE_MAIN,
                    to_prefix="ff00::/8",
                    description="IPv6 multicast bypass",
                )
            )
        rules.append(
            PlannedRule(
                family=socket.AF_INET6,
                priority=b + 20,
                table=RT_TABLE_MAIN,
                suppress_prefixlength=0,
                description="preserve main IPv6 specific routes",
            )
        )
        rules.append(
            PlannedRule(
                family=socket.AF_INET6,
                priority=b + 21,
                table=t,
                fwmark=spec.fwmark,
                fwmask=0xFFFFFFFF,
                invert=True,
                description="tunnel IPv6 blackhole route for unmarked traffic",
            )
        )
        return rules

    raise ValueError(f"Unsupported address family: {family}")


def nm_rules(spec: TunnelSpec, family: int, nm_module: Any) -> list[Any]:
    """Convert PlannedRules into NM.IPRoutingRule instances using setters (§8.5)."""
    out: list[Any] = []
    for pr in plan(spec, family):
        rule = nm_module.IPRoutingRule.new(pr.family)
        rule.set_priority(pr.priority)
        rule.set_table(pr.table)
        if pr.invert:
            rule.set_invert(True)
        if pr.fwmark is not None:
            rule.set_fwmark(pr.fwmark, pr.fwmask if pr.fwmask is not None else 0xFFFFFFFF)
        if pr.to_prefix:
            addr, plen_s = pr.to_prefix.split("/", 1)
            rule.set_to(addr, int(plen_s))
        if pr.suppress_prefixlength is not None:
            rule.set_suppress_prefixlength(pr.suppress_prefixlength)
        rule.validate()
        out.append(rule)
    return out


def _normalize_table(val: Any) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        v = val.strip().lower()
        if v == "main":
            return RT_TABLE_MAIN
        if v == "local":
            return 255
        if v == "default":
            return 253
        if v.isdigit():
            return int(v)
    return None


def _normalize_fwmark(val: Any) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        try:
            return int(s, 16) if s.startswith("0x") else int(s, 10)
        except ValueError:
            return None
    return None


def _rule_matches_kernel_entry(pr: PlannedRule, kentry: dict[str, Any]) -> bool:
    if kentry.get("priority") != pr.priority:
        return False
    ktable = _normalize_table(kentry.get("table"))
    if ktable != pr.table:
        return False

    kinvert = ("not" in kentry) or bool(kentry.get("invert", False))
    if kinvert != pr.invert:
        return False

    if pr.fwmark is not None:
        kmark = _normalize_fwmark(kentry.get("fwmark"))
        if kmark != pr.fwmark:
            return False

    if pr.suppress_prefixlength is not None:
        if kentry.get("suppress_prefixlength") != pr.suppress_prefixlength:
            return False

    if pr.to_prefix is not None:
        addr, plen_s = pr.to_prefix.split("/", 1)
        plen = int(plen_s)
        kdst = str(kentry.get("dst") or "")
        kdst_len = kentry.get("dstlen")
        if "/" in kdst:
            if kdst.lower() != pr.to_prefix.lower():
                return False
        else:
            if kdst.lower() != addr.lower():
                return False
            if kdst_len is not None and int(kdst_len) != plen:
                return False

    return True


def verify(
    spec: TunnelSpec,
    ip_runner: Callable[[list[str]], Any] = run_ip_json,
) -> list[Drift]:
    """Verify kernel rules and table routes against planned rules for `spec`."""
    drifts: list[Drift] = []

    for fam_const, fam_label, extra_args in (
        (socket.AF_INET, "ipv4", []),
        (socket.AF_INET6, "ipv6", ["-6"]),
    ):
        planned = plan(spec, fam_const)
        if not planned:
            continue
        krules = ip_runner(extra_args + ["rule", "show"])
        if not isinstance(krules, list):
            drifts.append(Drift(fam_label, "rules_unreadable", f"Failed to read {fam_label} policy rules"))
            continue

        for pr in planned:
            matches = [e for e in krules if isinstance(e, dict) and _rule_matches_kernel_entry(pr, e)]
            if len(matches) == 0:
                drifts.append(
                    Drift(
                        fam_label,
                        "missing_rule",
                        f"Missing {fam_label} rule at priority {pr.priority} ({pr.description})",
                    )
                )
            elif len(matches) > 1:
                drifts.append(
                    Drift(
                        fam_label,
                        "duplicate_rule",
                        f"Duplicate {fam_label} rule ({len(matches)}x) at priority {pr.priority}",
                    )
                )

        # Verify default route in table T
        kroutes = ip_runner(extra_args + ["route", "show", "table", str(spec.table)])
        has_default = False
        if isinstance(kroutes, list):
            for r in kroutes:
                if isinstance(r, dict) and r.get("dst") in ("default", "0.0.0.0/0", "::/0") and r.get("dev") == spec.iface:
                    has_default = True
                    break
        if not has_default:
            drifts.append(
                Drift(
                    fam_label,
                    "missing_table_route",
                    f"Table {spec.table} lacks default route via {spec.iface}",
                )
            )

    return drifts


def check_rule_priority_conflicts(
    priority_base: int = 30000,
    expected_table: int = 300000,
    ip_runner: Callable[[list[str]], Any] = run_ip_json,
) -> list[str]:
    """Check if foreign policy rules occupy priorities B..B+21."""
    warnings: list[str] = []
    krules = ip_runner(["rule", "show"])
    if not isinstance(krules, list):
        return warnings
    lo, hi = priority_base, priority_base + 21
    for entry in krules:
        if not isinstance(entry, dict):
            continue
        prio = entry.get("priority")
        if isinstance(prio, int) and lo <= prio <= hi:
            tbl = _normalize_table(entry.get("table"))
            if tbl not in (expected_table, RT_TABLE_MAIN):
                warnings.append(f"Priority {prio} occupied by foreign rule (table={entry.get('table')})")
    return warnings
