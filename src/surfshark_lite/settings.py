"""Settings model, validation, merge-patch, and reconnect requirements."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from surfshark_lite.errors import ValidationError
from surfshark_lite.fsutil import atomic_write_json, read_json_secure

IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")

REQUIRES_RECONNECT_KEYS: frozenset[str] = frozenset({
    "interface_name",
    "mtu",
    "profile_scope",
    "route_table",
    "fwmark",
    "rule_priority_base",
    "ipv6_guard",
})

DEFAULT_SETTINGS: dict[str, Any] = {
    "schema": 1,
    "driver": "auto",
    "profile_scope": "private",
    "interface_name": "surfshark_lite",
    "fwmark": 300000,
    "route_table": 300000,
    "rule_priority_base": 30000,
    "lan_bypass": "lan",
    "ipv6_guard": True,
    "mtu": None,
    "cleanweb": False,
    "kill_switch": "soft",
    "autoconnect": False,
    "autoconnect_target": "last",
    "disconnect_on_exit": False,
    "credential_store": "file",
    "web": {
        "enabled": True,
        "port": 8777,
    },
    "probes": {
        "when_disconnected": "surfshark-only",
        "egress_interval_s": 300,
        "liveness_interval_s": 30,
        "allow_http_providers": True,
    },
    "watchdog": {
        "enabled": True,
        "max_level": 4,
        "keep_trying": True,
        "act_in_surfsharkd_mode": False,
    },
    "notifications": {
        "leaks": True,
        "reauth": True,
        "connect_events": False,
    },
    "api": {
        "user_agent": None,
    },
}


def _require_bool(val: Any, name: str) -> bool:
    if not isinstance(val, bool):
        raise ValidationError(f"'{name}' must be a boolean", field=name)
    return val


def _require_int(val: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or not (lo <= val <= hi):
        raise ValidationError(f"'{name}' must be an integer between {lo} and {hi}", field=name)
    return val


def _require_choice(val: Any, name: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(val, str) or val not in allowed:
        raise ValidationError(f"'{name}' must be one of {allowed}", field=name)
    return val


def validate_settings_dict(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate a complete settings dictionary against schema constraints."""
    if not isinstance(raw, dict):
        raise ValidationError("Settings must be a JSON object")

    unknown = set(raw.keys()) - set(DEFAULT_SETTINGS.keys())
    if unknown:
        first = sorted(unknown)[0]
        raise ValidationError(f"Unknown setting key '{first}'", field=first)

    out = copy.deepcopy(DEFAULT_SETTINGS)
    for k, v in raw.items():
        if isinstance(out.get(k), dict) and isinstance(v, dict):
            sub_unknown = set(v.keys()) - set(out[k].keys())
            if sub_unknown:
                sf = f"{k}.{sorted(sub_unknown)[0]}"
                raise ValidationError(f"Unknown setting key '{sf}'", field=sf)
            out[k].update(v)
        elif isinstance(out.get(k), dict) and not isinstance(v, dict):
            raise ValidationError(f"'{k}' must be an object", field=k)
        else:
            out[k] = v

    _require_int(out["schema"], "schema", 1, 1)
    _require_choice(out["driver"], "driver", ("auto", "native", "surfsharkd"))
    _require_choice(out["profile_scope"], "profile_scope", ("private", "system"))

    iface = out["interface_name"]
    if not isinstance(iface, str) or not IFACE_RE.match(iface):
        raise ValidationError(
            "'interface_name' must match ^[A-Za-z0-9_-]{1,15}$",
            field="interface_name",
        )

    for tbl_key in ("fwmark", "route_table"):
        val = _require_int(out[tbl_key], tbl_key, 1, 2**32 - 1)
        if val in (253, 254, 255):
            raise ValidationError(f"'{tbl_key}' cannot use reserved table {val}", field=tbl_key)

    _require_int(out["rule_priority_base"], "rule_priority_base", 1000, 32000)
    _require_choice(out["lan_bypass"], "lan_bypass", ("connected", "lan"))
    _require_bool(out["ipv6_guard"], "ipv6_guard")

    if out["mtu"] is not None:
        _require_int(out["mtu"], "mtu", 1280, 1500)

    _require_bool(out["cleanweb"], "cleanweb")
    _require_choice(out["kill_switch"], "kill_switch", ("soft", "off"))
    _require_bool(out["autoconnect"], "autoconnect")
    if not isinstance(out["autoconnect_target"], str) or not out["autoconnect_target"].strip():
        raise ValidationError("'autoconnect_target' must be a non-empty string", field="autoconnect_target")
    _require_bool(out["disconnect_on_exit"], "disconnect_on_exit")
    _require_choice(out["credential_store"], "credential_store", ("file", "secret-service"))

    # web
    _require_bool(out["web"]["enabled"], "web.enabled")
    _require_int(out["web"]["port"], "web.port", 1024, 65535)

    # probes
    _require_choice(out["probes"]["when_disconnected"], "probes.when_disconnected", ("surfshark-only", "all", "none"))
    _require_int(out["probes"]["egress_interval_s"], "probes.egress_interval_s", 60, 86400)
    _require_int(out["probes"]["liveness_interval_s"], "probes.liveness_interval_s", 5, 600)
    _require_bool(out["probes"]["allow_http_providers"], "probes.allow_http_providers")

    # watchdog
    _require_bool(out["watchdog"]["enabled"], "watchdog.enabled")
    _require_int(out["watchdog"]["max_level"], "watchdog.max_level", 0, 5)
    _require_bool(out["watchdog"]["keep_trying"], "watchdog.keep_trying")
    _require_bool(out["watchdog"]["act_in_surfsharkd_mode"], "watchdog.act_in_surfsharkd_mode")

    # notifications
    _require_bool(out["notifications"]["leaks"], "notifications.leaks")
    _require_bool(out["notifications"]["reauth"], "notifications.reauth")
    _require_bool(out["notifications"]["connect_events"], "notifications.connect_events")

    # api
    ua = out["api"]["user_agent"]
    if ua is not None and (not isinstance(ua, str) or not ua.strip() or len(ua) > 256):
        raise ValidationError("'api.user_agent' must be null or a string <= 256 chars", field="api.user_agent")

    return out


def apply_merge_patch(current: dict[str, Any], patch: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Apply a JSON merge patch to current settings, validate, and return (new_settings, requires_reconnect_keys)."""
    if not isinstance(patch, dict):
        raise ValidationError("Settings patch must be a JSON object")

    merged = copy.deepcopy(current)
    changed_top_keys: list[str] = []

    for k, v in patch.items():
        if k not in DEFAULT_SETTINGS:
            raise ValidationError(f"Unknown setting key '{k}'", field=k)
        if isinstance(DEFAULT_SETTINGS[k], dict):
            if not isinstance(v, dict):
                raise ValidationError(f"'{k}' must be an object", field=k)
            for sk, sv in v.items():
                if sk not in DEFAULT_SETTINGS[k]:
                    raise ValidationError(f"Unknown setting key '{k}.{sk}'", field=f"{k}.{sk}")
                if merged[k].get(sk) != sv:
                    merged[k][sk] = sv
                    if f"{k}.{sk}" not in changed_top_keys:
                        changed_top_keys.append(f"{k}.{sk}")
        else:
            if merged.get(k) != v:
                merged[k] = v
                changed_top_keys.append(k)

    validated = validate_settings_dict(merged)
    reconnect_needed = [k for k in changed_top_keys if k in REQUIRES_RECONNECT_KEYS]
    return validated, reconnect_needed


class SettingsStore:
    """Thread-safe wrapper around settings.json."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = copy.deepcopy(DEFAULT_SETTINGS)

    def load(self) -> dict[str, Any]:
        raw = read_json_secure(self.path, check_perms=False)
        if raw is None:
            self._data = copy.deepcopy(DEFAULT_SETTINGS)
            return copy.deepcopy(self._data)
        # Be tolerant of older/partial files on load, but validate types
        merged = copy.deepcopy(DEFAULT_SETTINGS)
        for k, v in raw.items():
            if k in merged:
                if isinstance(merged[k], dict) and isinstance(v, dict):
                    for sk, sv in v.items():
                        if sk in merged[k]:
                            merged[k][sk] = sv
                else:
                    merged[k] = v
        self._data = validate_settings_dict(merged)
        return copy.deepcopy(self._data)

    def save(self, data: dict[str, Any] | None = None) -> dict[str, Any]:
        if data is not None:
            self._data = validate_settings_dict(data)
        atomic_write_json(self.path, self._data, mode=0o600)
        return copy.deepcopy(self._data)

    def get(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def patch(self, patch_obj: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        updated, reconnect_keys = apply_merge_patch(self._data, patch_obj)
        self._data = updated
        atomic_write_json(self.path, self._data, mode=0o600)
        return copy.deepcopy(self._data), reconnect_keys
