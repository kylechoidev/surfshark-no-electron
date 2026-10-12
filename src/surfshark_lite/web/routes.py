"""REST API route dispatcher for Surf Shark Ultra Lite (`/api/v1/*`)."""

from __future__ import annotations

import urllib.parse
from typing import Any

from surfshark_lite import __version__
from surfshark_lite.auth import LoginNeedsOtp, LoginOk
from surfshark_lite.catalog import TargetFilters
from surfshark_lite.credstore import epoch_to_iso
from surfshark_lite.errors import ErrorCode, SslError, ValidationError
from surfshark_lite.geo import flag


def dispatch_api_request(
    controller: Any,
    method: str,
    raw_path: str,
    body: dict[str, Any] | None,
    *,
    is_unix_socket: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Dispatch an `/api/v1/*` request to `controller` and return `(status_code, json_dict)`."""
    parsed = urllib.parse.urlsplit(raw_path)
    path = parsed.path.rstrip("/") or "/"
    qs = urllib.parse.parse_qs(parsed.query)
    payload = body if isinstance(body, dict) else {}

    if method == "GET" and path == "/api/v1/health":
        return 200, {"ok": True, "version": __version__}

    if method == "GET" and path == "/api/v1/status":
        return 200, controller.status_dict()

    if method == "POST" and path == "/api/v1/ui-ticket":
        if not is_unix_socket:
            raise SslError(
                ErrorCode.PERMISSION_DENIED,
                "UI tickets can only be minted over the local Unix control socket.",
                http_status=403,
            )
        ticket = controller.issue_ui_ticket()
        port = int(controller.settings.get("web", {}).get("port", 8777))
        return 200, {"ticket": ticket, "port": port}

    if method == "POST" and path in ("/api/v1/connect", "/api/v1/switch"):
        target = payload.get("target")
        if target is not None and not isinstance(target, str):
            raise ValidationError("'target' must be a string", field="target")
        kind = payload.get("kind")
        tags_raw = payload.get("tags") or []
        tags = frozenset(str(t).lower() for t in tags_raw if isinstance(t, str))
        phys = bool(payload.get("physical_only", False))
        takeover = bool(payload.get("takeover", False))
        flt = TargetFilters(kind=kind if isinstance(kind, str) else None, tags=tags, physical_only=phys)
        res = controller.connect(target=target or "fastest", filters=flt, takeover=takeover)
        return 200, res

    if method == "POST" and path == "/api/v1/disconnect":
        takeover = bool(payload.get("takeover", False))
        return 200, controller.disconnect(takeover=takeover)

    if method == "POST" and path == "/api/v1/reconnect":
        return 200, controller.reconnect()

    if method == "GET" and path == "/api/v1/servers":
        refresh = qs.get("refresh", ["0"])[0] in ("1", "true", "yes")
        bearer = controller.token_mgr.session.token if controller.token_mgr.session else None
        if refresh:
            controller.catalog.refresh(bearer=bearer)
        else:
            controller.catalog.ensure_loaded(bearer=bearer)

        lats = controller.catalog.get_fresh_latencies()
        q = (qs.get("q", [""])[0] or "").strip()
        cc_filter = (qs.get("country", [""])[0] or "").strip().upper()
        kind_filter = (qs.get("kind", [""])[0] or "").strip().lower()

        clusters = controller.catalog.clusters
        if cc_filter:
            clusters = [c for c in clusters if c.country_code == cc_filter]
        if kind_filter:
            clusters = [c for c in clusters if c.kind == kind_filter]
        if q:
            res = controller.catalog.resolver().resolve(
                q,
                latencies=lats,
                home=controller.persisted.home_location,
                last_cluster_id=controller.persisted.last_cluster,
            )
            clusters = list(res.candidates)

        countries_map: dict[str, dict[str, Any]] = {}
        for c in controller.catalog.clusters:
            if not c.wg_connectable:
                continue
            entry = countries_map.get(c.country_code)
            if entry is None:
                countries_map[c.country_code] = {
                    "country_code": c.country_code,
                    "country": c.country,
                    "region": c.region,
                    "flag": flag(c.country_code),
                    "cluster_count": 1,
                    "cities": {c.location},
                }
            else:
                entry["cluster_count"] += 1
                entry["cities"].add(c.location)

        countries_list = []
        for cc, info in sorted(countries_map.items(), key=lambda kv: kv[1]["country"]):
            countries_list.append({
                "country_code": cc,
                "country": info["country"],
                "region": info["region"],
                "flag": info["flag"],
                "cluster_count": info["cluster_count"],
                "cities": sorted(info["cities"]),
            })

        return 200, {
            "source": controller.catalog.source,
            "fetched_at": epoch_to_iso(controller.catalog.fetched_at),
            "total": len(clusters),
            "clusters": [c.to_summary(lats.get(c.hostname)) for c in clusters],
            "countries": countries_list,
        }

    if method == "POST" and path == "/api/v1/servers/probe":
        scope = str(payload.get("scope") or "nearest")
        Bearer = controller.token_mgr.session.token if controller.token_mgr.session else None
        controller.catalog.ensure_loaded(bearer=Bearer)
        probed = controller.catalog.probe_latencies(
            scope=scope,
            home=controller.persisted.home_location,
            last_cluster_id=controller.persisted.last_cluster,
            tunnel_connected=(controller._conn_state.value == "CONNECTED"),
        )
        return 200, {"probed": probed, "latencies": controller.catalog.get_fresh_latencies()}

    if method == "GET" and path == "/api/v1/ip":
        exp_cc = controller._active_cluster.country_code if controller._active_cluster else None
        rep = controller.egress.check(expected_country_code=exp_cc, timeout=4.0)
        snap = controller._refresh_telemetry(probe_egress=False)
        return 200, {
            "egress": rep.to_dict() if rep else None,
            "baseline": controller.egress.baseline.to_dict() if controller.egress.baseline else None,
            "telemetry": snap.to_dict(),
        }

    if method == "GET" and path == "/api/v1/auth":
        creds = controller.cred_store.load()
        key_exp = creds.wireguard.expires_at if creds.wireguard else None
        return 200, controller.auth.get_view(key_expires_at=key_exp)

    if method == "POST" and path == "/api/v1/auth/login":
        email = payload.get("email")
        password = payload.get("password")
        if not isinstance(email, str) or not email.strip():
            raise ValidationError("Email is required", field="email")
        if not isinstance(password, str) or not password:
            raise ValidationError("Password is required", field="password")
        outcome = controller.auth.login(email, password)
        if isinstance(outcome, LoginNeedsOtp):
            return 202, {
                "status": "otp_required",
                "challenge_id": outcome.challenge_id,
                "method_hint": outcome.method_hint,
            }
        assert isinstance(outcome, LoginOk)
        return 200, {
            "status": "authenticated",
            "account_hint": outcome.account_hint,
            "auth": controller.auth.get_view(),
        }

    if method == "POST" and path == "/api/v1/auth/otp":
        cid = payload.get("challenge_id")
        code = payload.get("code")
        if not isinstance(cid, str) or not cid:
            raise ValidationError("challenge_id is required", field="challenge_id")
        if not isinstance(code, str) or not code:
            raise ValidationError("Verification code is required", field="code")
        ok = controller.auth.verify_otp(cid, code)
        return 200, {
            "status": "authenticated",
            "account_hint": ok.account_hint,
            "auth": controller.auth.get_view(),
        }

    if method == "POST" and path == "/api/v1/auth/import-official":
        ok = controller.auth.import_official()
        return 200, {
            "status": "authenticated",
            "account_hint": ok.account_hint,
            "auth": controller.auth.get_view(),
        }

    if method == "POST" and path == "/api/v1/auth/logout":
        if controller._conn_state.value != "DISCONNECTED":
            controller.disconnect()
        controller.auth.logout()
        return 200, {"status": "logged_out", "auth": controller.auth.get_view()}

    if method == "GET" and path == "/api/v1/keys":
        creds = controller.cred_store.load()
        wg = creds.wireguard
        return 200, {
            "has_key": wg is not None and bool(wg.public_key),
            "public_key": wg.public_key if wg else None,
            "key_id": wg.key_id if wg else None,
            "registered_at": epoch_to_iso(wg.registered_at) if wg else None,
            "expires_at": epoch_to_iso(wg.expires_at) if wg else None,
            "last_validated_at": epoch_to_iso(wg.last_validated_at) if wg else None,
        }

    if method == "POST" and path == "/api/v1/keys/rotate":
        wg = controller.key_mgr.force_revalidate_or_rotate()
        return 200, {
            "has_key": True,
            "public_key": wg.public_key,
            "key_id": wg.key_id,
            "registered_at": epoch_to_iso(wg.registered_at),
            "expires_at": epoch_to_iso(wg.expires_at),
            "last_validated_at": epoch_to_iso(wg.last_validated_at),
        }

    if method == "GET" and path == "/api/v1/settings":
        return 200, {
            "settings": controller.settings,
            "requires_reconnect": list(controller._requires_reconnect_keys),
        }

    if method in ("PATCH", "POST") and path == "/api/v1/settings":
        return 200, controller.update_settings(payload)

    if method == "GET" and path == "/api/v1/logs":
        limit = int(qs.get("limit", ["200"])[0])
        entries = controller.ring_handler.tail(limit) if controller.ring_handler else []
        return 200, {"entries": entries}

    if method == "GET" and path == "/api/v1/doctor":
        return 200, controller.doctor()

    raise SslError(ErrorCode.VALIDATION, f"Unknown API endpoint: {method} {path}", http_status=404)
