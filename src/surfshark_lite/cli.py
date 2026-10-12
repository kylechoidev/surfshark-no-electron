"""Command-line interface (`surfshark-lite`) with semantic exit codes and `--json` support."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from typing import Any, Sequence

from surfshark_lite import __version__
from surfshark_lite.daemon import run_daemon
from surfshark_lite.errors import ErrorCode, SslError, ValidationError
from surfshark_lite.ipc import IpcClient
from surfshark_lite.term import Style, format_table
from surfshark_lite.ui_launcher import launch_ui

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_VALIDATION = 2
EXIT_AUTH = 3
EXIT_TARGET = 4
EXIT_NETWORK = 5
EXIT_DRIVER = 6
EXIT_UNPROTECTED = 7


def map_error_to_exit_code(code: ErrorCode) -> int:
    if code == ErrorCode.VALIDATION:
        return EXIT_VALIDATION
    if code in (
        ErrorCode.AUTH_REQUIRED,
        ErrorCode.REAUTH_REQUIRED,
        ErrorCode.INVALID_CREDENTIALS,
        ErrorCode.CAPTCHA_REQUIRED,
        ErrorCode.OTP_INVALID,
        ErrorCode.OTP_EXPIRED,
        ErrorCode.CREDENTIALS_INSECURE,
    ):
        return EXIT_AUTH
    if code in (ErrorCode.TARGET_NOT_FOUND, ErrorCode.TARGET_AMBIGUOUS):
        return EXIT_TARGET
    if code in (ErrorCode.NETWORK_UNAVAILABLE, ErrorCode.API_ERROR, ErrorCode.RATE_LIMITED):
        return EXIT_NETWORK
    if code in (
        ErrorCode.DRIVER_UNAVAILABLE,
        ErrorCode.PERMISSION_DENIED,
        ErrorCode.FOREIGN_TUNNEL_ACTIVE,
        ErrorCode.TUNNEL_VERIFY_FAILED,
        ErrorCode.KEY_REJECTED,
    ):
        return EXIT_DRIVER
    return EXIT_INTERNAL


def _print_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2) + "\n")
    sys.stdout.flush()


def _render_status(st: dict[str, Any], style: Style) -> None:
    conn = st.get("connection_state", "DISCONNECTED")
    telem = st.get("telemetry") or {}
    verdict = telem.get("verdict", "EXPOSED")
    cluster = st.get("active_cluster") or {}
    egress = telem.get("egress") or {}
    auth = st.get("auth") or {}

    conn_colored = style.green(conn) if conn == "CONNECTED" else (style.yellow(conn) if "ING" in conn else style.red(conn))
    verd_colored = (
        style.green(verdict)
        if verdict == "PROTECTED"
        else (style.yellow(verdict) if verdict in ("HANDSHAKE_PENDING", "UNVERIFIED") else style.red(verdict))
    )

    print(f"{style.bold('Surf Shark Ultra Lite')} v{st.get('version', __version__)}")
    print(f"  State:      {conn_colored}  (Driver: {st.get('driver', 'auto')})")
    print(f"  Verdict:    {verd_colored} — {telem.get('reason', '')}")
    if cluster:
        flag_str = f"{cluster.get('flag', '')} " if cluster.get("flag") else ""
        lat_str = f", {cluster['latency_ms']} ms" if cluster.get("latency_ms") is not None else ""
        print(
            f"  Server:     {flag_str}{cluster.get('label')} ({cluster.get('hostname')}, load {cluster.get('load')}%{lat_str})"
        )
    if egress and egress.get("ip"):
        print(
            f"  Egress IP:  {style.cyan(str(egress.get('ip')))} ({egress.get('city') or egress.get('country') or egress.get('country_code') or 'unknown'})"
        )
    print(f"  Account:    {auth.get('state', 'logged_out')} ({auth.get('account_hint') or 'none'})")
    req_rec = st.get("requires_reconnect") or []
    if req_rec:
        print(style.yellow(f"  Notice:     Reconnect needed to apply: {', '.join(req_rec)}"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="surfshark-lite",
        description="Surf Shark Ultra Lite for Linux — Native Zero-Electron WireGuard Client",
    )
    p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    sub = p.add_subparsers(dest="cmd")

    # status
    s_status = sub.add_parser("status", help="Show connection status and security verdict")
    s_status.add_argument("--require-protected", action="store_true", help="Exit 7 unless verdict is PROTECTED")
    s_status.add_argument("--json", action="store_true", help="Output JSON")

    # connect
    s_conn = sub.add_parser("connect", help="Connect or switch to a target location/server")
    s_conn.add_argument("target", nargs="?", default="fastest", help="Location, country, city code, or 'fastest'")
    s_conn.add_argument("--kind", choices=["generic", "static", "double", "obfuscated"], default=None)
    s_conn.add_argument("--physical-only", action="store_true", help="Exclude virtual servers")
    s_conn.add_argument("--takeover", action="store_true", help="Replace active foreign/official VPN connection")
    s_conn.add_argument("--json", action="store_true", help="Output JSON")

    # switch
    s_sw = sub.add_parser("switch", help="Switch active WireGuard peer in-place (<100ms)")
    s_sw.add_argument("target", help="Target location, country, city, or hostname")
    s_sw.add_argument("--json", action="store_true", help="Output JSON")

    # fastest
    s_fast = sub.add_parser("fastest", help="Connect to the fastest server globally or in a country")
    s_fast.add_argument("country", nargs="?", default="", help="Optional country code or name")
    s_fast.add_argument("--json", action="store_true", help="Output JSON")

    # disconnect
    s_disc = sub.add_parser("disconnect", help="Disconnect the active WireGuard tunnel")
    s_disc.add_argument("--takeover", action="store_true", help="Also disconnect foreign WireGuard tunnels")
    s_disc.add_argument("--json", action="store_true", help="Output JSON")

    # reconnect
    s_rec = sub.add_parser("reconnect", help="Reconnect to the current or last cluster")
    s_rec.add_argument("--json", action="store_true", help="Output JSON")

    # servers
    s_srv = sub.add_parser("servers", help="Search or list WireGuard server clusters")
    s_srv.add_argument("query", nargs="?", default="", help="Search query (city, country, code)")
    s_srv.add_argument("--country", default="", help="Filter by 2-letter country code")
    s_srv.add_argument("--kind", default="", help="Filter by cluster kind (generic, static, double)")
    s_srv.add_argument("--refresh", action="store_true", help="Force refresh from Surfshark API")
    s_srv.add_argument("--probe", action="store_true", help="Probe ICMP latency to nearest servers")
    s_srv.add_argument("--limit", type=int, default=30, help="Max rows to display")
    s_srv.add_argument("--json", action="store_true", help="Output JSON")

    # countries
    s_cnt = sub.add_parser("countries", help="List available countries and server counts")
    s_cnt.add_argument("--refresh", action="store_true", help="Force refresh from Surfshark API")
    s_cnt.add_argument("--json", action="store_true", help="Output JSON")

    # ip
    s_ip = sub.add_parser("ip", help="Verify current egress IP, location, and leak protection")
    s_ip.add_argument("--json", action="store_true", help="Output JSON")

    # login
    s_login = sub.add_parser("login", help="Authenticate with Surfshark (native email/password + 2FA or import)")
    s_login.add_argument("--email", default="", help="Account email address")
    s_login.add_argument(
        "--import-official",
        action="store_true",
        help="Import existing session from ~/.config/Surfshark",
    )
    s_login.add_argument("--json", action="store_true", help="Output JSON")

    # logout
    s_logout = sub.add_parser("logout", help="Revoke session token and wipe local credentials")
    s_logout.add_argument("--json", action="store_true", help="Output JSON")

    # whoami
    s_who = sub.add_parser("whoami", help="Show current authentication state and token expiry")
    s_who.add_argument("--json", action="store_true", help="Output JSON")

    # keys
    s_keys = sub.add_parser("keys", help="Inspect or rotate WireGuard public/private keypair")
    s_keys.add_argument("--rotate", action="store_true", help="Force revalidation or rotation of WireGuard keypair")
    s_keys.add_argument("--json", action="store_true", help="Output JSON")

    # settings
    s_set = sub.add_parser("settings", help="View or modify daemon settings")
    s_set.add_argument("kv", nargs="*", help="Key=value pairs to update (e.g. cleanweb=true lan_bypass=lan)")
    s_set.add_argument("--json", action="store_true", help="Output JSON")

    # ui
    s_ui = sub.add_parser("ui", help="Open the local Web UI in a chromeless desktop app window")
    s_ui.add_argument("--no-open", action="store_true", help="Print the single-use auth URL without launching a browser")
    s_ui.add_argument("--json", action="store_true", help="Output JSON")

    # daemon
    s_dae = sub.add_parser("daemon", help="Run the Surf Shark Ultra Lite background control daemon")
    s_dae.add_argument("--port", type=int, default=None, help="Override TCP loopback port (default: 8777)")
    s_dae.add_argument("--no-web", action="store_true", help="Disable TCP 127.0.0.1 listener (Unix socket only)")
    s_dae.add_argument("--debug", action="store_true", help="Enable debug logging")

    # logs
    s_logs = sub.add_parser("logs", help="Show recent daemon log entries (redacted)")
    s_logs.add_argument("--limit", type=int, default=100, help="Number of lines to show")
    s_logs.add_argument("--json", action="store_true", help="Output JSON")

    # doctor
    s_doc = sub.add_parser("doctor", help="Run self-diagnostics on NetworkManager, Polkit, routing, and keys")
    s_doc.add_argument("--json", action="store_true", help="Output JSON")

    # version
    s_ver = sub.add_parser("version", help="Print version")
    s_ver.add_argument("--json", action="store_true", help="Output JSON")

    return p


def _parse_kv_patch(pairs: Sequence[str]) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    for item in pairs:
        if item in ("get", "set"):
            continue
        if "=" not in item:
            raise ValidationError(f"Expected key=value, got {item!r}")
        k, raw_v = item.split("=", 1)
        k = k.strip()
        v_low = raw_v.strip().lower()
        if v_low in ("true", "yes", "on"):
            val: Any = True
        elif v_low in ("false", "no", "off") and k != "kill_switch":
            val = False
        elif v_low in ("null", "none"):
            val = None
        elif raw_v.strip().isdigit():
            val = int(raw_v.strip())
        else:
            val = raw_v.strip()

        if "." in k:
            top, sub = k.split(".", 1)
            patch.setdefault(top, {})[sub] = val
        else:
            patch[k] = val
    return patch


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.cmd or "status"
    want_json = bool(getattr(args, "json", False))
    style = Style(enabled=False if getattr(args, "no_color", False) else None)

    if cmd == "version":
        if want_json:
            _print_json({"version": __version__})
        else:
            print(f"surfshark-lite {__version__}")
        return EXIT_OK

    if cmd == "daemon":
        lvl = logging.DEBUG if getattr(args, "debug", False) else logging.INFO
        return run_daemon(port_override=args.port, no_web=args.no_web, log_level=lvl)

    if cmd == "ui":
        try:
            res = launch_ui(no_open=args.no_open)
            if want_json:
                _print_json(res)
            else:
                print(f"UI ready ({res['launcher']}): {res['url']}")
            return EXIT_OK
        except SslError as exc:
            if want_json:
                _print_json(exc.to_envelope())
            else:
                sys.stderr.write(f"Error [{exc.code.value}]: {exc.message}\n")
            return map_error_to_exit_code(exc.code)

    ipc = IpcClient()
    ipc.ensure_daemon(autostart=True, timeout=6.0)

    try:
        if cmd == "status":
            st = ipc.request("GET", "/api/v1/status")
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            if getattr(args, "require_protected", False):
                verdict = (st.get("telemetry") or {}).get("verdict")
                if verdict != "PROTECTED":
                    return EXIT_UNPROTECTED
            return EXIT_OK

        if cmd == "connect":
            st = ipc.request(
                "POST",
                "/api/v1/connect",
                body={
                    "target": args.target,
                    "kind": args.kind,
                    "physical_only": args.physical_only,
                    "takeover": args.takeover,
                },
            )
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            return EXIT_OK

        if cmd == "switch":
            st = ipc.request("POST", "/api/v1/switch", body={"target": args.target})
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            return EXIT_OK

        if cmd == "fastest":
            target = f"fastest {args.country}".strip() if args.country else "fastest"
            st = ipc.request("POST", "/api/v1/connect", body={"target": target})
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            return EXIT_OK

        if cmd == "disconnect":
            st = ipc.request("POST", "/api/v1/disconnect", body={"takeover": args.takeover})
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            return EXIT_OK

        if cmd == "reconnect":
            st = ipc.request("POST", "/api/v1/reconnect", body={})
            if want_json:
                _print_json(st)
            else:
                _render_status(st, style)
            return EXIT_OK

        if cmd == "servers":
            if args.probe:
                ipc.request("POST", "/api/v1/servers/probe", body={"scope": "nearest"})
            qs = []
            if args.query:
                qs.append(f"q={args.query}")
            if args.country:
                qs.append(f"country={args.country}")
            if args.kind:
                qs.append(f"kind={args.kind}")
            if args.refresh:
                qs.append("refresh=1")
            q_str = ("?" + "&".join(qs)) if qs else ""
            data = ipc.request("GET", f"/api/v1/servers{q_str}")
            if want_json:
                _print_json(data)
            else:
                rows = []
                for c in (data.get("clusters") or [])[: args.limit]:
                    lat = f"{c['latency_ms']} ms" if c.get("latency_ms") is not None else "-"
                    load = f"{c['load']}%" if c.get("load") is not None else "-"
                    rows.append([c.get("country_code", ""), c.get("location", ""), c.get("hostname", ""), load, lat, c.get("kind", "")])
                print(format_table(["CC", "CITY", "HOSTNAME", "LOAD", "RTT", "KIND"], rows, style=style))
            return EXIT_OK

        if cmd == "countries":
            q_str = "?refresh=1" if args.refresh else ""
            data = ipc.request("GET", f"/api/v1/servers{q_str}")
            countries = data.get("countries") or []
            if want_json:
                _print_json({"countries": countries})
            else:
                rows = [
                    [c.get("country_code", ""), c.get("country", ""), str(c.get("cluster_count", 0)), ", ".join((c.get("cities") or [])[:4])]
                    for c in countries
                ]
                print(format_table(["CC", "COUNTRY", "SERVERS", "CITIES"], rows, style=style))
            return EXIT_OK

        if cmd == "ip":
            data = ipc.request("GET", "/api/v1/ip")
            if want_json:
                _print_json(data)
            else:
                eg = data.get("egress") or {}
                tel = data.get("telemetry") or {}
                print(f"Verdict:  {tel.get('verdict')} ({tel.get('reason')})")
                print(f"IP:       {eg.get('ip') or 'unknown'}")
                print(f"Location: {eg.get('city') or '-'}, {eg.get('country') or eg.get('country_code') or '-'}")
                print(f"ISP:      {eg.get('isp') or '-'}")
                print(f"Provider: {eg.get('provider') or '-'}")
            return EXIT_OK

        if cmd == "login":
            if args.import_official:
                res = ipc.request("POST", "/api/v1/auth/import-official", body={})
                if want_json:
                    _print_json(res)
                else:
                    print(style.green(f"Imported session ({res.get('account_hint')})"))
                return EXIT_OK

            email = (args.email or "").strip() or input("Surfshark Email: ").strip()
            password = getpass.getpass("Surfshark Password: ")
            res = ipc.request("POST", "/api/v1/auth/login", body={"email": email, "password": password})
            if res.get("status") == "otp_required":
                cid = res["challenge_id"]
                otp_code = input("2FA Verification Code (6-8 digits): ").strip()
                res = ipc.request("POST", "/api/v1/auth/otp", body={"challenge_id": cid, "code": otp_code})
            if want_json:
                _print_json(res)
            else:
                print(style.green(f"Authenticated as {res.get('account_hint')}"))
            return EXIT_OK

        if cmd == "logout":
            res = ipc.request("POST", "/api/v1/auth/logout", body={})
            if want_json:
                _print_json(res)
            else:
                print("Logged out and wiped local credentials.")
            return EXIT_OK

        if cmd == "whoami":
            res = ipc.request("GET", "/api/v1/auth")
            if want_json:
                _print_json(res)
            else:
                for k, v in res.items():
                    print(f"{k}: {v}")
            return EXIT_OK

        if cmd == "keys":
            if args.rotate:
                res = ipc.request("POST", "/api/v1/keys/rotate", body={})
            else:
                res = ipc.request("GET", "/api/v1/keys")
            if want_json:
                _print_json(res)
            else:
                for k, v in res.items():
                    print(f"{k}: {v}")
            return EXIT_OK

        if cmd == "settings":
            patch = _parse_kv_patch(args.kv)
            if patch:
                res = ipc.request("PATCH", "/api/v1/settings", body=patch)
            else:
                res = ipc.request("GET", "/api/v1/settings")
            if want_json:
                _print_json(res)
            else:
                print(json.dumps(res, indent=2))
            return EXIT_OK

        if cmd == "logs":
            res = ipc.request("GET", f"/api/v1/logs?limit={args.limit}")
            if want_json:
                _print_json(res)
            else:
                for entry in res.get("entries") or []:
                    print(f"{entry.get('t')} [{entry.get('level', '').upper()}] {entry.get('logger')}: {entry.get('msg')}")
            return EXIT_OK

        if cmd == "doctor":
            res = ipc.request("GET", "/api/v1/doctor")
            if want_json:
                _print_json(res)
            else:
                for chk in res.get("checks") or []:
                    mark = style.green("PASS") if chk.get("ok") else style.red("FAIL")
                    print(f"[{mark}] {chk.get('title')}: {chk.get('detail')}")
                    if not chk.get("ok") and chk.get("remediation"):
                        print(f"       Fix: {chk['remediation']}")
            return EXIT_OK if res.get("ok") else EXIT_DRIVER

    except SslError as exc:
        if want_json:
            _print_json(exc.to_envelope())
        else:
            sys.stderr.write(f"Error [{exc.code.value}]: {exc.message}\n")
            if exc.code == ErrorCode.TARGET_AMBIGUOUS and exc.details.get("candidates"):
                for cand in exc.details["candidates"][:5]:
                    sys.stderr.write(f"  - {cand.get('label')} ({cand.get('hostname')})\n")
        return map_error_to_exit_code(exc.code)

    return EXIT_OK
