"""Unit tests for 7-state Telemetry Verdict, Watchdog L0-L5 ladder, Egress quorum, Web security matrix, and SurfsharkdDriver."""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite.egress import EgressChecker, EgressReport
from surfshark_lite.telemetry import Verdict, evaluate_verdict
from surfshark_lite.tunnel import routing
from surfshark_lite.tunnel.surfsharkd import SurfsharkdDriver
from surfshark_lite.watchdog import WatchdogLevel, WatchdogState, step_watchdog
from surfshark_lite.web.server import validate_http_security


class TestTelemetryWatchdogAndWeb(unittest.TestCase):
    def test_all_seven_verdicts(self) -> None:
        eg_ok = EgressReport("203.0.113.9", "US", "United States", "San Francisco", "Surfshark", True, "surfshark", 100.0)

        # 1. EXPOSED
        v, _ = evaluate_verdict(
            tunnel_up=False, iface_up=False, tunnel_age_s=None, handshake_age_s=None,
            handshake_source="wg", rx_bytes=0, drifts=(), dns_ok=True,
            egress=None, baseline_ip=None, expected_country_code="US",
        )
        self.assertEqual(v, Verdict.EXPOSED)

        # 2. ROUTING_DEGRADED
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=30.0, handshake_age_s=5.0,
            handshake_source="wg", rx_bytes=1024,
            drifts=(routing.Drift("ipv4", "missing_rule", "Missing rule 30021"),),
            dns_ok=True, egress=eg_ok, baseline_ip="198.51.100.1", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.ROUTING_DEGRADED)

        # 3. HANDSHAKE_PENDING
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=5.0, handshake_age_s=None,
            handshake_source="wg", rx_bytes=0, drifts=(), dns_ok=True,
            egress=None, baseline_ip="198.51.100.1", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.HANDSHAKE_PENDING)

        # 4. STALE_HANDSHAKE
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=300.0, handshake_age_s=240.0,
            handshake_source="wg", rx_bytes=1024, drifts=(), dns_ok=True,
            egress=eg_ok, baseline_ip="198.51.100.1", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.STALE_HANDSHAKE)

        # 5. LEAK_SUSPECTED (matches baseline IP)
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=60.0, handshake_age_s=10.0,
            handshake_source="wg", rx_bytes=1024, drifts=(), dns_ok=True,
            egress=eg_ok, baseline_ip="203.0.113.9", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.LEAK_SUSPECTED)

        # 6. UNVERIFIED (no egress check yet)
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=60.0, handshake_age_s=10.0,
            handshake_source="wg", rx_bytes=1024, drifts=(), dns_ok=True,
            egress=None, baseline_ip="198.51.100.1", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.UNVERIFIED)

        # 7. PROTECTED
        v, _ = evaluate_verdict(
            tunnel_up=True, iface_up=True, tunnel_age_s=60.0, handshake_age_s=10.0,
            handshake_source="wg", rx_bytes=1024, drifts=(), dns_ok=True,
            egress=eg_ok, baseline_ip="198.51.100.1", expected_country_code="US",
        )
        self.assertEqual(v, Verdict.PROTECTED)

    def test_watchdog_escalation_and_hysteresis_reset(self) -> None:
        st = WatchdogState()
        # Stale handshake jumps to L2_REAPPLY_POKE
        dec1 = step_watchdog(st, Verdict.STALE_HANDSHAKE, now=100.0)
        self.assertEqual(dec1.next_state.level, WatchdogLevel.L2_REAPPLY_POKE)
        self.assertEqual(dec1.action, "reapply_poke")

        # Dwell < 15s at L2 does nothing
        dec2 = step_watchdog(dec1.next_state, Verdict.STALE_HANDSHAKE, now=105.0)
        self.assertEqual(dec2.action, "none")

        # Dwell >= 15s escalates to L3_FAILOVER_SAME_COUNTRY
        dec3 = step_watchdog(dec2.next_state, Verdict.STALE_HANDSHAKE, now=116.0)
        self.assertEqual(dec3.next_state.level, WatchdogLevel.L3_FAILOVER_SAME_COUNTRY)
        self.assertEqual(dec3.action, "failover_cluster")

        # Recovery to PROTECTED requires 30s sustained healthy before resetting to L0
        dec4 = step_watchdog(dec3.next_state, Verdict.PROTECTED, now=120.0)
        self.assertEqual(dec4.next_state.level, WatchdogLevel.L3_FAILOVER_SAME_COUNTRY)
        dec5 = step_watchdog(dec4.next_state, Verdict.PROTECTED, now=151.0)
        self.assertEqual(dec5.next_state.level, WatchdogLevel.L0_HEALTHY)

    def test_egress_quorum_and_circuit_breaker(self) -> None:
        def _fake_fetcher(url: str, _timeout: float) -> str:
            if "surfshark.com" in url:
                return json.dumps({"ip": "203.0.113.50", "countryCode": "NL", "country": "Netherlands", "secured": True})
            if "ipinfo.io" in url:
                return json.dumps({"ip": "203.0.113.50", "country": "DE", "city": "Frankfurt", "org": "AS9009"})
            raise OSError("Provider down")

        checker = EgressChecker(fetcher=_fake_fetcher)
        rep = checker.check(expected_country_code="DE")
        self.assertIsNotNone(rep)
        assert rep is not None
        self.assertEqual(rep.country_code, "DE")
        self.assertEqual(rep.provider, "surfshark+ipinfo")

    def test_web_security_matrix(self) -> None:
        # 1. Invalid Host -> 421
        err = validate_http_security(
            method="GET", path="/api/v1/status",
            headers={"Host": "evil.example.com"}, port=8777, is_unix_socket=False,
        )
        self.assertEqual(err[0] if err else 0, 421)

        # 2. Sec-Fetch-Site: cross-site -> 403
        err = validate_http_security(
            method="GET", path="/api/v1/status",
            headers={"Host": "127.0.0.1:8777", "Sec-Fetch-Site": "cross-site"}, port=8777, is_unix_socket=False,
        )
        self.assertEqual(err[0] if err else 0, 403)

        # 3. Foreign Origin -> 403
        err = validate_http_security(
            method="POST", path="/api/v1/connect",
            headers={"Host": "127.0.0.1:8777", "Origin": "https://attacker.com", "X-SSUL": "1"},
            port=8777, is_unix_socket=False,
        )
        self.assertEqual(err[0] if err else 0, 403)

        # 4. POST without X-SSUL: 1 -> 403
        err = validate_http_security(
            method="POST", path="/api/v1/connect",
            headers={"Host": "127.0.0.1:8777", "Content-Type": "application/json", "Content-Length": "2"},
            port=8777, is_unix_socket=False,
        )
        self.assertEqual(err[0] if err else 0, 403)

        # 5. POST with wrong Content-Type -> 415
        err = validate_http_security(
            method="POST", path="/api/v1/connect",
            headers={"Host": "127.0.0.1:8777", "X-SSUL": "1", "Content-Type": "text/plain", "Content-Length": "2"},
            port=8777, is_unix_socket=False,
        )
        self.assertEqual(err[0] if err else 0, 415)

        # 6. Valid POST passes
        ok = validate_http_security(
            method="POST", path="/api/v1/connect",
            headers={
                "Host": "127.0.0.1:8777",
                "Origin": "http://127.0.0.1:8777",
                "Sec-Fetch-Site": "same-origin",
                "X-SSUL": "1",
                "Content-Type": "application/json",
                "Content-Length": "18",
            },
            port=8777, is_unix_socket=False,
        )
        self.assertIsNone(ok)

    def test_surfsharkd_driver_over_mock_unix_socket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "surfsharkd.sock"
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(str(sock_path))
            srv.listen(5)

            def _serve() -> None:
                try:
                    conn, _ = srv.accept()
                    with conn:
                        data = conn.recv(4096)
                        req = json.loads(data.decode("utf-8").strip())
                        if req.get("method") == "getState":
                            resp = {
                                "type": "result",
                                "value": {
                                    "connectivity": 4,
                                    "ipv6_active_connection_state": 2,
                                    "ipv6_device_state": 100,
                                    "wg_active_connection_state": 2,
                                    "wg_device_state": 100,
                                    "wg_exists": True,
                                },
                            }
                            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
                finally:
                    srv.close()

            t = threading.Thread(target=_serve, daemon=True)
            t.start()

            drv = SurfsharkdDriver(sock_path=sock_path)
            ok, msg = drv.probe()
            self.assertTrue(ok)
            self.assertIn("surfsharkd.sock", msg)
            t.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
