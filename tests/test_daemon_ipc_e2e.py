"""End-to-end integration test for Controller + DualHttpServer + IpcClient + Single-use UI Ticket Exchange."""

from __future__ import annotations

import http.client
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parent.parent / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from surfshark_lite.controller import Controller
from surfshark_lite.errors import SslError
from surfshark_lite.ipc import IpcClient
from surfshark_lite.tunnel.base import DriverCaps, Observation, TunnelSpec
from surfshark_lite.web.server import DualHttpServer


class _DummyDriver:
    name = "native"

    def probe(self) -> tuple[bool, str]:
        return True, "Dummy NM 1.46"

    def caps(self) -> DriverCaps:
        return DriverCaps(True, True, True, True)

    def current(self) -> Observation:
        return Observation(False, "none", None, None, None, "disconnected", None)

    def up(self, spec: TunnelSpec, cancel: threading.Event) -> Observation:
        return Observation(True, "self", spec.iface, spec.peers[0].public_key, spec.peers[0].endpoint, "activated", 1000.0)

    def replace_peer(self, spec: TunnelSpec, cancel: threading.Event, force_reset: bool = False) -> Observation:
        return self.up(spec, cancel)

    def down(self, cancel: threading.Event, takeover_foreign: bool = False) -> Observation:
        return Observation(False, "none", None, None, None, "disconnected", None)

    def set_listener(self, cb) -> None:
        pass

    def close(self) -> None:
        pass


class TestDaemonIpcEndToEnd(unittest.TestCase):
    def test_dual_server_ipc_and_single_use_ticket_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_home = os.environ.get("SSUL_HOME")
            os.environ["SSUL_HOME"] = tmp
            try:
                ctrl = Controller(driver=_DummyDriver())
                sock_path = Path(tmp) / "run" / "control.sock"
                srv = DualHttpServer(ctrl, unix_sock_path=sock_path, tcp_enabled=True, tcp_port=0)
                ctrl.start()
                srv.start()
                try:
                    ipc = IpcClient(sock_path=sock_path)
                    self.assertTrue(ipc.ping())

                    st = ipc.request("GET", "/api/v1/status")
                    self.assertEqual(st["connection_state"], "DISCONNECTED")

                    # Mint single-use ticket over Unix socket
                    t_res = ipc.request("POST", "/api/v1/ui-ticket", body={})
                    ticket = t_res["ticket"]
                    port = srv.tcp_port

                    # Attempt to mint UI ticket over TCP must fail with 403
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                    conn.request(
                        "POST",
                        "/api/v1/ui-ticket",
                        body=b"{}",
                        headers={"Host": f"127.0.0.1:{port}", "X-SSUL": "1", "Content-Type": "application/json"},
                    )
                    resp_forbidden = conn.getresponse()
                    resp_forbidden.read()
                    self.assertIn(resp_forbidden.status, (401, 403))
                    conn.close()

                    # Redeem single-use ticket once -> 303 + Set-Cookie
                    conn2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                    conn2.request("GET", f"/auth?t={ticket}", headers={"Host": f"127.0.0.1:{port}"})
                    resp_ok = conn2.getresponse()
                    resp_ok.read()
                    self.assertEqual(resp_ok.status, 303)
                    cookie_hdr = resp_ok.getheader("Set-Cookie") or ""
                    self.assertIn("ssul_session=", cookie_hdr)
                    conn2.close()

                    # Redeeming the same ticket a second time must fail with 401
                    conn3 = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
                    conn3.request("GET", f"/auth?t={ticket}", headers={"Host": f"127.0.0.1:{port}"})
                    resp_replay = conn3.getresponse()
                    resp_replay.read()
                    self.assertEqual(resp_replay.status, 401)
                    conn3.close()
                finally:
                    srv.stop()
                    ctrl.stop()
            finally:
                if old_home is None:
                    os.environ.pop("SSUL_HOME", None)
                else:
                    os.environ["SSUL_HOME"] = old_home


if __name__ == "__main__":
    unittest.main()
