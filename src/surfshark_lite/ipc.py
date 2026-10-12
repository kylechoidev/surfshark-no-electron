"""Unix domain socket HTTP client (`control.sock`) and daemon auto-starter."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from surfshark_lite.errors import ErrorCode, SslError
from surfshark_lite.paths import control_sock_path, ensure_all_dirs


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection over a local AF_UNIX stream socket."""

    def __init__(self, sock_path: Path, timeout: float = 20.0) -> None:
        super().__init__("127.0.0.1", timeout=timeout)
        self._sock_path = sock_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(str(self._sock_path))
        self.sock = sock


class IpcClient:
    """Client for the local daemon control socket (`$XDG_RUNTIME_DIR/surfshark-ultralite/control.sock`)."""

    def __init__(self, sock_path: Path | None = None) -> None:
        self.sock_path = sock_path or control_sock_path()

    def ping(self, timeout: float = 1.0) -> bool:
        if not self.sock_path.exists():
            return False
        try:
            res = self.request("GET", "/api/v1/health", timeout=timeout)
            return bool(res.get("ok"))
        except Exception:
            return False

    def ensure_daemon(self, autostart: bool = True, timeout: float = 6.0) -> bool:
        if self.ping(timeout=1.0):
            return True
        if not autostart:
            return False

        ensure_all_dirs()
        # Try systemd --user first if available
        systemctl = shutil.which("systemctl")
        started_via_systemd = False
        if systemctl:
            try:
                proc = subprocess.run(
                    [systemctl, "--user", "start", "surfshark-ultralite.service"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3.0,
                    shell=False,
                )
                if proc.returncode == 0:
                    started_via_systemd = True
            except Exception:
                pass

        if not started_via_systemd:
            env = dict(os.environ)
            subprocess.Popen(
                [sys.executable, "-m", "surfshark_lite", "daemon"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env=env,
            )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.ping(timeout=0.5):
                return True
            time.sleep(0.1)
        return self.ping(timeout=0.5)

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float = 25.0,
    ) -> dict[str, Any]:
        conn = _UnixHTTPConnection(self.sock_path, timeout=timeout)
        headers = {
            "Host": "127.0.0.1",
            "X-SSUL": "1",
            "Accept": "application/json",
        }
        payload_bytes: bytes | None = None
        if body is not None:
            payload_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(payload_bytes))

        try:
            conn.request(method.upper(), path, body=payload_bytes, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(2 * 1024 * 1024)
            status = resp.status
        except OSError as exc:
            raise SslError(
                ErrorCode.INTERNAL,
                f"Unable to connect to Surf Shark Ultra Lite daemon at {self.sock_path}: {exc}",
                http_status=503,
            ) from exc
        finally:
            conn.close()

        data: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(parsed, dict):
                    data = parsed
            except ValueError:
                pass

        if status >= 400:
            err_obj = data.get("error") if isinstance(data.get("error"), dict) else {}
            code_str = str(err_obj.get("code") or "INTERNAL")
            msg = str(err_obj.get("message") or f"Daemon returned HTTP {status}")
            details = err_obj.get("details") if isinstance(err_obj.get("details"), dict) else {}
            try:
                err_code = ErrorCode(code_str)
            except ValueError:
                err_code = ErrorCode.INTERNAL
            raise SslError(err_code, msg, details=details, http_status=status)

        return data
