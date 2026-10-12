"""Dual-listener HTTP server (TCP 127.0.0.1:8777 + Unix control.sock) with security guards."""

from __future__ import annotations

import http.cookies
import http.server
import json
import logging
import os
import socket
import socketserver
import threading
import urllib.parse
from pathlib import Path
from typing import Any

from surfshark_lite.errors import ErrorCode, SslError
from surfshark_lite.web.routes import dispatch_api_request
from surfshark_lite.web.sse import SseClientStream, format_sse_frame

log = logging.getLogger("surfshark_lite.web.server")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = 64 * 1024

CSP_HEADER = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

STATIC_ASSETS: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/favicon.ico": ("icon.svg", "image/svg+xml"),
}


def validate_http_security(
    *,
    method: str,
    path: str,
    headers: dict[str, str],
    port: int,
    is_unix_socket: bool,
) -> tuple[int, str] | None:
    """Validate Host, Origin, Sec-Fetch-Site, X-SSUL, and Content-Type headers (§10.2).

    Returns `(http_status, error_message)` if rejected, or `None` if allowed.
    """
    h = {k.lower(): v.strip() for k, v in headers.items()}

    # 1. Host header validation (DNS rebinding defense)
    host = h.get("host", "")
    allowed_hosts = {
        "127.0.0.1",
        f"127.0.0.1:{port}",
        "localhost",
        f"localhost:{port}",
    }
    if not is_unix_socket and host not in allowed_hosts:
        return 421, f"Misdirected Request: invalid Host header {host!r}"

    # 2. Sec-Fetch-Site validation (cross-site defense)
    sfs = h.get("sec-fetch-site", "").lower()
    if sfs and sfs not in ("same-origin", "none"):
        return 403, f"Forbidden: Sec-Fetch-Site={sfs!r} rejected"

    # 3. Origin header validation (CSRF defense)
    origin = h.get("origin", "")
    if origin:
        allowed_origins = {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            "http://127.0.0.1",
            "http://localhost",
        }
        if origin not in allowed_origins:
            return 403, f"Forbidden: invalid Origin header {origin!r}"

    # 4. Mutating method guards (POST / PATCH / PUT / DELETE)
    if method.upper() in ("POST", "PATCH", "PUT", "DELETE"):
        if h.get("x-ssul") != "1":
            return 403, "Forbidden: missing required X-SSUL: 1 header"
        clen = int(h.get("content-length") or "0")
        if clen > MAX_BODY_BYTES:
            return 413, f"Payload Too Large ({clen} > {MAX_BODY_BYTES} bytes)"
        if clen > 0:
            ctype = h.get("content-type", "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                return 415, f"Unsupported Media Type: expected application/json, got {ctype!r}"

    return None


def _extract_session_cookie(cookie_header: str | None) -> str | None:
    if not cookie_header:
        return None
    c = http.cookies.SimpleCookie()
    try:
        c.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = c.get("ssul_session")
    return morsel.value if morsel else None


class _SSULRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging
        pass

    @property
    def controller(self) -> Any:
        return getattr(self.server, "controller")

    @property
    def is_unix_socket(self) -> bool:
        return bool(getattr(self.server, "is_unix_socket", False))

    @property
    def tcp_port(self) -> int:
        return int(getattr(self.server, "tcp_port", 8777))

    def _send_security_headers(self, is_api: bool = True) -> None:
        self.send_header("Content-Security-Policy", CSP_HEADER)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if is_api:
            self.send_header("Cache-Control", "no-store")

    def _send_json(self, status: int, data: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_security_headers(is_api=True)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _handle_all(self, method: str) -> None:
        headers_dict = {k: v for k, v in self.headers.items()}
        sec_err = validate_http_security(
            method=method,
            path=self.path,
            headers=headers_dict,
            port=self.tcp_port,
            is_unix_socket=self.is_unix_socket,
        )
        if sec_err is not None:
            st, msg = sec_err
            self._send_json(st, {"error": {"code": "PERMISSION_DENIED", "message": msg, "details": {}}})
            return

        parsed = urllib.parse.urlsplit(self.path)
        clean_path = parsed.path or "/"
        qs = urllib.parse.parse_qs(parsed.query)

        # Single-use ticket exchange: GET /auth?t=<ticket>
        if method == "GET" and clean_path == "/auth":
            tickets = qs.get("t", [])
            ticket = tickets[0] if tickets else ""
            sess_tok = self.controller.redeem_ui_ticket(ticket)
            if not sess_tok:
                self._send_json(
                    401,
                    {"error": {"code": "AUTH_REQUIRED", "message": "Invalid or expired UI launch ticket", "details": {}}},
                )
                return
            self.send_response(303)
            self._send_security_headers(is_api=True)
            self.send_header(
                "Set-Cookie",
                f"ssul_session={sess_tok}; HttpOnly; SameSite=Strict; Path=/",
            )
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # Static UI assets
        if method == "GET" and clean_path in STATIC_ASSETS:
            fname, mime = STATIC_ASSETS[clean_path]
            fpath = STATIC_DIR / fname
            if not fpath.is_file():
                self._send_json(404, {"error": {"code": "VALIDATION", "message": "Static asset not found", "details": {}}})
                return
            content = fpath.read_bytes()
            self.send_response(200)
            self._send_security_headers(is_api=(clean_path in ("/", "/index.html")))
            # If user opens GET / on localhost without a valid session cookie yet, mint one
            if clean_path in ("/", "/index.html") and not self.is_unix_socket:
                cur_cookie = _extract_session_cookie(self.headers.get("Cookie"))
                if not self.controller.validate_session_cookie(cur_cookie):
                    new_tok = self.controller.issue_direct_session_cookie()
                    self.send_header(
                        "Set-Cookie",
                        f"ssul_session={new_tok}; HttpOnly; SameSite=Strict; Path=/",
                    )
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(content)
            return

        # Check session cookie on TCP for /api/v1/* (except /api/v1/health)
        if not self.is_unix_socket and clean_path.startswith("/api/") and clean_path != "/api/v1/health":
            cur_cookie = _extract_session_cookie(self.headers.get("Cookie"))
            # Also permit local CLI/scripts that explicitly supply X-SSUL: 1 with no Origin header
            has_cli_header = self.headers.get("X-SSUL") == "1" and not self.headers.get("Origin")
            if not self.controller.validate_session_cookie(cur_cookie) and not has_cli_header:
                self._send_json(
                    401,
                    {
                        "error": {
                            "code": "AUTH_REQUIRED",
                            "message": "Missing or expired UI session cookie. Reload http://127.0.0.1:8777/",
                            "details": {},
                        }
                    },
                )
                return

        # SSE stream: GET /api/v1/events
        if method == "GET" and clean_path == "/api/v1/events":
            self._handle_sse()
            return

        # Parse JSON body for mutating requests
        body_obj: dict[str, Any] | None = None
        clen = int(self.headers.get("Content-Length") or "0")
        if clen > 0:
            raw_body = self.rfile.read(clen)
            try:
                parsed_json = json.loads(raw_body.decode("utf-8"))
                if not isinstance(parsed_json, dict):
                    raise ValueError("JSON root must be an object")
                body_obj = parsed_json
            except Exception as exc:
                self._send_json(
                    400,
                    {"error": {"code": "VALIDATION", "message": f"Invalid JSON body: {exc}", "details": {}}},
                )
                return

        try:
            status_code, resp_dict = dispatch_api_request(
                self.controller,
                method,
                self.path,
                body_obj,
                is_unix_socket=self.is_unix_socket,
            )
            self._send_json(status_code, resp_dict)
        except SslError as exc:
            self._send_json(exc.http_status, exc.to_envelope())
        except Exception as exc:
            log.exception("Unhandled API exception on %s %s", method, self.path)
            self._send_json(
                500,
                {"error": {"code": "INTERNAL", "message": str(exc), "details": {}}},
            )

    def _handle_sse(self) -> None:
        self.send_response(200)
        self._send_security_headers(is_api=True)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        stream = SseClientStream()
        unsub = self.controller.subscribe_sse(stream.push)
        try:
            # Send initial state snapshot immediately
            init_frame = format_sse_frame("state", self.controller.status_dict())
            self.wfile.write(init_frame)
            self.wfile.flush()

            while True:
                frame = stream.get(timeout=15.0)
                if frame is None:
                    break
                self.wfile.write(frame)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            unsub()
            stream.close()

    def do_GET(self) -> None:
        self._handle_all("GET")

    def do_POST(self) -> None:
        self._handle_all("POST")

    def do_PATCH(self) -> None:
        self._handle_all("PATCH")

    def do_PUT(self) -> None:
        self._handle_all("PUT")

    def do_DELETE(self) -> None:
        self._handle_all("DELETE")


class _ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class DualHttpServer:
    """Manages the Unix control socket server and the optional TCP 127.0.0.1:8777 web UI server."""

    def __init__(
        self,
        controller: Any,
        *,
        unix_sock_path: Path,
        tcp_enabled: bool = True,
        tcp_port: int = 8777,
    ) -> None:
        self.controller = controller
        self.unix_sock_path = unix_sock_path
        self.tcp_enabled = tcp_enabled
        self.tcp_port = tcp_port

        self._unix_srv: _ThreadedUnixServer | None = None
        self._tcp_srv: _ThreadedTCPServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self.unix_sock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.unix_sock_path.exists() or self.unix_sock_path.is_socket():
            try:
                self.unix_sock_path.unlink()
            except OSError:
                pass

        old_umask = os.umask(0o177)
        try:
            u_srv = _ThreadedUnixServer(str(self.unix_sock_path), _SSULRequestHandler)
        finally:
            os.umask(old_umask)
        os.chmod(self.unix_sock_path, 0o600)
        setattr(u_srv, "controller", self.controller)
        setattr(u_srv, "is_unix_socket", True)
        setattr(u_srv, "tcp_port", self.tcp_port)
        self._unix_srv = u_srv

        t_unix = threading.Thread(target=u_srv.serve_forever, name="ssul-http-unix", daemon=True)
        t_unix.start()
        self._threads.append(t_unix)

        if self.tcp_enabled:
            t_srv: _ThreadedTCPServer | None = None
            base_port = self.tcp_port
            for offset in range(10 if base_port != 0 else 1):
                cand_port = base_port + offset if base_port != 0 else 0
                try:
                    t_srv = _ThreadedTCPServer(("127.0.0.1", cand_port), _SSULRequestHandler)
                    break
                except OSError:
                    if base_port == 0 or offset == 9:
                        raise
            assert t_srv is not None
            actual_port = int(t_srv.server_address[1])
            setattr(t_srv, "controller", self.controller)
            setattr(t_srv, "is_unix_socket", False)
            setattr(t_srv, "tcp_port", actual_port)
            setattr(u_srv, "tcp_port", actual_port)
            self.tcp_port = actual_port
            if hasattr(self.controller, "settings") and isinstance(self.controller.settings.get("web"), dict):
                self.controller.settings["web"]["port"] = actual_port
            self._tcp_srv = t_srv

            t_tcp = threading.Thread(target=t_srv.serve_forever, name="ssul-http-tcp", daemon=True)
            t_tcp.start()
            self._threads.append(t_tcp)

    def stop(self) -> None:
        if self._tcp_srv is not None:
            try:
                self._tcp_srv.shutdown()
                self._tcp_srv.server_close()
            except Exception:
                pass
            self._tcp_srv = None

        if self._unix_srv is not None:
            try:
                self._unix_srv.shutdown()
                self._unix_srv.server_close()
            except Exception:
                pass
            self._unix_srv = None

        if self.unix_sock_path.exists() or self.unix_sock_path.is_socket():
            try:
                self.unix_sock_path.unlink()
            except OSError:
                pass
