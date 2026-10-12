"""Stdlib HTTPS JSON client with no proxies, no redirects, base failover, and strict validation."""

from __future__ import annotations

import email.utils
import http.client
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from surfshark_lite import __version__
from surfshark_lite.errors import NetworkError, ValidationError

MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MiB
DEFAULT_USER_AGENT = "SurfsharkLinux/3.14.0 device/desktop"


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    json_data: Any
    raw_text: str
    elapsed_ms: int

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


NoRedirectHandler = _NoRedirectHandler


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that optionally overrides TLS SNI server_hostname (used for anycast IP 172.16.0.36)."""

    def __init__(self, host: str, *args: Any, sni_hostname: str | None = None, **kwargs: Any) -> None:
        super().__init__(host, *args, **kwargs)
        self._sni_hostname = sni_hostname

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        server_hostname = self._sni_hostname or self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


class _SNIHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, sni_hostname: str | None = None) -> None:
        super().__init__(context=context)
        self._sni_hostname = sni_hostname

    def https_open(self, req: urllib.request.Request) -> Any:
        def _conn_factory(host: str, **kwargs: Any) -> _SNIHTTPSConnection:
            return _SNIHTTPSConnection(host, sni_hostname=self._sni_hostname, **kwargs)

        return self.do_open(_conn_factory, req)


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


create_ssl_context = _create_ssl_context


def _classify_transport_error(exc: BaseException) -> NetworkError:
    if isinstance(exc, ssl.SSLError):
        return NetworkError("tls", f"TLS error: {exc}")
    if isinstance(exc, TimeoutError) or isinstance(exc, socket.timeout):
        return NetworkError("timeout", f"Request timed out: {exc}")
    if isinstance(exc, socket.gaierror):
        return NetworkError("dns", f"DNS resolution failed: {exc}")
    if isinstance(exc, ConnectionResetError):
        return NetworkError("reset", f"Connection reset: {exc}")
    if isinstance(exc, urllib.error.URLError) and exc.reason is not None:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            return NetworkError("tls", f"TLS error: {reason}")
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return NetworkError("timeout", f"Request timed out: {reason}")
        if isinstance(reason, socket.gaierror):
            return NetworkError("dns", f"DNS resolution failed: {reason}")
        if isinstance(reason, ConnectionResetError):
            return NetworkError("reset", f"Connection reset: {reason}")
    return NetworkError("connect", f"Transport error: {exc}")


class HttpClient:
    """Zero-dependency HTTPS client with base URL failover and clock skew tracking."""

    def __init__(
        self,
        bases: list[str] | None = None,
        user_agent: str | None = None,
        transport: Callable[[str, str, dict[str, str], bytes | None, float, str | None], Response] | None = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.bases = list(bases) if bases else ["https://ext2.surfshark.com", "https://api.surfshark.com"]
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self._transport = transport
        self._clock = clock
        self._sleep = sleeper
        self._ssl_ctx = _create_ssl_context()
        self._good_base: str | None = None
        self._good_base_at: float = 0.0
        self.clock_skew_s: float = 0.0

    def _ordered_bases(self) -> list[str]:
        now = self._clock()
        if self._good_base and (now - self._good_base_at) < 3600.0 and self._good_base in self.bases:
            rest = [b for b in self.bases if b != self._good_base]
            return [self._good_base] + rest
        return list(self.bases)

    def _update_skew(self, headers: dict[str, str]) -> None:
        date_hdr = headers.get("date") or headers.get("Date")
        if not date_hdr:
            return
        try:
            dt = email.utils.parsedate_to_datetime(date_hdr)
            server_ts = dt.timestamp()
            self.clock_skew_s = server_ts - self._clock()
        except Exception:
            pass

    def _default_transport(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
        sni_hostname: str | None,
    ) -> Response:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _SNIHTTPSHandler(self._ssl_ctx, sni_hostname=sni_hostname),
            _NoRedirectHandler(),
        )
        req = urllib.request.Request(url=url, data=body, headers=headers, method=method)
        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = int(resp.status)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as http_err:
            status = int(http_err.code)
            resp_headers = {k.lower(): v for k, v in http_err.headers.items()} if http_err.headers else {}
            try:
                raw_bytes = http_err.read(MAX_RESPONSE_BYTES + 1) if http_err.fp else b""
            except Exception:
                raw_bytes = b""
        except BaseException as exc:
            raise _classify_transport_error(exc) from exc

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if len(raw_bytes) > MAX_RESPONSE_BYTES:
            raise NetworkError("reset", "Response exceeded 4 MiB limit")

        raw_text = raw_bytes.decode("utf-8", errors="replace")
        json_data: Any = None
        if raw_text.strip():
            try:
                json_data = json.loads(raw_text)
            except ValueError:
                json_data = None

        return Response(
            status=status,
            headers=resp_headers,
            json_data=json_data,
            raw_text=raw_text,
            elapsed_ms=elapsed_ms,
        )

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        bearer: str | None = None,
        timeout: float = 15.0,
        sni_hostname: str | None = None,
    ) -> Response:
        method = method.upper()
        req_headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            "x-device-type": "desktop",
            "x-device-platform": "linux",
            "x-device-version": "3.14.0",
        }
        if headers:
            req_headers.update(headers)
        if bearer:
            req_headers["Authorization"] = f"Bearer {bearer}"

        body_bytes: bytes | None = None
        if json_body is not None:
            req_headers["Content-Type"] = "application/json"
            body_bytes = json.dumps(json_body).encode("utf-8")

        transport_fn = self._transport or self._default_transport

        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            targets = [path_or_url]
            is_api_base = False
        else:
            targets = [f"{b.rstrip('/')}/{path_or_url.lstrip('/')}" for b in self._ordered_bases()]
            is_api_base = True

        last_err: NetworkError | None = None
        retry_delays = (0.5, 1.5) if method == "GET" else ()

        for idx, url in enumerate(targets):
            attempts = 1 + len(retry_delays)
            for attempt in range(attempts):
                try:
                    resp = transport_fn(method, url, req_headers, body_bytes, timeout, sni_hostname)
                    self._update_skew(resp.headers)
                    if is_api_base:
                        base_used = self._ordered_bases()[idx]
                        self._good_base = base_used
                        self._good_base_at = self._clock()
                    return resp
                except NetworkError as err:
                    last_err = err
                    if attempt < len(retry_delays):
                        self._sleep(retry_delays[attempt])
                        continue
                    break

        assert last_err is not None
        raise last_err


# Schema validation helpers for untrusted API JSON responses
def require_dict(obj: Any, context: str = "response") -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValidationError(f"Expected JSON object in {context}")
    return obj


def require_str(obj: dict[str, Any], key: str, max_len: int = 8192) -> str:
    val = obj.get(key)
    if not isinstance(val, str) or not val or len(val) > max_len:
        raise ValidationError(f"Invalid or missing string field '{key}'", field=key)
    return val


def opt_str(obj: dict[str, Any], key: str, max_len: int = 8192) -> str | None:
    val = obj.get(key)
    if val is None:
        return None
    if not isinstance(val, str) or len(val) > max_len:
        return None
    return val


def opt_int(obj: dict[str, Any], key: str) -> int | None:
    val = obj.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        return None
    return val
