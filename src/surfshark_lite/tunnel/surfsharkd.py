"""Fallback TunnelDriver communicating with surfsharkd.sock over NDJSON-RPC."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from surfshark_lite.errors import DriverError, ErrorCode
from surfshark_lite.netprobe import resolve_ipv4_all
from surfshark_lite.paths import runtime_dir
from surfshark_lite.tunnel.base import DriverCaps, Observation, TunnelSpec
from surfshark_lite.tunnel.surfsharkd_schema import (
    DEFAULT_ANYCAST_IP,
    DEFAULT_ANYCAST_PUB,
    SurfsharkdState,
    build_add_connection_params,
    build_replace_peer_params,
    build_rpc_request,
)

log = logging.getLogger("surfshark_lite.tunnel.surfsharkd")


def default_surfsharkd_sock_path() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "surfsharkd.sock"
    return runtime_dir().parent / "surfsharkd.sock"


class SurfsharkdDriver:
    """Fallback driver for environments without python3-gi, using surfsharkd.sock."""

    name = "surfsharkd"

    def __init__(self, sock_path: Path | None = None) -> None:
        self._sock_path = sock_path or default_surfsharkd_sock_path()
        self._last_spec: TunnelSpec | None = None
        self._since: float | None = None
        self._listener: Callable[[Observation], None] | None = None
        self._stream_stop = threading.Event()
        self._stream_thread: threading.Thread | None = None

    @property
    def sock_path(self) -> Path:
        return self._sock_path

    def _call(self, method: str, params: list[Any] | None = None, timeout: float = 10.0) -> Any:
        """Execute a single unary NDJSON-RPC call on surfsharkd.sock.

        CRITICAL (Gate G8): Do NOT call sock.shutdown(SHUT_WR) before reading the response;
        surfsharkd monitors EOF on the stream and cancels the in-flight GCancellable.
        """
        frame = build_rpc_request(method, params)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(self._sock_path))
                sock.sendall(frame)
                buf = bytearray()
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if b"\n" in chunk:
                        break
        except OSError as exc:
            raise DriverError(
                ErrorCode.DRIVER_UNAVAILABLE,
                f"surfsharkd RPC {method!r} failed on {self._sock_path}: {exc}",
            ) from exc

        line = bytes(buf).split(b"\n", 1)[0].strip()
        if not line:
            raise DriverError(
                ErrorCode.DRIVER_UNAVAILABLE,
                f"surfsharkd RPC {method!r} returned empty response",
            )
        try:
            resp = json.loads(line.decode("utf-8"))
        except Exception as exc:
            raise DriverError(
                ErrorCode.DRIVER_UNAVAILABLE,
                f"surfsharkd RPC {method!r} returned invalid JSON: {line!r}",
            ) from exc

        msg_type = resp.get("type")
        val = resp.get("value")
        if msg_type == "error":
            if isinstance(val, dict):
                err_msg = val.get("message") or str(val)
            else:
                err_msg = str(val)
            raise DriverError(ErrorCode.DRIVER_UNAVAILABLE, f"surfsharkd {method} error: {err_msg}")
        return val

    def stream_net_state(self, stop_timeout: float = 30.0) -> Iterator[SurfsharkdState]:
        """Yield state updates from surfsharkd's streaming `onNetStateChange` RPC."""
        frame = build_rpc_request("onNetStateChange", [])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(stop_timeout)
            sock.connect(str(self._sock_path))
            sock.sendall(frame)
            buf = b""
            while not self._stream_stop.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    msg = json.loads(line.decode("utf-8"))
                    if msg.get("type") == "item" and isinstance(msg.get("value"), dict):
                        yield SurfsharkdState.from_dict(msg["value"])

    def probe(self) -> tuple[bool, str]:
        if not self._sock_path.exists():
            return False, f"Socket {self._sock_path} does not exist"
        try:
            raw = self._call("getState", [], timeout=2.0)
            if isinstance(raw, dict):
                return True, f"surfsharkd.sock ({self._sock_path})"
            return False, "Unexpected getState response from surfsharkd.sock"
        except Exception as exc:
            return False, str(exc)

    def caps(self) -> DriverCaps:
        return DriverCaps(peer_replace=True, psk=True, adopt=True, dns_reapply=False)

    @staticmethod
    def _extract_endpoint_ipv4(endpoint_or_host: str) -> str:
        host = endpoint_or_host.rsplit(":", 1)[0] if ":" in endpoint_or_host else endpoint_or_host
        try:
            ipaddress.IPv4Address(host)
            return host
        except ValueError:
            pass
        ips = resolve_ipv4_all(host, timeout=4.0)
        if not ips:
            raise DriverError(
                ErrorCode.NETWORK_UNAVAILABLE,
                f"Unable to resolve IPv4 address for endpoint {host!r}",
            )
        return ips[0]

    def current(self) -> Observation:
        try:
            raw = self._call("getState", [], timeout=3.0)
            s_state = SurfsharkdState.from_dict(raw if isinstance(raw, dict) else {})
        except Exception as exc:
            log.debug("surfsharkd getState failed: %s", exc)
            return Observation(False, "none", None, None, None, "unavailable", None, str(exc))

        if not s_state.wg_exists and s_state.wg_active_connection_state == 0:
            return Observation(False, "none", None, None, None, "disconnected", None)

        spec = self._last_spec
        p0 = spec.peers[0] if (spec and spec.peers) else None
        nm_state = (
            "activated"
            if s_state.is_activated
            else ("activating" if s_state.is_activating else f"state-{s_state.wg_active_connection_state}")
        )
        return Observation(
            up=s_state.is_activated,
            owner="self" if spec is not None else "surfsharkd",
            iface="surfshark_wg" if s_state.wg_exists else None,
            peer_pubkey=p0.public_key if p0 else None,
            endpoint=p0.endpoint if p0 else None,
            nm_state=nm_state,
            since=self._since if s_state.is_activated else None,
            detail="surfsharkd.sock",
            cluster_id_hint=spec.cluster_id if spec else None,
        )

    def up(self, spec: TunnelSpec, cancel: threading.Event) -> Observation:
        if cancel.is_set():
            return self.current()
        if not spec.peers:
            raise DriverError(ErrorCode.VALIDATION, "TunnelSpec must contain at least one peer")

        p0 = spec.peers[0]
        domain_ipv4 = self._extract_endpoint_ipv4(p0.endpoint or p0.endpoint_host)
        anycast_pub = spec.peers[1].public_key if len(spec.peers) > 1 else DEFAULT_ANYCAST_PUB

        try:
            raw = self._call("getState", [], timeout=3.0)
            cur = SurfsharkdState.from_dict(raw if isinstance(raw, dict) else {})
            if cur.wg_exists:
                if self._last_spec is not None and cur.is_activated:
                    return self.replace_peer(spec, cancel)
                try:
                    self._call("removeConnection", ["wg"], timeout=5.0)
                except DriverError:
                    pass
        except DriverError:
            pass

        if spec.address6:
            try:
                self._call("addIPV6Connection", [], timeout=5.0)
            except DriverError as exc:
                log.debug("addIPV6Connection warning: %s", exc)

        mtu_safe = bool(spec.mtu and spec.mtu <= 1280)
        params = build_add_connection_params(
            domain_ipv4=domain_ipv4,
            pub_b64=p0.public_key,
            priv_b64=spec.private_key,
            cleanweb=spec.cleanweb,
            mtu_safe=mtu_safe,
            anycast_pub=anycast_pub,
            anycast_ip=DEFAULT_ANYCAST_IP,
            ifname="wg",
        )
        self._call("addConnection", params, timeout=15.0)
        self._call("connect", ["wg"], timeout=15.0)
        self._last_spec = spec
        self._since = time.time()

        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and not cancel.is_set():
            obs = self.current()
            if obs.up:
                self._emit(obs)
                return obs
            time.sleep(0.15)
        obs = self.current()
        self._emit(obs)
        return obs

    def replace_peer(self, spec: TunnelSpec, cancel: threading.Event, force_reset: bool = False) -> Observation:
        if cancel.is_set():
            return self.current()
        if not spec.peers:
            raise DriverError(ErrorCode.VALIDATION, "TunnelSpec must contain at least one peer")

        obs = self.current()
        can_replace = (
            not force_reset
            and obs.up
            and self._last_spec is not None
            and self._last_spec.cleanweb == spec.cleanweb
            and self._last_spec.mtu == spec.mtu
        )
        if not can_replace:
            self.down(cancel)
            return self.up(spec, cancel)

        p0 = spec.peers[0]
        domain_ipv4 = self._extract_endpoint_ipv4(p0.endpoint or p0.endpoint_host)
        params = build_replace_peer_params(
            domain_ipv4=domain_ipv4,
            pub_b64=p0.public_key,
            priv_b64=spec.private_key,
        )
        self._call("replacePeer", params, timeout=10.0)
        self._last_spec = spec
        obs = self.current()
        self._emit(obs)
        return obs

    def down(self, cancel: threading.Event, takeover_foreign: bool = False) -> Observation:
        for method, params in (
            ("disconnect", ["wg"]),
            ("removeConnection", ["wg"]),
            ("removeIPV6Connection", []),
        ):
            try:
                self._call(method, params, timeout=8.0)
            except DriverError as exc:
                log.debug("surfsharkd %s during down ignored: %s", method, exc)
        self._last_spec = None
        self._since = None
        obs = self.current()
        self._emit(obs)
        return obs

    def _emit(self, obs: Observation) -> None:
        if self._listener is not None:
            try:
                self._listener(obs)
            except Exception:
                pass

    def set_listener(self, cb: Callable[[Observation], None]) -> None:
        self._listener = cb

    def close(self) -> None:
        self._stream_stop.set()
        self._listener = None

