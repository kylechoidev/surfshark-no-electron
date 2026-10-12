"""Native NetworkManager WireGuard driver using libnm via PyGObject."""

from __future__ import annotations

import concurrent.futures
import getpass
import logging
import os
import socket
import threading
import time
import uuid
from typing import Any, Callable

try:
    import gi

    gi.require_version("NM", "1.0")
    from gi.repository import GLib, NM

    HAS_NM = True
except Exception:
    HAS_NM = False
    GLib = None  # type: ignore[assignment]
    NM = None  # type: ignore[assignment]

from surfshark_lite import __version__
from surfshark_lite.errors import DriverError, ErrorCode
from surfshark_lite.tunnel import routing
from surfshark_lite.tunnel.base import DriverCaps, Observation, PeerSpec, TunnelSpec
from surfshark_lite.tunnel.nmloop import HAS_NM_GI, NM_IMPORT_ERROR, NmLoop

log = logging.getLogger("surfshark_lite.tunnel.nm")

OWNER_KEY = "surfshark-ultralite.owner"
VERSION_KEY = "surfshark-ultralite.version"
CLUSTER_KEY = "surfshark-ultralite.created-cluster"
PROFILE_NAME = "Surf Shark Ultra Lite"


def _glib_to_driver_error(exc: BaseException, default_code: ErrorCode = ErrorCode.DRIVER_UNAVAILABLE) -> DriverError:
    msg = str(exc)
    low = msg.lower()
    if "not authorized" in low or "permission" in low or "insufficient privileges" in low:
        return DriverError(
            ErrorCode.PERMISSION_DENIED,
            f"NetworkManager permission denied: {msg}. Run 'surfshark-lite doctor' or './install.sh --polkit'.",
            http_status=403,
        )
    return DriverError(default_code, f"NetworkManager error: {msg}")


def _build_wg_peer(p: PeerSpec, keepalive_override: int | None = None) -> Any:
    peer = NM.WireGuardPeer.new()
    if not peer.set_public_key(p.public_key, False):
        raise DriverError(ErrorCode.VALIDATION, "Invalid WireGuard peer public key")
    if not peer.set_endpoint(p.endpoint, False):
        raise DriverError(ErrorCode.VALIDATION, f"Invalid WireGuard peer endpoint {p.endpoint}")
    for cidr in p.allowed_ips:
        if not peer.append_allowed_ip(cidr, False):
            raise DriverError(ErrorCode.VALIDATION, f"Invalid WireGuard allowed-ip {cidr}")
    ka = keepalive_override if keepalive_override is not None else p.keepalive
    peer.set_persistent_keepalive(ka)
    if p.preshared_key:
        peer.set_preshared_key(p.preshared_key, False)
        peer.set_preshared_key_flags(NM.SettingSecretFlags.NONE)
    peer.seal()
    return peer


def _build_nm_connection(spec: TunnelSpec, username: str, scope: str) -> Any:
    con = NM.SimpleConnection.new()

    s_con = NM.SettingConnection.new()
    s_con.set_property(NM.SETTING_CONNECTION_ID, PROFILE_NAME)
    s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
    s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_WIREGUARD_SETTING_NAME)
    s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, spec.iface)
    s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, False)
    if scope == "private" and username:
        s_con.add_permission("user", username, None)
    con.add_setting(s_con)

    s_user = NM.SettingUser.new()
    s_user.set_data(OWNER_KEY, "1")
    s_user.set_data(VERSION_KEY, __version__)
    s_user.set_data(CLUSTER_KEY, spec.cluster_id)
    con.add_setting(s_user)

    s_wg = NM.SettingWireGuard.new()
    s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY, spec.private_key)
    s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY_FLAGS, NM.SettingSecretFlags.NONE)
    s_wg.set_property(NM.SETTING_WIREGUARD_FWMARK, spec.fwmark)
    s_wg.set_property(NM.SETTING_WIREGUARD_PEER_ROUTES, True)
    if spec.mtu:
        s_wg.set_property(NM.SETTING_WIREGUARD_MTU, int(spec.mtu))
    for p in spec.peers:
        s_wg.append_peer(_build_wg_peer(p))
    con.add_setting(s_wg)

    s4 = NM.SettingIP4Config.new()
    s4.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP4_CONFIG_METHOD_MANUAL)
    addr4, plen4 = spec.address4.split("/", 1)
    s4.add_address(NM.IPAddress.new(socket.AF_INET, addr4, int(plen4)))
    for d in spec.dns4:
        s4.add_dns(d)
    s4.add_dns_search("~.")
    s4.set_property(NM.SETTING_IP_CONFIG_DNS_PRIORITY, -2018)
    s4.set_property(NM.SETTING_IP_CONFIG_IGNORE_AUTO_DNS, True)
    for r4 in routing.nm_rules(spec, socket.AF_INET, NM):
        s4.add_routing_rule(r4)
    con.add_setting(s4)

    s6 = NM.SettingIP6Config.new()
    if spec.address6:
        s6.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_MANUAL)
        addr6, plen6 = spec.address6.split("/", 1)
        s6.add_address(NM.IPAddress.new(socket.AF_INET6, addr6, int(plen6)))
        s6.set_property(NM.SETTING_IP_CONFIG_DNS_PRIORITY, -2018)
        for r6 in routing.nm_rules(spec, socket.AF_INET6, NM):
            s6.add_routing_rule(r6)
    else:
        s6.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_DISABLED)
    con.add_setting(s6)

    con.verify()
    return con


def _is_our_connection(con: Any) -> bool:
    if con is None:
        return False
    try:
        s_user = con.get_setting_by_name(NM.SETTING_USER_SETTING_NAME)
        if s_user is not None and s_user.get_data(OWNER_KEY) == "1":
            return True
        if con.get_id() == PROFILE_NAME or con.get_interface_name() == "surfshark_lite":
            return True
    except Exception:
        pass
    return False


class NmDriver:
    """Native NetworkManager WireGuard driver."""

    name = "native"

    def __init__(self, on_resume: Callable[[], None] | None = None) -> None:
        self._on_resume = on_resume
        self._loop: NmLoop | None = None
        self._listener: Callable[[Observation], None] | None = None
        self._keepalive_toggle: bool = False
        self._username: str = self._resolve_username()

    @staticmethod
    def _resolve_username() -> str:
        try:
            return getpass.getuser()
        except Exception:
            return os.environ.get("USER") or ""

    def _ensure_loop(self) -> NmLoop:
        if self._loop is not None:
            return self._loop
        if not HAS_NM_GI:
            raise DriverError(
                ErrorCode.DRIVER_UNAVAILABLE,
                f"PyGObject / NetworkManager typelib unavailable ({NM_IMPORT_ERROR}). "
                "Install with: sudo apt install python3-gi gir1.2-nm-1.0",
            )
        loop = NmLoop(on_resume=self._on_resume)
        loop.start()
        loop.ready.wait(timeout=5.0)
        if loop.init_error is not None:
            raise _glib_to_driver_error(loop.init_error)
        self._loop = loop
        self._loop.call(self._attach_nm_signals)
        return self._loop

    def _attach_nm_signals(self) -> None:
        cl = self._loop.client if self._loop else None
        if cl is None:
            return
        cl.connect("active-connection-added", lambda *_a: self._emit_observation_on_loop())
        cl.connect("active-connection-removed", lambda *_a: self._emit_observation_on_loop())
        cl.connect("notify::state", lambda *_a: self._emit_observation_on_loop())

    def _emit_observation_on_loop(self) -> None:
        if self._listener is None:
            return
        try:
            obs = self._current_on_loop()
            self._listener(obs)
        except Exception:
            pass

    def probe(self) -> tuple[bool, str]:
        if not HAS_NM_GI:
            return False, f"Missing python3-gi / gir1.2-nm-1.0 ({NM_IMPORT_ERROR})"
        try:
            loop = self._ensure_loop()
            ver = loop.call(lambda: str(loop.client.get_version() or "unknown")).result(timeout=3.0)
            running = loop.call(lambda: bool(loop.client.get_nm_running())).result(timeout=3.0)
            if not running:
                return False, "NetworkManager daemon is not running"
            return True, f"NetworkManager {ver}"
        except Exception as exc:
            return False, str(exc)

    def caps(self) -> DriverCaps:
        return DriverCaps(peer_replace=True, psk=True, adopt=True, dns_reapply=True)

    def get_permissions_on_loop(self) -> dict[str, str]:
        cl = self._loop.client if self._loop else None
        if cl is None:
            return {}
        out: dict[str, str] = {}
        for name, perm_enum in (
            ("settings.modify.own", NM.ClientPermission.SETTINGS_MODIFY_OWN),
            ("settings.modify.system", NM.ClientPermission.SETTINGS_MODIFY_SYSTEM),
            ("network-control", NM.ClientPermission.NETWORK_CONTROL),
        ):
            try:
                res = cl.get_permission_result(perm_enum)
                out[name] = res.value_nick if hasattr(res, "value_nick") else str(int(res))
            except Exception as exc:
                out[name] = f"error ({exc})"
        return out

    def get_permissions(self) -> dict[str, str]:
        try:
            loop = self._ensure_loop()
            return loop.call(self.get_permissions_on_loop).result(timeout=3.0)
        except Exception:
            return {}

    def get_nm_connectivity(self) -> str:
        try:
            loop = self._ensure_loop()
            val = loop.call(lambda: loop.client.get_connectivity()).result(timeout=2.0)
            return val.value_nick if hasattr(val, "value_nick") else str(int(val))
        except Exception:
            return "unknown"

    def _current_on_loop(self) -> Observation:
        cl = self._loop.client if self._loop else None
        if cl is None:
            return Observation(False, "none", None, None, None, None, None, "NM client not initialized")

        active_conns = cl.get_active_connections() or []
        our_ac = None
        foreign_ac = None

        for ac in active_conns:
            con = ac.get_connection()
            ctype = ac.get_connection_type()
            if _is_our_connection(con) or ac.get_id() == PROFILE_NAME:
                our_ac = ac
                break
            if ctype in ("wireguard", "vpn"):
                foreign_ac = ac

        if our_ac is not None:
            st = our_ac.get_state()
            st_nick = st.value_nick if hasattr(st, "value_nick") else str(int(st))
            is_up = st == NM.ActiveConnectionState.ACTIVATED
            con = our_ac.get_connection()
            iface = None
            devs = our_ac.get_devices() or []
            if devs:
                iface = devs[0].get_iface()
            if not iface and con is not None:
                iface = con.get_interface_name()

            peer_pub = None
            endpoint = None
            cluster_hint = None
            since = None

            if con is not None:
                s_user = con.get_setting_by_name(NM.SETTING_USER_SETTING_NAME)
                if s_user is not None:
                    cluster_hint = s_user.get_data(CLUSTER_KEY)
                s_con = con.get_setting_connection()
                if s_con is not None:
                    ts = s_con.get_timestamp()
                    if ts and ts > 0:
                        since = float(ts)
                s_wg = con.get_setting_by_name(NM.SETTING_WIREGUARD_SETTING_NAME)
                if s_wg is not None and s_wg.get_peers_len() > 0:
                    p0 = s_wg.get_peer(0)
                    peer_pub = p0.get_public_key()
                    endpoint = p0.get_endpoint()

            return Observation(
                up=is_up,
                owner="self",
                iface=iface,
                peer_pubkey=peer_pub,
                endpoint=endpoint,
                nm_state=st_nick,
                since=since,
                detail=f"ActiveConnection={our_ac.get_id()}",
                cluster_id_hint=cluster_hint,
            )

        if foreign_ac is not None:
            f_id = foreign_ac.get_id() or "foreign-vpn"
            devs = foreign_ac.get_devices() or []
            f_iface = devs[0].get_iface() if devs else None
            owner_kind: Any = "surfsharkd" if (f_iface == "surfshark_wg" or f_id == "surfshark_wg") else "foreign"
            return Observation(
                up=True,
                owner=owner_kind,
                iface=f_iface,
                peer_pubkey=None,
                endpoint=None,
                nm_state="activated",
                since=None,
                detail=f"Foreign VPN active: {f_id}",
            )

        return Observation(
            up=False,
            owner="none",
            iface=None,
            peer_pubkey=None,
            endpoint=None,
            nm_state="disconnected",
            since=None,
        )

    def current(self) -> Observation:
        loop = self._ensure_loop()
        return loop.call(self._current_on_loop).result(timeout=5.0)

    def _cleanup_stale_profiles_on_loop(self) -> None:
        cl = self._loop.client if self._loop else None
        if cl is None:
            return
        active_uuids = {ac.get_uuid() for ac in (cl.get_active_connections() or [])}
        for con in (cl.get_connections() or []):
            if _is_our_connection(con) and con.get_uuid() not in active_uuids:
                try:
                    con.delete_async(None, lambda c, r, _d: None, None)
                except Exception:
                    pass

    def _activate_on_loop(self, spec: TunnelSpec, scope: str) -> concurrent.futures.Future[Observation]:
        fut: concurrent.futures.Future[Observation] = concurrent.futures.Future()
        cl = self._loop.client if self._loop else None
        if cl is None:
            fut.set_exception(DriverError(ErrorCode.DRIVER_UNAVAILABLE, "NM client not available"))
            return fut

        self._cleanup_stale_profiles_on_loop()
        con = _build_nm_connection(spec, self._username, scope)

        def _wait_activated(ac: Any) -> None:
            state_now = ac.get_state()
            if state_now == NM.ActiveConnectionState.ACTIVATED:
                fut.set_result(self._current_on_loop())
                return
            if state_now == NM.ActiveConnectionState.DEACTIVATED:
                fut.set_exception(
                    DriverError(ErrorCode.DRIVER_UNAVAILABLE, "WireGuard connection deactivated immediately")
                )
                return

            sig_holder: list[int] = []
            timer_holder: list[int] = []

            def _cleanup() -> None:
                if sig_holder:
                    try:
                        ac.disconnect(sig_holder.pop())
                    except Exception:
                        pass
                if timer_holder:
                    try:
                        GLib.source_remove(timer_holder.pop())
                    except Exception:
                        pass

            def _on_state(ac_obj: Any, new_state: int, reason: int, *_rest: Any) -> None:
                if fut.done():
                    _cleanup()
                    return
                if new_state == int(NM.ActiveConnectionState.ACTIVATED):
                    _cleanup()
                    fut.set_result(self._current_on_loop())
                elif new_state in (
                    int(NM.ActiveConnectionState.DEACTIVATED),
                    int(NM.ActiveConnectionState.DEACTIVATING),
                ):
                    _cleanup()
                    fut.set_exception(
                        DriverError(
                            ErrorCode.DRIVER_UNAVAILABLE,
                            f"WireGuard activation failed (NM reason={reason})",
                        )
                    )

            def _on_timeout() -> bool:
                timer_holder.clear()
                if not fut.done():
                    _cleanup()
                    fut.set_exception(DriverError(ErrorCode.DRIVER_UNAVAILABLE, "Timed out waiting for NM activation"))
                return False

            sig_holder.append(ac.connect("state-changed", _on_state))
            timer_holder.append(GLib.timeout_add_seconds(20, _on_timeout))

        def _activated_cb(client_obj: Any, act_res: Any, remote_con: Any) -> None:
            try:
                ac = client_obj.activate_connection_finish(act_res)
            except BaseException as exc:
                try:
                    remote_con.delete_async(None, lambda c, r, _d: None, None)
                except Exception:
                    pass
                fut.set_exception(_glib_to_driver_error(exc))
                return
            ac.connect("notify::state", lambda *_a: self._emit_observation_on_loop())
            _wait_activated(ac)

        def _added_cb(client_obj: Any, result: Any, _data: Any) -> None:
            try:
                remote_con = client_obj.add_connection_finish(result)
            except BaseException as exc:
                fut.set_exception(_glib_to_driver_error(exc))
                return
            client_obj.activate_connection_async(remote_con, None, None, None, _activated_cb, remote_con)

        cl.add_connection_async(con, False, None, _added_cb, None)
        return fut

    def up(self, spec: TunnelSpec, cancel: threading.Event) -> Observation:
        obs = self.current()
        if obs.up and obs.owner in ("foreign", "surfsharkd"):
            raise DriverError(
                ErrorCode.FOREIGN_TUNNEL_ACTIVE,
                f"Another VPN connection is active ({obs.detail}). Pass --takeover to replace it.",
                http_status=409,
            )
        if obs.up and obs.owner == "self":
            return self.replace_peer(spec, cancel)

        if cancel.is_set():
            return obs

        loop = self._ensure_loop()
        try:
            return loop.call(self._activate_on_loop, spec, spec.profile_scope).result(timeout=25.0)
        except DriverError as err:
            if spec.profile_scope == "private" and err.code == ErrorCode.PERMISSION_DENIED:
                log.info("Private profile scope rejected; falling back to system profile scope")
                return loop.call(self._activate_on_loop, spec, "system").result(timeout=25.0)
            raise

    def _reapply_on_loop(self, spec: TunnelSpec, force_reset: bool) -> concurrent.futures.Future[Observation]:
        fut: concurrent.futures.Future[Observation] = concurrent.futures.Future()
        cl = self._loop.client if self._loop else None
        if cl is None:
            fut.set_exception(DriverError(ErrorCode.DRIVER_UNAVAILABLE, "NM client not available"))
            return fut

        dev = cl.get_device_by_iface(spec.iface)
        if dev is None:
            fut.set_exception(DriverError(ErrorCode.DRIVER_UNAVAILABLE, f"WireGuard device {spec.iface} not found"))
            return fut

        ka_override: int | None = None
        if force_reset:
            self._keepalive_toggle = not self._keepalive_toggle
            ka_override = 24 if self._keepalive_toggle else 25

        def _got_applied(d_obj: Any, result: Any, _data: Any) -> None:
            try:
                applied, version_id = d_obj.get_applied_connection_finish(result)
            except BaseException as exc:
                fut.set_exception(_glib_to_driver_error(exc))
                return

            try:
                new_con = NM.SimpleConnection.new_clone(applied)
                s_wg = new_con.get_setting_by_name(NM.SETTING_WIREGUARD_SETTING_NAME)
                if s_wg is None:
                    raise DriverError(ErrorCode.INTERNAL, "Applied connection lacks wireguard setting")
                # D-Bus never returns secrets; always re-insert private key before Reapply
                s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY, spec.private_key)
                s_wg.set_property(NM.SETTING_WIREGUARD_PRIVATE_KEY_FLAGS, NM.SettingSecretFlags.NONE)
                s_wg.clear_peers()
                for idx, p in enumerate(spec.peers):
                    ka = ka_override if (idx == 0 and ka_override is not None) else None
                    s_wg.append_peer(_build_wg_peer(p, keepalive_override=ka))

                s4 = new_con.get_setting_ip4_config()
                if s4 is not None:
                    s4.clear_dns()
                    for dns_ip in spec.dns4:
                        s4.add_dns(dns_ip)
                    s4.clear_routing_rules()
                    for r4 in routing.nm_rules(spec, socket.AF_INET, NM):
                        s4.add_routing_rule(r4)

                s6 = new_con.get_setting_ip6_config()
                if s6 is not None and spec.address6:
                    s6.clear_routing_rules()
                    for r6 in routing.nm_rules(spec, socket.AF_INET6, NM):
                        s6.add_routing_rule(r6)
            except BaseException as exc:
                fut.set_exception(_glib_to_driver_error(exc))
                return

            def _reapplied(d2: Any, res2: Any, _d2: Any) -> None:
                try:
                    d2.reapply_finish(res2)
                    # Also update created-cluster hint on active connection's settings profile if accessible
                    for ac in (cl.get_active_connections() or []):
                        con_prof = ac.get_connection()
                        if _is_our_connection(con_prof):
                            su = con_prof.get_setting_by_name(NM.SETTING_USER_SETTING_NAME)
                            if su is not None:
                                su.set_data(CLUSTER_KEY, spec.cluster_id)
                    fut.set_result(self._current_on_loop())
                except BaseException as exc:
                    fut.set_exception(_glib_to_driver_error(exc))

            d_obj.reapply_async(new_con, version_id, 0, None, _reapplied, None)

        dev.get_applied_connection_async(0, None, _got_applied, None)
        return fut

    def replace_peer(self, spec: TunnelSpec, cancel: threading.Event, force_reset: bool = False) -> Observation:
        if cancel.is_set():
            return self.current()
        loop = self._ensure_loop()
        try:
            obs = loop.call(self._reapply_on_loop, spec, force_reset).result(timeout=15.0)
            self._emit_observation_on_loop()
            return obs
        except Exception as exc:
            log.warning("fail-open gap during fallback switch (Reapply rejected: %s)", exc)
            self.down(cancel)
            return self.up(spec, cancel)

    def _down_on_loop(self, takeover_foreign: bool) -> concurrent.futures.Future[Observation]:
        fut: concurrent.futures.Future[Observation] = concurrent.futures.Future()
        cl = self._loop.client if self._loop else None
        if cl is None:
            fut.set_result(Observation(False, "none", None, None, None, "disconnected", None))
            return fut

        targets: list[Any] = []
        for ac in (cl.get_active_connections() or []):
            con = ac.get_connection()
            if _is_our_connection(con) or ac.get_id() == PROFILE_NAME:
                targets.append(ac)
            elif takeover_foreign and ac.get_connection_type() in ("wireguard", "vpn"):
                targets.append(ac)

        if not targets:
            self._cleanup_stale_profiles_on_loop()
            fut.set_result(self._current_on_loop())
            return fut

        ac = targets[0]

        def _deactivated_cb(client_obj: Any, result: Any, _data: Any) -> None:
            try:
                client_obj.deactivate_connection_finish(result)
            except BaseException as exc:
                fut.set_exception(_glib_to_driver_error(exc))
                return

            deadline = time.monotonic() + 10.0

            def _poll_gone() -> bool:
                cur = self._current_on_loop()
                if not cur.up or time.monotonic() >= deadline:
                    self._cleanup_stale_profiles_on_loop()
                    if not fut.done():
                        fut.set_result(self._current_on_loop())
                    return False
                return True

            GLib.timeout_add(150, _poll_gone)

        cl.deactivate_connection_async(ac, None, _deactivated_cb, None)
        return fut

    def down(self, cancel: threading.Event, takeover_foreign: bool = False) -> Observation:
        loop = self._ensure_loop()
        obs = loop.call(self._down_on_loop, takeover_foreign).result(timeout=15.0)
        self._emit_observation_on_loop()
        return obs

    def set_listener(self, cb: Callable[[Observation], None]) -> None:
        self._listener = cb

    def close(self) -> None:
        if self._loop is not None:
            self._loop.stop()
            self._loop = None
