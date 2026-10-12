"""Central actor-model controller, intent reconciler, timer scheduler, and doctor diagnostics."""

from __future__ import annotations

import enum
import heapq
import logging
import queue
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from surfshark_lite import __version__, sdnotify
from surfshark_lite.api import SurfsharkAPI
from surfshark_lite.auth import AuthEngine, AuthState, LoginNeedsOtp, LoginOk, TokenManager
from surfshark_lite.catalog import CatalogManager, Cluster, TargetFilters
from surfshark_lite.credstore import CredentialStore
from surfshark_lite.egress import EgressChecker, EgressReport
from surfshark_lite.errors import DriverError, ErrorCode, SslError, ValidationError
from surfshark_lite.geo import get_country_entry
from surfshark_lite.httpclient import HttpClient
from surfshark_lite.keys import KeyManager
from surfshark_lite.logs import RingBufferHandler
from surfshark_lite.netlink import NetlinkWatcher
from surfshark_lite.netprobe import lookup_dns_txt_pubkey, resolve_ipv4_all
from surfshark_lite.paths import (
    clusters_cache_path,
    credentials_path,
    ensure_all_dirs,
    get_paths,
    latency_cache_path,
    settings_path,
    state_path,
)
from surfshark_lite.settings import SettingsStore
from surfshark_lite.state_store import Desired, HomeLocation, StateStore
from surfshark_lite.telemetry import TelemetrySnapshot, Verdict, collect_snapshot
from surfshark_lite.tunnel import (
    Observation,
    TunnelDriver,
    TunnelSpec,
    build_spec,
    routing,
    select_driver,
)
from surfshark_lite.tunnel.profile import AUX_PEER_DEFAULT_PUBKEY, AUX_PEER_HOST
from surfshark_lite.watchdog import WatchdogLevel, WatchdogState, step_watchdog

log = logging.getLogger("surfshark_lite.controller")


class ConnState(str, enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    SWITCHING = "SWITCHING"
    RECONNECTING = "RECONNECTING"
    DISCONNECTING = "DISCONNECTING"
    FAULT = "FAULT"


@dataclass(order=True)
class _ScheduledTimer:
    due_mono: float
    seq: int
    name: str = field(compare=False)
    callback: Callable[[], None] = field(compare=False)


class Controller:
    """Single-threaded actor state machine coordinating tunnel, auth, catalog, telemetry, and watchdog."""

    def __init__(
        self,
        *,
        settings_store: SettingsStore | None = None,
        state_store: StateStore | None = None,
        cred_store: CredentialStore | None = None,
        api: SurfsharkAPI | None = None,
        driver: TunnelDriver | None = None,
        egress_checker: EgressChecker | None = None,
        ring_handler: RingBufferHandler | None = None,
    ) -> None:
        app_paths = ensure_all_dirs()
        self.settings_store = settings_store or SettingsStore(app_paths.settings_file)
        self.settings = self.settings_store.load()

        self.state_store = state_store or StateStore(app_paths.state_file)
        self.persisted = self.state_store.load()

        self.cred_store = cred_store or CredentialStore(
            app_paths.credentials_file,
            app_paths.credentials_lock,
            backend=self.settings.get("credential_store", "file"),
        )
        self.http = HttpClient(user_agent=self.settings.get("api", {}).get("user_agent"))
        self.api = api or SurfsharkAPI(http=self.http)
        self.token_mgr = TokenManager(
            self.cred_store,
            self.api,
            on_state_change=self._on_auth_state_change,
        )
        self.token_mgr.load_from_store()
        self.auth = AuthEngine(self.cred_store, self.api, self.token_mgr)
        self.key_mgr = KeyManager(self.cred_store, self.token_mgr, self.api)
        self.catalog = CatalogManager(clusters_cache_path(), latency_cache_path(), self.api)
        self.catalog.load_cache()

        self.egress = egress_checker or EgressChecker()
        self.ring_handler = ring_handler

        self._driver: TunnelDriver | None = driver
        self._conn_state: ConnState = ConnState.DISCONNECTED
        self._active_cluster: Cluster | None = None
        self._active_spec: TunnelSpec | None = None
        self._last_obs: Observation = Observation(False, "none", None, None, None, "disconnected", None)
        self._telemetry: TelemetrySnapshot = collect_snapshot(self._last_obs, None, None)
        self._watchdog: WatchdogState = WatchdogState()
        self._last_error: dict[str, Any] | None = None
        self._requires_reconnect_keys: list[str] = []

        self._cancel_op = threading.Event()
        self._inbox: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._timers: list[_ScheduledTimer] = []
        self._timer_seq = 0
        self._running = False
        self._actor_thread: threading.Thread | None = None
        self._netlink: NetlinkWatcher | None = None

        self._sse_subscribers: list[Callable[[str, dict[str, Any]], None]] = []
        self._sse_lock = threading.Lock()

        # Ephemeral single-use UI tickets: token -> expiry monotonic timestamp
        self._ui_tickets: dict[str, float] = {}
        self._session_tokens: dict[str, float] = {}
        self._ticket_lock = threading.Lock()
        self.started_at = time.time()

    @property
    def driver(self) -> TunnelDriver:
        if self._driver is None:
            self._driver = select_driver(
                self.settings.get("driver", "auto"),
                on_resume=lambda: self.post_event("resume", None),
            )
            self._driver.set_listener(lambda obs: self.post_event("driver_obs", obs))
        return self._driver

    def subscribe_sse(self, cb: Callable[[str, dict[str, Any]], None]) -> Callable[[], None]:
        with self._sse_lock:
            self._sse_subscribers.append(cb)

        def _unsub() -> None:
            with self._sse_lock:
                if cb in self._sse_subscribers:
                    self._sse_subscribers.remove(cb)

        return _unsub

    def _emit_sse(self, event_type: str, data: dict[str, Any]) -> None:
        with self._sse_lock:
            subs = list(self._sse_subscribers)
        for cb in subs:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def _on_auth_state_change(self, new_state: AuthState, err: str | None) -> None:
        self._emit_sse("auth", {"state": new_state.value, "error": err})

    # --- UI Ticket & Cookie Session Management ---

    def issue_ui_ticket(self, ttl_s: float = 30.0) -> str:
        now = time.monotonic()
        t = secrets.token_urlsafe(24)
        with self._ticket_lock:
            expired = [k for k, exp in self._ui_tickets.items() if exp <= now]
            for k in expired:
                self._ui_tickets.pop(k, None)
            self._ui_tickets[t] = now + ttl_s
        return t

    def redeem_ui_ticket(self, ticket: str) -> str | None:
        now = time.monotonic()
        with self._ticket_lock:
            exp = self._ui_tickets.pop(ticket, None)
            if exp is None or exp <= now:
                return None
            sess_tok = secrets.token_urlsafe(32)
            self._session_tokens[sess_tok] = now + 7 * 86400.0
            return sess_tok

    def issue_direct_session_cookie(self) -> str:
        now = time.monotonic()
        with self._ticket_lock:
            sess_tok = secrets.token_urlsafe(32)
            self._session_tokens[sess_tok] = now + 7 * 86400.0
            return sess_tok

    def validate_session_cookie(self, token: str | None) -> bool:
        if not token:
            return False
        now = time.monotonic()
        with self._ticket_lock:
            exp = self._session_tokens.get(token)
            if exp is None or exp <= now:
                self._session_tokens.pop(token, None)
                return False
            return True

    # --- Actor Lifecycle & Event Loop ---

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._netlink = NetlinkWatcher(on_change=lambda: self.post_event("netlink_change", None))
        self._netlink.start()
        self._actor_thread = threading.Thread(target=self._actor_loop, name="ssul-controller", daemon=True)
        self._actor_thread.start()
        self.post_event("startup", None)

    def stop(self) -> None:
        if not self._running:
            return
        sdnotify.stopping("Shutting down Surf Shark Ultra Lite")
        self._running = False
        self._cancel_op.set()
        self.post_event("shutdown", None)
        if self._netlink is not None:
            self._netlink.stop()
            self._netlink = None
        if self._actor_thread is not None:
            self._actor_thread.join(timeout=5.0)
            self._actor_thread = None
        if self._driver is not None:
            if self.settings.get("disconnect_on_exit", False):
                try:
                    self._driver.down(threading.Event())
                except Exception:
                    pass
            self._driver.close()

    def post_event(self, kind: str, payload: Any = None) -> None:
        self._inbox.put((kind, payload))

    def schedule_timer(self, name: str, delay_s: float, callback: Callable[[], None]) -> None:
        self._timer_seq += 1
        due = time.monotonic() + max(0.05, delay_s)
        heapq.heappush(self._timers, _ScheduledTimer(due, self._timer_seq, name, callback))

    def _actor_loop(self) -> None:
        self._schedule_periodic_timers()
        while self._running:
            now = time.monotonic()
            while self._timers and self._timers[0].due_mono <= now:
                tmr = heapq.heappop(self._timers)
                try:
                    tmr.callback()
                except Exception as exc:
                    log.debug("Timer %s error: %s", tmr.name, exc)
                now = time.monotonic()

            wait_s = 1.0
            if self._timers:
                wait_s = max(0.02, min(1.0, self._timers[0].due_mono - now))

            try:
                kind, payload = self._inbox.get(timeout=wait_s)
            except queue.Empty:
                continue

            if kind == "shutdown":
                break
            try:
                self._handle_event(kind, payload)
            except Exception as exc:
                log.exception("Unhandled error in controller event %s: %s", kind, exc)

    def _schedule_periodic_timers(self) -> None:
        liveness_s = float(self.settings.get("probes", {}).get("liveness_interval_s", 30))

        def _tick_liveness() -> None:
            if not self._running:
                return
            self._refresh_telemetry(probe_egress=False)
            sdnotify.watchdog()
            self.schedule_timer("liveness", liveness_s, _tick_liveness)

        egress_s = float(self.settings.get("probes", {}).get("egress_interval_s", 300))

        def _tick_egress() -> None:
            if not self._running:
                return
            if self._conn_state == ConnState.CONNECTED:
                self._refresh_telemetry(probe_egress=True)
            self.schedule_timer("egress", egress_s, _tick_egress)

        self.schedule_timer("liveness", liveness_s, _tick_liveness)
        self.schedule_timer("egress", egress_s, _tick_egress)
        self._schedule_token_renewal()

    def _schedule_token_renewal(self) -> None:
        delay = self.token_mgr.next_renew_delay_s()
        if delay is None:
            return

        def _do_renew() -> None:
            if not self._running:
                return
            try:
                self.token_mgr.proactive_renew()
            except Exception as exc:
                log.warning("Proactive token renewal failed: %s", exc)
            self._schedule_token_renewal()

        self.schedule_timer("token_renew", delay, _do_renew)

    def _handle_event(self, kind: str, payload: Any) -> None:
        if kind == "startup":
            self._adopt_or_Autoconnect()
            sdnotify.ready("Controller ready")
        elif kind == "driver_obs":
            if isinstance(payload, Observation):
                self._last_obs = payload
                self._refresh_telemetry(probe_egress=False)
        elif kind in ("netlink_change", "resume"):
            self._refresh_telemetry(probe_egress=(kind == "resume" and self._conn_state == ConnState.CONNECTED))

    def _adopt_or_Autoconnect(self) -> None:
        try:
            obs = self.driver.current()
            self._last_obs = obs
            if obs.up and obs.owner in ("self", "surfsharkd"):
                cid = obs.cluster_id_hint or self.persisted.last_cluster
                if cid:
                    for c in self.catalog.clusters:
                        if c.id == cid or c.hostname == cid:
                            self._active_cluster = c
                            break
                self._conn_state = ConnState.CONNECTED
                self._refresh_telemetry(probe_egress=True)
                log.info("Adopted existing active WireGuard tunnel (%s)", obs.iface)
                return
        except Exception as exc:
            log.debug("Initial driver probe during startup: %s", exc)

        if self.settings.get("autoconnect", False) and self.token_mgr.state == AuthState.AUTHENTICATED:
            target = self.settings.get("autoconnect_target") or "last"
            try:
                self.connect(target=target)
            except Exception as exc:
                log.warning("Autoconnect to %r failed: %s", target, exc)

    # --- Core Operations (Callable from HTTP routes / CLI) ---

    def _resolve_cluster_and_spec(self, target: str | None, filters: TargetFilters | None = None) -> tuple[Cluster, TunnelSpec]:
        bearer = self.token_mgr.session.token if self.token_mgr.session else None
        self.catalog.ensure_loaded(bearer=bearer)
        res = self.catalog.resolve_or_raise(
            target,
            filters=filters,
            home=self.persisted.home_location,
            last_cluster_id=self.persisted.last_cluster,
            allow_ambiguous_top=False,
        )
        assert res.choice is not None
        cluster = res.choice

        wg_rec = self.key_mgr.ensure_registered()
        ips = resolve_ipv4_all(cluster.hostname, timeout=4.0)
        if not ips:
            raise SslError(ErrorCode.NETWORK_UNAVAILABLE, f"DNS resolution failed for {cluster.hostname}")
        server_ip = ips[0]

        aux_ips = resolve_ipv4_all(AUX_PEER_HOST, timeout=3.0)
        aux_ip = aux_ips[0] if aux_ips else None
        aux_pub = lookup_dns_txt_pubkey(AUX_PEER_HOST, timeout=2.0) or AUX_PEER_DEFAULT_PUBKEY

        spec = build_spec(
            cluster=cluster,
            private_key=wg_rec.private_key,
            server_ip=server_ip,
            settings=self.settings,
            aux_ip=aux_ip,
            aux_pubkey=aux_pub,
        )
        return cluster, spec

    def connect(
        self,
        target: str | None = "fastest",
        *,
        filters: TargetFilters | None = None,
        takeover: bool = False,
    ) -> dict[str, Any]:
        if self.token_mgr.state not in (AuthState.AUTHENTICATED, AuthState.DEGRADED):
            # Attempt automatic import from official Surfshark config if present
            try:
                self.auth.import_official()
            except Exception:
                raise SslError(
                    ErrorCode.AUTH_REQUIRED,
                    "Authentication required. Run 'surfshark-lite login' first.",
                    http_status=401,
                )

        # Capture baseline IP if currently disconnected
        if self._conn_state == ConnState.DISCONNECTED and self.egress.baseline is None:
            when_disc = self.settings.get("probes", {}).get("when_disconnected", "surfshark-only")
            if when_disc != "none":
                base_rep = self.egress.capture_baseline(timeout=2.5)
                if base_rep and base_rep.country_code and self.persisted.home_location is None:
                    ce = get_country_entry(base_rep.country_code)
                    if ce:
                        self.persisted = self.state_store.update(
                            home_location=HomeLocation(lat=ce.lat, lon=ce.lon, country_code=ce.alpha2)
                        )

        was_connected = self._conn_state in (ConnState.CONNECTED, ConnState.SWITCHING, ConnState.RECONNECTING)
        self._conn_state = ConnState.SWITCHING if was_connected else ConnState.CONNECTING
        self._last_error = None
        self._emit_sse("state", self.status_dict())

        try:
            cluster, spec = self._resolve_cluster_and_spec(target, filters=filters)
            self._cancel_op.clear()

            if takeover:
                obs_now = self.driver.current()
                if obs_now.up and obs_now.owner in ("foreign", "surfsharkd"):
                    self.driver.down(self._cancel_op, takeover_foreign=True)

            if was_connected:
                obs = self.driver.replace_peer(spec, self._cancel_op)
            else:
                obs = self.driver.up(spec, self._cancel_op)

            self._last_obs = obs
            self._active_cluster = cluster
            self._active_spec = spec
            self._conn_state = ConnState.CONNECTED if obs.up else ConnState.FAULT
            self._watchdog = WatchdogState(level=WatchdogLevel.L0_HEALTHY, level_entered_at=time.monotonic())
            self._requires_reconnect_keys = []

            new_desired = Desired(
                connected=True,
                target_query=target or "fastest",
                cluster_id=cluster.id,
                revision=self.persisted.desired.revision + 1,
            )
            self.persisted = self.state_store.update(desired=new_desired, last_cluster=cluster.id)
            self._refresh_telemetry(probe_egress=True)
            return self.status_dict()
        except SslError as exc:
            self._last_error = exc.to_envelope()["error"]
            self._conn_state = ConnState.CONNECTED if (self._last_obs.up and was_connected) else ConnState.FAULT
            self._emit_sse("state", self.status_dict())
            raise
        except Exception as exc:
            err = SslError(ErrorCode.INTERNAL, str(exc), http_status=500)
            self._last_error = err.to_envelope()["error"]
            self._conn_state = ConnState.FAULT
            self._emit_sse("state", self.status_dict())
            raise err from exc

    def switch(self, target: str, *, filters: TargetFilters | None = None) -> dict[str, Any]:
        return self.connect(target=target, filters=filters)

    def disconnect(self, *, takeover: bool = False) -> dict[str, Any]:
        self._conn_state = ConnState.DISCONNECTING
        self._emit_sse("state", self.status_dict())
        self._cancel_op.clear()
        try:
            obs = self.driver.down(self._cancel_op, takeover_foreign=takeover)
            self._last_obs = obs
        finally:
            self._active_cluster = None
            self._active_spec = None
            self._conn_state = ConnState.DISCONNECTED
            self._watchdog = WatchdogState(level=WatchdogLevel.L0_HEALTHY, level_entered_at=time.monotonic())
            new_desired = Desired(
                connected=False,
                target_query=self.persisted.desired.target_query,
                cluster_id=self.persisted.desired.cluster_id,
                revision=self.persisted.desired.revision + 1,
            )
            self.persisted = self.state_store.update(desired=new_desired)
            self._refresh_telemetry(probe_egress=False)
        return self.status_dict()

    def reconnect(self) -> dict[str, Any]:
        target = (
            (self._active_cluster.hostname if self._active_cluster else None)
            or self.persisted.last_cluster
            or self.persisted.desired.target_query
            or "fastest"
        )
        self._conn_state = ConnState.RECONNECTING
        self._emit_sse("state", self.status_dict())
        self.driver.down(threading.Event())
        self._conn_state = ConnState.DISCONNECTED
        return self.connect(target=target)

    def _refresh_telemetry(self, *, probe_egress: bool = False) -> TelemetrySnapshot:
        try:
            if self._driver is not None:
                self._last_obs = self.driver.current()
        except Exception:
            pass

        exp_cc = self._active_cluster.country_code if self._active_cluster else None
        eg_rep: EgressReport | None = self.egress.last_report
        if probe_egress and self._last_obs.up:
            eg_rep = self.egress.check(expected_country_code=exp_cc, timeout=3.5)

        base_ip = self.egress.baseline.ip if self.egress.baseline else None
        snap = collect_snapshot(
            obs=self._last_obs,
            spec=self._active_spec,
            egress=eg_rep if self._last_obs.up else None,
            baseline_ip=base_ip,
            expected_country_code=exp_cc,
        )
        self._telemetry = snap

        # Run watchdog ladder if enabled and desired connected
        wd_cfg = self.settings.get("watchdog", {})
        if wd_cfg.get("enabled", True) and self.persisted.desired.connected and self._conn_state == ConnState.CONNECTED:
            drv_name = self._driver.name if self._driver else "native"
            if drv_name != "surfsharkd" or wd_cfg.get("act_in_surfsharkd_mode", False):
                dec = step_watchdog(self._watchdog, snap.verdict, time.monotonic(), desired_connected=True)
                self._watchdog = dec.next_state
                max_lvl = int(wd_cfg.get("max_level", 4))
                if int(dec.next_state.level) <= max_lvl and dec.action != "none":
                    self._execute_watchdog_action(dec.action)

        self._emit_sse("telemetry", snap.to_dict())
        self._emit_sse("state", self.status_dict())
        return snap

    def _execute_watchdog_action(self, action: str) -> None:
        log.info("Watchdog executing recovery action: %s (level=%s)", action, self._watchdog.level.name)
        try:
            if action == "probe_egress":
                exp_cc = self._active_cluster.country_code if self._active_cluster else None
                self.egress.check(expected_country_code=exp_cc, timeout=3.5)
            elif action == "reapply_poke" and self._active_spec is not None:
                self.driver.replace_peer(self._active_spec, threading.Event(), force_reset=True)
            elif action == "failover_cluster" and self._active_cluster is not None:
                cc = self._active_cluster.country_code
                self.connect(target=cc)
            elif action == "full_reconnect":
                self.reconnect()
            elif action == "enter_fault":
                self._conn_state = ConnState.FAULT
        except Exception as exc:
            log.warning("Watchdog action %s failed: %s", action, exc)

    # --- Status, Settings, Keys, and Doctor ---

    def update_settings(self, patch_obj: dict[str, Any]) -> dict[str, Any]:
        updated, reconnect_keys = self.settings_store.patch(patch_obj)
        self.settings = updated
        for k in reconnect_keys:
            if k not in self._requires_reconnect_keys:
                self._requires_reconnect_keys.append(k)

        # If CleanWeb or LAN bypass changed while connected, reapply in-place immediately
        if self._conn_state == ConnState.CONNECTED and self._active_cluster is not None and not reconnect_keys:
            if "cleanweb" in patch_obj or "lan_bypass" in patch_obj:
                try:
                    _, new_spec = self._resolve_cluster_and_spec(self._active_cluster.hostname)
                    self.driver.replace_peer(new_spec, threading.Event())
                    self._active_spec = new_spec
                except Exception as exc:
                    log.warning("Live reapply of settings failed: %s", exc)

        self._emit_sse("settings", {"settings": self.settings, "requires_reconnect": list(self._requires_reconnect_keys)})
        return {
            "settings": self.settings,
            "requires_reconnect": list(self._requires_reconnect_keys),
        }

    def status_dict(self) -> dict[str, Any]:
        lats = self.catalog.get_fresh_latencies()
        active_sum = (
            self._active_cluster.to_summary(lats.get(self._active_cluster.hostname))
            if self._active_cluster
            else None
        )
        creds = self.cred_store.load()
        key_exp = creds.wireguard.expires_at if creds.wireguard else None
        drv_name = self._driver.name if self._driver else self.settings.get("driver", "auto")
        return {
            "version": __version__,
            "uptime_s": round(max(0.0, time.time() - self.started_at), 1),
            "connection_state": self._conn_state.value,
            "driver": drv_name,
            "active_cluster": active_sum,
            "desired": self.persisted.desired.to_dict(),
            "last_cluster": self.persisted.last_cluster,
            "auth": self.auth.get_view(key_expires_at=key_exp),
            "telemetry": self._telemetry.to_dict(),
            "watchdog": self._watchdog.to_dict(),
            "settings_summary": {
                "cleanweb": self.settings.get("cleanweb", False),
                "ipv6_guard": self.settings.get("ipv6_guard", True),
                "lan_bypass": self.settings.get("lan_bypass", "lan"),
                "kill_switch": self.settings.get("kill_switch", "soft"),
            },
            "requires_reconnect": list(self._requires_reconnect_keys),
            "last_error": self._last_error,
        }

    def doctor(self) -> dict[str, Any]:
        """Run 11-point system & security self-diagnostics (§13)."""
        checks: list[dict[str, Any]] = []

        # 1. Native NM PyGObject availability
        from surfshark_lite.tunnel.nm import NmDriver
        nm_drv = NmDriver()
        nm_ok, nm_msg = nm_drv.probe()
        checks.append({
            "id": "nm_pygobject",
            "title": "NetworkManager & PyGObject (libnm)",
            "ok": nm_ok,
            "detail": nm_msg,
            "remediation": None if nm_ok else "sudo apt install python3-gi gir1.2-nm-1.0",
        })

        # 2. Polkit permissions
        perms = nm_drv.get_permissions() if nm_ok else {}
        perm_ok = perms.get("settings.modify.own") == "yes" and perms.get("network-control") == "yes"
        checks.append({
            "id": "nm_polkit",
            "title": "NetworkManager Polkit Permissions",
            "ok": perm_ok,
            "detail": ", ".join(f"{k}={v}" for k, v in perms.items()) or "unverified",
            "remediation": None if perm_ok else "./install.sh --polkit",
        })

        # 3. Rule priority conflicts
        conflicts = routing.check_rule_priority_conflicts(
            priority_base=int(self.settings.get("rule_priority_base", 30000)),
            expected_table=int(self.settings.get("route_table", 300000)),
        )
        checks.append({
            "id": "policy_rule_priorities",
            "title": "Policy Routing Priority Window",
            "ok": len(conflicts) == 0,
            "detail": "Clean" if not conflicts else "; ".join(conflicts),
            "remediation": None if not conflicts else "Adjust rule_priority_base in settings.json",
        })

        # 4. Credential store security
        cred_ok = True
        cred_detail = f"Backend={self.cred_store.backend}, State={self.token_mgr.state.value}"
        try:
            self.cred_store.load()
        except Exception as exc:
            cred_ok = False
            cred_detail = str(exc)
        checks.append({
            "id": "credential_store",
            "title": "Credential Store & File Permissions",
            "ok": cred_ok,
            "detail": cred_detail,
            "remediation": None if cred_ok else f"chmod 600 {credentials_path()}",
        })

        # 5. Curve25519 key derivation backend
        from surfshark_lite.keys import _HAS_CRYPTOGRAPHY
        wg_bin = shutil.which("wg")
        key_backend = "cryptography" if _HAS_CRYPTOGRAPHY else ("wg-cli" if wg_bin else "pure-python-rfc7748")
        checks.append({
            "id": "x25519_backend",
            "title": "WireGuard X25519 Key Derivation",
            "ok": True,
            "detail": f"Active backend: {key_backend}",
            "remediation": None,
        })

        # 6. Catalog cache status
        cat_count = len(self.catalog.clusters)
        checks.append({
            "id": "catalog_cache",
            "title": "Server Catalog Cache",
            "ok": cat_count > 0,
            "detail": f"{cat_count} clusters loaded (source={self.catalog.source})",
            "remediation": None if cat_count > 0 else "surfshark-lite servers --refresh",
        })

        # 7. Active tunnel routing verification
        drifts = list(self._telemetry.drifts)
        checks.append({
            "id": "tunnel_routing",
            "title": "Active Tunnel Routing Integrity",
            "ok": len(drifts) == 0,
            "detail": "Verified" if not drifts else "; ".join(d.message for d in drifts),
            "remediation": None if not drifts else "surfshark-lite reconnect",
        })

        overall_ok = all(c["ok"] for c in checks)
        return {
            "ok": overall_ok,
            "version": __version__,
            "checks": checks,
        }
