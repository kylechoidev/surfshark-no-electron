"""Dedicated GLib MainLoop thread for thread-safe libnm operations and logind resume signals."""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from typing import Any, Callable

try:
    import gi

    gi.require_version("NM", "1.0")
    from gi.repository import Gio, GLib, NM

    HAS_NM_GI = True
    NM_IMPORT_ERROR = ""
except Exception as _exc:
    HAS_NM_GI = False
    NM_IMPORT_ERROR = str(_exc)
    Gio = None  # type: ignore[assignment]
    GLib = None  # type: ignore[assignment]
    NM = None  # type: ignore[assignment]

log = logging.getLogger("surfshark_lite.tunnel.nmloop")


def _chain_future(src: concurrent.futures.Future[Any], dst: concurrent.futures.Future[Any]) -> None:
    if dst.done():
        return
    exc = src.exception()
    if exc is not None:
        dst.set_exception(exc)
    else:
        dst.set_result(src.result())


class NmLoop(threading.Thread):
    """Single thread running the global-default GLib MainContext and owning all NM.Client objects."""

    def __init__(self, on_resume: Callable[[], None] | None = None) -> None:
        super().__init__(daemon=True, name="nm-loop")
        self._on_resume = on_resume
        self.ready = threading.Event()
        self.init_error: BaseException | None = None
        self.loop: Any = None
        self.client: Any = None
        self._sys_bus: Any = None
        self._sleep_sub_id: int | None = None

    def run(self) -> None:
        if not HAS_NM_GI:
            self.init_error = RuntimeError(f"PyGObject / NM-1.0 unavailable: {NM_IMPORT_ERROR}")
            self.ready.set()
            return
        try:
            self.loop = GLib.MainLoop.new(None, False)
            self.client = NM.Client.new(None)
            self._subscribe_logind_resume()
        except BaseException as exc:
            self.init_error = exc
            self.ready.set()
            return

        self.ready.set()
        try:
            self.loop.run()
        except BaseException as exc:
            log.debug("GLib MainLoop exited: %s", exc)

    def _subscribe_logind_resume(self) -> None:
        if Gio is None or self._on_resume is None:
            return
        try:
            self._sys_bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            self._sleep_sub_id = self._sys_bus.signal_subscribe(
                "org.freedesktop.login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                "/org/freedesktop/login1",
                None,
                Gio.DBusSignalFlags.NONE,
                self._on_prepare_for_sleep,
                None,
            )
        except Exception as exc:
            log.debug("Could not subscribe to logind PrepareForSleep: %s", exc)

    def _on_prepare_for_sleep(
        self,
        _conn: Any,
        _sender: Any,
        _path: Any,
        _iface: Any,
        _sig: Any,
        params: Any,
        _user_data: Any,
    ) -> None:
        try:
            unpacked = params.unpack()
            if isinstance(unpacked, tuple) and len(unpacked) >= 1 and unpacked[0] is False:
                if self._on_resume:
                    self._on_resume()
        except Exception:
            pass

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> concurrent.futures.Future[Any]:
        fut: concurrent.futures.Future[Any] = concurrent.futures.Future()
        if not HAS_NM_GI or self.init_error is not None:
            fut.set_exception(self.init_error or RuntimeError("NM GLib loop unavailable"))
            return fut

        def _invoke() -> bool:
            try:
                res = fn(*args, **kwargs)
                if isinstance(res, concurrent.futures.Future):
                    res.add_done_callback(lambda src: _chain_future(src, fut))
                else:
                    fut.set_result(res)
            except BaseException as exc:
                if not fut.done():
                    fut.set_exception(exc)
            return False

        GLib.idle_add(_invoke)
        return fut

    def stop(self) -> None:
        if self.loop is not None and HAS_NM_GI:
            def _quit() -> bool:
                try:
                    if self._sys_bus is not None and self._sleep_sub_id is not None:
                        self._sys_bus.signal_unsubscribe(self._sleep_sub_id)
                        self._sleep_sub_id = None
                except Exception:
                    pass
                if self.loop.is_running():
                    self.loop.quit()
                return False

            GLib.idle_add(_quit)
