"""Minimal Linux rtnetlink multicast listener with 250ms debounce."""

from __future__ import annotations

import logging
import os
import select
import socket
import threading
import time
from typing import Callable

log = logging.getLogger("surfshark_lite.netlink")

# Linux rtnetlink multicast group bitmasks
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_IPV6_IFADDR = 0x100
RTMGRP_IPV6_ROUTE = 0x400

DEFAULT_GROUPS = (
    RTMGRP_LINK
    | RTMGRP_IPV4_IFADDR
    | RTMGRP_IPV4_ROUTE
    | RTMGRP_IPV6_IFADDR
    | RTMGRP_IPV6_ROUTE
)


class NetlinkWatcher:
    """Listens to kernel rtnetlink multicast events and invokes `on_change` after a debounce window."""

    def __init__(
        self,
        on_change: Callable[[], None],
        debounce_s: float = 0.25,
        groups: int = DEFAULT_GROUPS,
    ) -> None:
        self._on_change = on_change
        self._debounce_s = debounce_s
        self._groups = groups
        self._stop_r: int | None = None
        self._stop_w: int | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> bool:
        if self._running:
            return True
        if not hasattr(socket, "AF_NETLINK"):
            log.debug("AF_NETLINK not supported on this platform; NetlinkWatcher disabled")
            return False
        try:
            r_fd, w_fd = os.pipe()
            os.set_blocking(r_fd, False)
            os.set_blocking(w_fd, False)
            self._stop_r = r_fd
            self._stop_w = w_fd
        except OSError as exc:
            log.warning("Failed to create netlink wakeup pipe: %s", exc)
            return False

        self._running = True
        self._thread = threading.Thread(target=self._run, name="ssul-netlink", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._stop_w is not None:
            try:
                os.write(self._stop_w, b"x")
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        for fd in (self._stop_r, self._stop_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._stop_r = None
        self._stop_w = None

    def _run(self) -> None:
        nl_sock: socket.socket | None = None
        try:
            nl_sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
            nl_sock.setblocking(False)
            nl_sock.bind((0, self._groups))
        except OSError as exc:
            log.debug("Unable to bind AF_NETLINK socket: %s", exc)
            if nl_sock is not None:
                try:
                    nl_sock.close()
                except OSError:
                    pass
            return

        pending_deadline: float | None = None
        stop_fd = self._stop_r

        try:
            while self._running and stop_fd is not None:
                timeout: float | None = None
                if pending_deadline is not None:
                    rem = pending_deadline - time.monotonic()
                    if rem <= 0:
                        pending_deadline = None
                        self._fire()
                        continue
                    timeout = rem

                try:
                    readable, _, _ = select.select([nl_sock, stop_fd], [], [], timeout)
                except (OSError, ValueError):
                    break

                if not readable:
                    if pending_deadline is not None and time.monotonic() >= pending_deadline:
                        pending_deadline = None
                        self._fire()
                    continue

                if stop_fd in readable:
                    break

                if nl_sock in readable:
                    # Drain all queued netlink datagrams
                    while True:
                        try:
                            data = nl_sock.recv(16384)
                            if not data:
                                break
                        except BlockingIOError:
                            break
                        except OSError:
                            break
                    pending_deadline = time.monotonic() + self._debounce_s
        finally:
            try:
                nl_sock.close()
            except OSError:
                pass

    def _fire(self) -> None:
        try:
            self._on_change()
        except Exception as exc:
            log.debug("NetlinkWatcher callback error: %s", exc)
