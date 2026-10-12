"""Pure-stdlib systemd sd_notify datagram sender."""

from __future__ import annotations

import os
import socket


def notify(state: str) -> bool:
    """Send a notification datagram to $NOTIFY_SOCKET if set."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(state.encode("utf-8"))
        return True
    except OSError:
        return False


def ready(status: str = "Ready") -> bool:
    return notify(f"READY=1\nSTATUS={status}")


def status(msg: str) -> bool:
    return notify(f"STATUS={msg}")


def stopping(msg: str = "Stopping") -> bool:
    return notify(f"STOPPING=1\nSTATUS={msg}")


def watchdog() -> bool:
    return notify("WATCHDOG=1")
