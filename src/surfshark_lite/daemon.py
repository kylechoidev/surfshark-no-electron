"""Daemon runner with single-instance flock, signal handling, and DualHttpServer lifecycle."""

from __future__ import annotations

import fcntl
import logging
import os
import signal
import threading
from pathlib import Path

from surfshark_lite.controller import Controller
from surfshark_lite.logs import setup_logging
from surfshark_lite.paths import ensure_all_dirs
from surfshark_lite.web.server import DualHttpServer

log = logging.getLogger("surfshark_lite.daemon")


class DaemonAlreadyRunningError(RuntimeError):
    pass


def acquire_daemon_lock(lock_path: Path) -> int:
    """Acquire an exclusive non-blocking flock on `lock_path` and return the open fd."""
    lock_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise DaemonAlreadyRunningError(f"Daemon is already running (lock held on {lock_path})") from exc
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    os.fsync(fd)
    return fd


def run_daemon(
    *,
    port_override: int | None = None,
    no_web: bool = False,
    log_level: int = logging.INFO,
) -> int:
    """Start the single-instance Surf Shark Ultra Lite daemon and block until SIGTERM/SIGINT."""
    paths = ensure_all_dirs()
    try:
        lock_fd = acquire_daemon_lock(paths.daemon_lock)
    except DaemonAlreadyRunningError as exc:
        log.info("%s", exc)
        return 0

    ring = setup_logging(log_file=paths.log_file, level=log_level, enable_stderr=True)
    controller = Controller(ring_handler=ring)

    web_cfg = controller.settings.get("web", {})
    tcp_enabled = False if no_web else bool(web_cfg.get("enabled", True))
    tcp_port = port_override if port_override is not None else int(web_cfg.get("port", 8777))

    server = DualHttpServer(
        controller,
        unix_sock_path=paths.control_sock,
        tcp_enabled=tcp_enabled,
        tcp_port=tcp_port,
    )

    stop_event = threading.Event()

    def _on_sig(signum: int, _frame: object) -> None:
        log.info("Received signal %d; initiating shutdown", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_sig)
    signal.signal(signal.SIGINT, _on_sig)

    try:
        controller.start()
        server.start()
        log.info(
            "Surf Shark Ultra Lite daemon running (unix=%s, web=%s)",
            paths.control_sock,
            f"http://127.0.0.1:{server.tcp_port}" if tcp_enabled else "disabled",
        )
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    finally:
        server.stop()
        controller.stop()
        try:
            os.close(lock_fd)
        except OSError:
            pass
    return 0
