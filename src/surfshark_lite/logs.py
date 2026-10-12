"""Logging setup, secret redacting filter, and ring buffer for UI/SSE."""

from __future__ import annotations

import collections
import datetime
import logging
import logging.handlers
import re
import sys
import threading
from pathlib import Path
from typing import Any, Callable

# 1. JWT tokens: eyJ...
_JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")

# 2. JSON or key=value pairs with sensitive keys
_KV_SECRET_RE = re.compile(
    r"""(?P<prefix>["']?(?:password|otp|token|renewToken|renew_token|private_key|preshared_key|pubKey|preshared|priv)["']?\s*[:=]\s*)(?P<val>"[^"]*"|'[^']*'|[^\s,}\]]+)""",
    re.IGNORECASE,
)

# 3. 44-char base64 strings ending with '=' (32-byte WireGuard keys)
_WG_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=_-])")

# 4. Email addresses -> u***@domain
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def mask_email(email: str | None) -> str | None:
    """Return masked email hint like 'u***@example.com'."""
    if not email or "@" not in email:
        return None
    local, _, domain = email.strip().partition("@")
    if not local or not domain:
        return None
    return f"{local[0]}***@{domain}"


def redact_text(text: str) -> str:
    """Apply all secret redaction patterns to a string."""
    if not text:
        return text
    out = _JWT_RE.sub("<jwt>", text)
    out = _KV_SECRET_RE.sub(r"\g<prefix><redacted>", out)
    out = _WG_KEY_RE.sub("<key>", out)
    out = _EMAIL_RE.sub(r"\1***@\2", out)
    return out


class RedactingFilter(logging.Filter):
    """Filter attached to every handler that scrubs secrets from log messages and args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        redacted = redact_text(msg)
        record.msg = redacted
        record.args = ()
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text)
        return True


class FlushingStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """StreamHandler that flushes after every emit (safe under python3 -E)."""

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


class RingBufferHandler(logging.Handler):
    """Thread-safe bounded ring buffer of formatted log records with sequence numbers."""

    def __init__(self, capacity: int = 1000) -> None:
        super().__init__()
        self.capacity = capacity
        self._lock = threading.Lock()
        self._seq = 0
        self._buf: collections.deque[dict[str, Any]] = collections.deque(maxlen=capacity)
        self._listeners: list[Callable[[dict[str, Any]], None]] = []

    def add_listener(self, cb: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._listeners.append(cb)

    def remove_listener(self, cb: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if cb in self._listeners:
                self._listeners.remove(cb)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Ensure RedactingFilter has run
            msg = redact_text(record.getMessage())
            if record.exc_info:
                formatter = self.formatter or logging.Formatter()
                exc_str = redact_text(formatter.formatException(record.exc_info))
                msg = f"{msg}\n{exc_str}"
            ts = datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            lvl = record.levelname.lower()
            if lvl == "warning":
                lvl = "warn"
            with self._lock:
                self._seq += 1
                item = {
                    "seq": self._seq,
                    "t": ts,
                    "level": lvl,
                    "logger": record.name,
                    "msg": msg,
                }
                self._buf.append(item)
                listeners = list(self._listeners)
            for cb in listeners:
                try:
                    cb(item)
                except Exception:
                    pass
        except Exception:
            self.handleError(record)

    def get_records(self, after: int = 0, limit: int = 200) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            items = [r for r in self._buf if r["seq"] > after]
            if limit > 0 and len(items) > limit:
                items = items[-limit:]
            return items, self._seq

    def tail(self, limit: int = 200) -> list[dict[str, Any]]:
        items, _ = self.get_records(after=0, limit=limit)
        return items



def setup_logging(
    log_file: Path | None = None,
    level: int = logging.INFO,
    enable_stderr: bool = True,
) -> RingBufferHandler:
    """Configure root logger for Surf Shark Ultra Lite with RedactingFilter on all handlers."""
    root = logging.getLogger("surfshark_lite")
    root.setLevel(level)
    root.propagate = False

    # Clear existing handlers if re-initialized
    for h in list(root.handlers):
        root.removeHandler(h)

    redactor = RedactingFilter()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    ring = RingBufferHandler(capacity=1000)
    ring.addFilter(redactor)
    ring.setFormatter(fmt)
    root.addHandler(ring)

    if enable_stderr:
        sh = FlushingStreamHandler(sys.stderr)
        sh.addFilter(redactor)
        sh.setFormatter(fmt)
        root.addHandler(sh)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        try:
            import os
            os.chmod(str(log_file), 0o600)
        except OSError:
            pass
        fh.addFilter(redactor)
        fh.setFormatter(fmt)
        root.addHandler(fh)

    return ring
