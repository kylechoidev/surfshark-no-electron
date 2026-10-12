"""Server-Sent Events (SSE) broadcaster and client stream queue."""

from __future__ import annotations

import json
import queue
from typing import Any


def format_sse_frame(event: str, data: dict[str, Any]) -> bytes:
    payload = json.dumps(data, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n".encode("utf-8")


class SseClientStream:
    """Bounded per-client queue for SSE frames with heartbeat support."""

    def __init__(self, maxsize: int = 64) -> None:
        self._q: queue.Queue[bytes | None] = queue.Queue(maxsize=maxsize)
        self._closed = False

    def push(self, event: str, data: dict[str, Any]) -> None:
        if self._closed:
            return
        frame = format_sse_frame(event, data)
        try:
            self._q.put_nowait(frame)
        except queue.Full:
            # Drop oldest frame so slow browser tab never blocks controller
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(frame)
            except queue.Full:
                pass

    def get(self, timeout: float = 15.0) -> bytes | None:
        if self._closed:
            return None
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return b": keepalive\n\n"

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._q.put_nowait(None)
            except queue.Full:
                pass
