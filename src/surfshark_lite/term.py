"""ANSI terminal styling, tables, duration formatting, and TTY/NO_COLOR support."""

from __future__ import annotations

import os
import sys
from typing import Sequence


def use_color(stream: object = None) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", None)
    return bool(isatty and isatty())


class Style:
    def __init__(self, enabled: bool | None = None) -> None:
        self.enabled = use_color() if enabled is None else enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


def format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "0s"
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    mins, secs = divmod(total, 60)
    if mins < 60:
        return f"{mins}m {secs:02d}s"
    hours, mins = divmod(mins, 60)
    if hours < 24:
        return f"{hours}h {mins:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def format_table(headers: Sequence[str], rows: Sequence[Sequence[str]], style: Style | None = None) -> str:
    st = style or Style(enabled=False)
    if not rows:
        return ""
    widths = [len(h) for h in headers]
    for r in rows:
        for idx, cell in enumerate(r):
            if idx < len(widths):
                widths[idx] = max(widths[idx], len(str(cell)))

    hdr_line = "  ".join(st.bold(h.ljust(widths[i])) for i, h in enumerate(headers))
    sep_line = "  ".join(st.dim("─" * widths[i]) for i in range(len(headers)))
    lines = [hdr_line, sep_line]
    for r in rows:
        lines.append("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(r)))
    return "\n".join(lines)
