"""Desktop browser app-window launcher with single-use auth ticket exchange."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable

from surfshark_lite.ipc import IpcClient
from surfshark_lite.paths import get_paths

CHROMIUM_CANDIDATES: tuple[str, ...] = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
    "microsoft-edge",
    "vivaldi",
)


def build_auth_url(port: int, ticket: str) -> str:
    return f"http://127.0.0.1:{port}/auth?t={ticket}"


def find_app_browser(which_fn: Callable[[str], str | None] = shutil.which) -> str | None:
    env_browser = os.environ.get("SSUL_BROWSER")
    if env_browser:
        found = which_fn(env_browser)
        if found:
            return found
    for name in CHROMIUM_CANDIDATES:
        found = which_fn(name)
        if found:
            return found
    return None


def launch_ui(
    ipc: IpcClient | None = None,
    *,
    no_open: bool = False,
    which_fn: Callable[[str], str | None] = shutil.which,
) -> dict[str, str]:
    """Ensure daemon is running, mint a single-use UI ticket, and open the app window."""
    client = ipc or IpcClient()
    client.ensure_daemon(autostart=True, timeout=6.0)
    res = client.request("POST", "/api/v1/ui-ticket", body={})
    ticket = str(res["ticket"])
    port = int(res.get("port", 8777))
    url = build_auth_url(port, ticket)

    if no_open:
        return {"url": url, "launcher": "none"}

    browser_bin = find_app_browser(which_fn=which_fn)
    if browser_bin:
        profile_dir = get_paths().browser_profile_dir
        profile_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        cmd = [
            browser_bin,
            f"--app={url}",
            f"--user-data-dir={profile_dir}",
            "--class=surfshark-ultralite",
            "--new-window",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"url": url, "launcher": os.path.basename(browser_bin)}

    xdg_open = which_fn("xdg-open")
    if xdg_open:
        subprocess.Popen(
            [xdg_open, url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"url": url, "launcher": "xdg-open"}

    return {"url": url, "launcher": "printed"}
