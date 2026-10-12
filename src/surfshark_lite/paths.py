"""XDG directory resolution and 0700 directory enforcement."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "surfshark-ultralite"


@dataclass(frozen=True)
class AppPaths:
    config_dir: Path
    cache_dir: Path
    state_dir: Path
    runtime_dir: Path
    data_dir: Path

    @property
    def settings_file(self) -> Path:
        return self.config_dir / "settings.json"

    @property
    def credentials_file(self) -> Path:
        return self.config_dir / "credentials.json"

    @property
    def credentials_lock(self) -> Path:
        return self.config_dir / "credentials.lock"

    @property
    def web_secret_file(self) -> Path:
        return self.config_dir / "web_secret"

    @property
    def clusters_cache(self) -> Path:
        return self.cache_dir / "clusters.json"

    @property
    def latency_cache(self) -> Path:
        return self.cache_dir / "latency.json"

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def log_file(self) -> Path:
        return self.state_dir / "daemon.log"

    @property
    def control_sock(self) -> Path:
        return self.runtime_dir / "control.sock"

    @property
    def daemon_lock(self) -> Path:
        return self.runtime_dir / "daemon.lock"

    @property
    def browser_profile_dir(self) -> Path:
        return self.data_dir / "browser"

    def ensure_dirs(self) -> None:
        for d in (
            self.config_dir,
            self.cache_dir,
            self.state_dir,
            self.runtime_dir,
            self.data_dir,
        ):
            d.mkdir(parents=True, mode=0o700, exist_ok=True)
            try:
                st = d.stat()
                if st.st_uid == os.getuid() and (st.st_mode & 0o777) != 0o700:
                    os.chmod(d, 0o700)
            except OSError:
                pass


def get_paths(root_override: str | Path | None = None) -> AppPaths:
    """Resolve XDG paths for Surf Shark Ultra Lite, or under root_override for tests."""
    if root_override is not None:
        base = Path(root_override)
        return AppPaths(
            config_dir=base / "config",
            cache_dir=base / "cache",
            state_dir=base / "state",
            runtime_dir=base / "run",
            data_dir=base / "data",
        )

    env_root = os.environ.get("SSUL_HOME")
    if env_root:
        return get_paths(env_root)

    home = Path.home()
    uid = os.getuid()

    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME") or (home / ".config"))
    xdg_cache = Path(os.environ.get("XDG_CACHE_HOME") or (home / ".cache"))
    xdg_state = Path(os.environ.get("XDG_STATE_HOME") or (home / ".local" / "state"))
    xdg_data = Path(os.environ.get("XDG_DATA_HOME") or (home / ".local" / "share"))
    xdg_runtime = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}")

    return AppPaths(
        config_dir=xdg_config / APP_NAME,
        cache_dir=xdg_cache / APP_NAME,
        state_dir=xdg_state / APP_NAME,
        runtime_dir=xdg_runtime / APP_NAME,
        data_dir=xdg_data / APP_NAME,
    )


def ensure_all_dirs(root_override: str | Path | None = None) -> AppPaths:
    p = get_paths(root_override)
    p.ensure_dirs()
    return p


def runtime_dir() -> Path:
    return get_paths().runtime_dir


def settings_path() -> Path:
    return get_paths().settings_file


def credentials_path() -> Path:
    return get_paths().credentials_file


def clusters_cache_path() -> Path:
    return get_paths().clusters_cache


def latency_cache_path() -> Path:
    return get_paths().latency_cache


def state_path() -> Path:
    return get_paths().state_file


def control_sock_path() -> Path:
    return get_paths().control_sock


def daemon_lock_path() -> Path:
    return get_paths().daemon_lock


def daemon_log_path() -> Path:
    return get_paths().log_file

