"""Tunnel driver selection and re-exports."""

from __future__ import annotations

from typing import Callable

from surfshark_lite.errors import DriverError, ErrorCode
from surfshark_lite.tunnel.base import DriverCaps, Observation, PeerSpec, TunnelDriver, TunnelSpec
from surfshark_lite.tunnel.nm import NmDriver
from surfshark_lite.tunnel.profile import build_spec
from surfshark_lite.tunnel.surfsharkd import SurfsharkdDriver


def select_driver(
    mode: str = "auto",
    on_resume: Callable[[], None] | None = None,
) -> TunnelDriver:
    """Select and return a TunnelDriver for `mode` ('auto', 'native', or 'surfsharkd')."""
    m = (mode or "auto").strip().lower()
    if m == "native":
        drv = NmDriver(on_resume=on_resume)
        ok, msg = drv.probe()
        if not ok:
            raise DriverError(ErrorCode.DRIVER_UNAVAILABLE, f"Native NetworkManager driver unavailable: {msg}")
        return drv

    if m == "surfsharkd":
        sdrv = SurfsharkdDriver()
        ok, msg = sdrv.probe()
        if not ok:
            raise DriverError(ErrorCode.DRIVER_UNAVAILABLE, f"surfsharkd fallback driver unavailable: {msg}")
        return sdrv

    # 'auto': prefer native NetworkManager, fall back to surfsharkd.sock if available
    ndrv = NmDriver(on_resume=on_resume)
    nok, nmsg = ndrv.probe()
    if nok:
        return ndrv

    sdrv = SurfsharkdDriver()
    sok, smsg = sdrv.probe()
    if sok:
        return sdrv

    raise DriverError(
        ErrorCode.DRIVER_UNAVAILABLE,
        f"No tunnel driver available (native: {nmsg}; surfsharkd: {smsg}). "
        "Install python3-gi and gir1.2-nm-1.0.",
    )


__all__ = [
    "DriverCaps",
    "NmDriver",
    "Observation",
    "PeerSpec",
    "SurfsharkdDriver",
    "TunnelDriver",
    "TunnelSpec",
    "build_spec",
    "select_driver",
]
