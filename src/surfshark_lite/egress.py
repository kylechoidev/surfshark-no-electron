"""Egress IP and Geo verification chain with circuit breakers and quorum."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from surfshark_lite.httpclient import NoRedirectHandler, create_ssl_context

log = logging.getLogger("surfshark_lite.egress")


@dataclass(frozen=True)
class EgressReport:
    ip: str | None
    country_code: str | None
    country: str | None
    city: str | None
    isp: str | None
    secured: bool | None
    provider: str
    checked_at: float
    quorum_agreed: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country_code": self.country_code,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "secured": self.secured,
            "provider": self.provider,
            "checked_at": self.checked_at,
            "quorum_agreed": self.quorum_agreed,
        }


@dataclass
class _Breaker:
    failures: int = 0
    open_until: float = 0.0

    def is_open(self, now: float) -> bool:
        return now < self.open_until

    def record_success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def record_failure(self, now: float, threshold: int = 3, cooldown_s: float = 120.0) -> None:
        self.failures += 1
        if self.failures >= threshold:
            self.open_until = now + cooldown_s


def _fetch_url_text(url: str, timeout: float = 4.0) -> str:
    ctx = create_ssl_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirectHandler(),
        urllib.request.ProxyHandler({}),
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SurfsharkLinux/3.14.0 device/desktop",
            "Accept": "application/json, text/plain;q=0.8",
        },
        method="GET",
    )
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(65536)
        return raw.decode("utf-8", errors="replace").strip()


def _probe_surfshark(timeout: float = 4.0, fetcher: Callable[[str, float], str] = _fetch_url_text) -> EgressReport:
    data = json.loads(fetcher("https://api.surfshark.com/v1/server/user", timeout))
    cc = str(data.get("countryCode") or "").upper() or None
    return EgressReport(
        ip=str(data.get("ip") or "").strip() or None,
        country_code=cc,
        country=str(data.get("country") or "").strip() or None,
        city=str(data.get("city") or "").strip() or None,
        isp=str(data.get("isp") or "").strip() or None,
        secured=bool(data["secured"]) if "secured" in data else None,
        provider="surfshark",
        checked_at=time.time(),
    )


def _probe_ipinfo(timeout: float = 4.0, fetcher: Callable[[str, float], str] = _fetch_url_text) -> EgressReport:
    data = json.loads(fetcher("https://ipinfo.io/json", timeout))
    cc = str(data.get("country") or "").upper() or None
    return EgressReport(
        ip=str(data.get("ip") or "").strip() or None,
        country_code=cc,
        country=cc,
        city=str(data.get("city") or "").strip() or None,
        isp=str(data.get("org") or "").strip() or None,
        secured=None,
        provider="ipinfo",
        checked_at=time.time(),
    )


def _probe_ip_sb(timeout: float = 4.0, fetcher: Callable[[str, float], str] = _fetch_url_text) -> EgressReport:
    data = json.loads(fetcher("https://api.ip.sb/geoip", timeout))
    cc = str(data.get("country_code") or "").upper() or None
    return EgressReport(
        ip=str(data.get("ip") or "").strip() or None,
        country_code=cc,
        country=str(data.get("country") or "").strip() or None,
        city=str(data.get("city") or "").strip() or None,
        isp=str(data.get("isp") or data.get("organization") or "").strip() or None,
        secured=None,
        provider="ip.sb",
        checked_at=time.time(),
    )


def _probe_ipify(timeout: float = 4.0, fetcher: Callable[[str, float], str] = _fetch_url_text) -> EgressReport:
    data = json.loads(fetcher("https://api.ipify.org?format=json", timeout))
    return EgressReport(
        ip=str(data.get("ip") or "").strip() or None,
        country_code=None,
        country=None,
        city=None,
        isp=None,
        secured=None,
        provider="ipify",
        checked_at=time.time(),
    )


def _probe_icanhazip(timeout: float = 4.0, fetcher: Callable[[str, float], str] = _fetch_url_text) -> EgressReport:
    ip = fetcher("https://icanhazip.com", timeout).splitlines()[0].strip()
    return EgressReport(
        ip=ip or None,
        country_code=None,
        country=None,
        city=None,
        isp=None,
        secured=None,
        provider="icanhazip",
        checked_at=time.time(),
    )


PROVIDERS: dict[str, Callable[[float, Callable[[str, float], str]], EgressReport]] = {
    "surfshark": _probe_surfshark,
    "ipinfo": _probe_ipinfo,
    "ip.sb": _probe_ip_sb,
    "ipify": _probe_ipify,
    "icanhazip": _probe_icanhazip,
}

DEFAULT_CHAIN: tuple[str, ...] = ("surfshark", "ipinfo", "ip.sb", "ipify", "icanhazip")
GEO_CAPABLE_PROVIDERS: frozenset[str] = frozenset({"surfshark", "ipinfo", "ip.sb"})


class EgressChecker:
    """Multi-provider egress IP/Geo checker with circuit breakers and country quorum."""

    def __init__(
        self,
        chain: tuple[str, ...] = DEFAULT_CHAIN,
        fetcher: Callable[[str, float], str] = _fetch_url_text,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._chain = tuple(p for p in chain if p in PROVIDERS) or DEFAULT_CHAIN
        self._fetcher = fetcher
        self._clock = clock
        self._breakers: dict[str, _Breaker] = {p: _Breaker() for p in PROVIDERS}
        self._baseline: EgressReport | None = None
        self._last_report: EgressReport | None = None

    @property
    def baseline(self) -> EgressReport | None:
        return self._baseline

    @property
    def last_report(self) -> EgressReport | None:
        return self._last_report

    def set_baseline(self, report: EgressReport | None) -> None:
        self._baseline = report

    def capture_baseline(self, timeout: float = 3.5) -> EgressReport | None:
        rep = self.check(expected_country_code=None, timeout=timeout)
        if rep is not None and rep.ip:
            self._baseline = rep
        return self._baseline

    def _try_provider(self, name: str, timeout: float) -> EgressReport | None:
        now = self._clock()
        br = self._breakers.setdefault(name, _Breaker())
        if br.is_open(now):
            return None
        fn = PROVIDERS.get(name)
        if fn is None:
            return None
        try:
            rep = fn(timeout, self._fetcher)
            if not rep.ip:
                raise ValueError(f"Provider {name} returned empty IP")
            br.record_success()
            return rep
        except Exception as exc:
            log.debug("Egress provider %s failed: %s", name, exc)
            br.record_failure(now)
            return None

    def check(
        self,
        expected_country_code: str | None = None,
        timeout: float = 4.0,
    ) -> EgressReport | None:
        """Query providers in order. If geo mismatches expected_country_code, seek quorum."""
        exp_cc = expected_country_code.upper() if expected_country_code else None
        primary: EgressReport | None = None

        for name in self._chain:
            rep = self._try_provider(name, timeout)
            if rep is not None:
                primary = rep
                break

        if primary is None:
            return None

        # If we expect a country code and primary has geo that disagrees, cross-check a second geo provider
        if exp_cc and primary.country_code and primary.country_code.upper() != exp_cc:
            for second_name in self._chain:
                if second_name == primary.provider or second_name not in GEO_CAPABLE_PROVIDERS:
                    continue
                second = self._try_provider(second_name, timeout)
                if second is None or not second.country_code:
                    continue
                if second.ip == primary.ip and second.country_code.upper() == exp_cc:
                    # Secondary agrees with expected country -> GeoIP database lag on primary
                    merged = EgressReport(
                        ip=primary.ip,
                        country_code=exp_cc,
                        country=second.country or primary.country,
                        city=second.city or primary.city,
                        isp=primary.isp or second.isp,
                        secured=primary.secured,
                        provider=f"{primary.provider}+{second.provider}",
                        checked_at=primary.checked_at,
                        quorum_agreed=True,
                    )
                    self._last_report = merged
                    return merged
                break

        self._last_report = primary
        return primary
