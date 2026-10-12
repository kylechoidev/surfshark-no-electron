"""Server catalog model, caching, latency probing orchestration, and target Resolver."""

from __future__ import annotations

import base64
import concurrent.futures
import difflib
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

from surfshark_lite.api import SurfsharkAPI
from surfshark_lite.credstore import epoch_to_iso, iso_to_epoch
from surfshark_lite.errors import TargetAmbiguousError, TargetNotFoundError
from surfshark_lite.fsutil import atomic_write_json, read_json_secure
from surfshark_lite.geo import (
    CITY_ALIASES,
    COUNTRIES_BY_A2,
    flag,
    get_country_entry,
    haversine_km,
    norm_text,
    normalize_country,
    region_from_timezone,
)
from surfshark_lite.netprobe import get_physical_default_iface, icmp_echo_probe
from surfshark_lite.state_store import HomeLocation

log = logging.getLogger("surfshark_lite.catalog")

_HOSTNAME_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_CITY_CODE_RE = re.compile(r"^([a-z]{2})-([a-z]{3})(?:-|$)")

FRESH_TTL_S = 6 * 3600.0
MAX_STALE_TTL_S = 30 * 86400.0
LATENCY_TTL_S = 24 * 3600.0


def _valid_wg_pubkey(pub: Any) -> str | None:
    if not isinstance(pub, str) or len(pub) != 44 or not pub.endswith("="):
        return None
    try:
        raw = base64.b64decode(pub, validate=True)
        return pub if len(raw) == 32 else None
    except Exception:
        return None


def _short_city_name(loc: str) -> str:
    """Return canonical short city name (e.g. 'Frankfurt am Main' -> 'Frankfurt')."""
    norm = norm_text(loc)
    if norm.endswith(" am main"):
        return loc[: len(loc) - 8].strip()
    if norm.endswith(" d.c."):
        return loc[: len(loc) - 5].strip()
    return loc


@dataclass(frozen=True)
class Cluster:
    id: str
    hostname: str
    pubkey: str | None
    country: str
    country_code: str
    region: str | None
    location: str
    load: int | None
    tags: frozenset[str]
    kind: str
    lat: float | None
    lon: float | None
    transit: "Cluster | None"
    code: str
    city_code: str | None
    virtual: bool
    raw: Mapping[str, Any]

    @property
    def wg_connectable(self) -> bool:
        return self.pubkey is not None

    @property
    def label(self) -> str:
        return f"{self.location}, {self.country_code}"

    def to_summary(self, latency_ms: float | None = None) -> dict[str, Any]:
        ce = COUNTRIES_BY_A2.get(self.country_code)
        extra_terms: list[str] = []
        if ce is not None:
            extra_terms.append(ce.alpha3.lower())
            extra_terms.extend(ce.aliases)
            if ce.alpha2 == "GB":
                extra_terms.append("uk")
        loc_norm = norm_text(self.location)
        short_norm = norm_text(_short_city_name(self.location))
        for alias_k, target_city in CITY_ALIASES.items():
            tnorm = norm_text(target_city)
            if tnorm in (loc_norm, short_norm):
                extra_terms.append(alias_k)
        search_terms = " ".join(
            [
                self.location.lower(),
                self.country.lower(),
                self.country_code.lower(),
                self.hostname.lower(),
                (self.city_code or "").lower(),
                *extra_terms,
            ]
        )
        return {
            "id": self.id,
            "label": self.label,
            "hostname": self.hostname,
            "country_code": self.country_code,
            "country": self.country,
            "location": self.location,
            "load": self.load,
            "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
            "tags": sorted(self.tags),
            "kind": self.kind,
            "virtual": self.virtual,
            "flag": flag(self.country_code),
            "search_terms": search_terms,
        }


def parse_cluster(raw: Mapping[str, Any]) -> Cluster | None:
    if not isinstance(raw, Mapping):
        return None
    cid = raw.get("id")
    hostname_raw = raw.get("connectionName") or raw.get("hostname")
    if not isinstance(cid, str) or not cid or not isinstance(hostname_raw, str):
        return None
    hostname = hostname_raw.strip().lower()
    if not _HOSTNAME_RE.match(hostname):
        log.debug("Skipping cluster with invalid hostname: %s", hostname)
        return None
    if not hostname.endswith(".surfshark.com"):
        log.warning("Cluster hostname does not end with .surfshark.com: %s", hostname)

    cc = normalize_country(raw.get("countryCode"))
    if not cc:
        return None
    country_entry = get_country_entry(cc)
    country = str(raw.get("country") or (country_entry.name if country_entry else cc))
    region = raw.get("region")
    if not isinstance(region, str) or not region:
        region = country_entry.region if country_entry else None

    location = str(raw.get("location") or country).strip()
    pubkey = _valid_wg_pubkey(raw.get("pubKey"))

    load_raw = raw.get("load")
    load: int | None = None
    if not isinstance(load_raw, bool) and isinstance(load_raw, (int, float)):
        load = max(0, min(100, int(load_raw)))

    tags_raw = raw.get("tags")
    tags: frozenset[str] = frozenset()
    if isinstance(tags_raw, list):
        tags = frozenset(str(t).strip().lower() for t in tags_raw if isinstance(t, str) and t.strip())

    kind = str(raw.get("type") or "generic").strip().lower()

    coords = raw.get("coordinates")
    lat: float | None = None
    lon: float | None = None
    if isinstance(coords, Mapping):
        try:
            if coords.get("latitude") is not None and coords.get("longitude") is not None:
                lat = float(coords["latitude"])
                lon = float(coords["longitude"])
        except (TypeError, ValueError):
            lat, lon = None, None

    transit_raw = raw.get("transitCluster")
    transit = parse_cluster(transit_raw) if isinstance(transit_raw, Mapping) else None

    code = hostname.split(".", 1)[0]
    m = _CITY_CODE_RE.match(code)
    city_code = m.group(2) if m else None
    virtual = "virtual" in tags

    return Cluster(
        id=cid,
        hostname=hostname,
        pubkey=pubkey,
        country=country,
        country_code=cc,
        region=region,
        location=location,
        load=load,
        tags=tags,
        kind=kind,
        lat=lat,
        lon=lon,
        transit=transit,
        code=code,
        city_code=city_code,
        virtual=virtual,
        raw=dict(raw),
    )


def parse_clusters(raw_list: list[Any]) -> list[Cluster]:
    out: list[Cluster] = []
    for item in raw_list:
        if isinstance(item, Mapping):
            c = parse_cluster(item)
            if c is not None:
                out.append(c)
    return out


@dataclass(frozen=True)
class TargetFilters:
    kind: str | None = None          # "generic" | "static" | "double" | "obfuscated"
    tags: frozenset[str] = frozenset()
    physical_only: bool = False

    def matches(self, c: Cluster) -> bool:
        if not c.wg_connectable:
            return False
        if self.kind and c.kind != self.kind:
            return False
        if self.physical_only and c.virtual:
            return False
        for t in self.tags:
            if t not in c.tags:
                return False
        return True


@dataclass(frozen=True)
class Resolution:
    query: str
    scope: Literal["cluster", "city", "country", "region", "global"]
    candidates: tuple[Cluster, ...]
    choice: Cluster | None
    ambiguous: bool
    alternatives: tuple[tuple[str, float], ...]

    def to_dict(self, latencies: Mapping[str, float] | None = None) -> dict[str, Any]:
        lats = latencies or {}
        return {
            "query": self.query,
            "scope": self.scope,
            "ambiguous": self.ambiguous,
            "choice": self.choice.to_summary(lats.get(self.choice.hostname)) if self.choice else None,
            "candidates": [c.to_summary(lats.get(c.hostname)) for c in self.candidates[:25]],
            "alternatives": [{"label": lbl, "score": round(sc, 1)} for lbl, sc in self.alternatives],
        }


def _term_match_multiplier(q: str, term: str, is_city_name: bool = False) -> float:
    if not q or not term:
        return 0.0
    if q == term:
        return 1.0
    words = term.split()
    if len(q) >= 3:
        if is_city_name and len(words) > 1 and words[0] == q:
            return 0.96
        if term.startswith(q):
            return 0.85
        for w in words[1:]:
            if w.startswith(q):
                return 0.70
    if len(q) >= 4:
        ratio = difflib.SequenceMatcher(None, q, term).ratio()
        if ratio >= 0.80:
            return ratio * 0.60
    return 0.0


def select_best_cluster(
    candidates: list[Cluster] | tuple[Cluster, ...],
    latencies: Mapping[str, float] | None = None,
    home: HomeLocation | None = None,
) -> Cluster | None:
    if not candidates:
        return None
    lats = latencies or {}

    # Filter out load >= 90 unless all candidates have load >= 90
    under_90 = [c for c in candidates if (c.load is None or c.load < 90)]
    pool = under_90 if under_90 else list(candidates)

    # 1. If fresh latency exists for at least one candidate, minimize rtt_ms * (1 + load/200)
    with_lat = [c for c in pool if c.hostname in lats]
    if with_lat:
        def _lat_score(c: Cluster) -> tuple[float, int, str]:
            rtt = lats[c.hostname]
            load_val = c.load if c.load is not None else 50
            return (rtt * (1.0 + load_val / 200.0), load_val, c.hostname)

        return min(with_lat, key=_lat_score)

    # 2. If home location exists, choose nearest by haversine distance, breaking ties by load
    if home is not None:
        with_coords = [c for c in pool if c.lat is not None and c.lon is not None]
        if with_coords:
            def _dist_score(c: Cluster) -> tuple[float, int, str]:
                assert c.lat is not None and c.lon is not None
                d = haversine_km(home.lat, home.lon, c.lat, c.lon)
                load_val = c.load if c.load is not None else 50
                return (round(d, 1), load_val, c.hostname)

            return min(with_coords, key=_dist_score)

    # 3. Otherwise choose lowest load
    def _load_score(c: Cluster) -> tuple[int, str]:
        return (c.load if c.load is not None else 50, c.hostname)

    return min(pool, key=_load_score)


class Resolver:
    """Resolves user query strings ('sfo', 'tokyo', 'uk', 'fastest us', 'last') to clusters."""

    def __init__(self, clusters: list[Cluster]) -> None:
        self.clusters = list(clusters)
        # Map canonical city norm -> list of aliases
        self._city_aliases_by_target: dict[str, list[str]] = {}
        for alias_norm, target_city in CITY_ALIASES.items():
            for key_norm in (norm_text(target_city), norm_text(_short_city_name(target_city))):
                self._city_aliases_by_target.setdefault(key_norm, []).append(alias_norm)

    def _cluster_terms(self, c: Cluster) -> list[tuple[str, float, Literal["cluster", "city", "country", "region"]]]:
        terms: list[tuple[str, float, Literal["cluster", "city", "country", "region"]]] = [
            (norm_text(c.hostname), 1000.0, "cluster"),
            (norm_text(c.id), 1000.0, "cluster"),
            (norm_text(c.code), 950.0, "cluster"),
        ]
        if c.city_code:
            terms.append((norm_text(c.city_code), 900.0, "city"))

        city_norm = norm_text(c.location)
        short_city_norm = norm_text(_short_city_name(c.location))
        terms.append((city_norm, 880.0, "city"))
        if short_city_norm and short_city_norm != city_norm:
            terms.append((short_city_norm, 880.0, "city"))

        for k_norm in {city_norm, short_city_norm}:
            for al in self._city_aliases_by_target.get(k_norm, ()):
                terms.append((al, 870.0, "city"))

        cc_lower = c.country_code.lower()
        terms.append((cc_lower, 800.0, "country"))
        terms.append((norm_text(c.country), 780.0, "country"))

        ce = COUNTRIES_BY_A2.get(c.country_code)
        if ce:
            terms.append((ce.alpha3.lower(), 790.0, "country"))
            for al in ce.aliases:
                weight = 790.0 if len(al) <= 3 else 770.0
                terms.append((al, weight, "country"))
                al_nodot = al.replace(".", "")
                if al_nodot != al:
                    terms.append((al_nodot, weight, "country"))

        if c.region:
            terms.append((norm_text(c.region), 600.0, "region"))

        return terms

    def resolve(
        self,
        query: str | None,
        *,
        filters: TargetFilters | None = None,
        latencies: Mapping[str, float] | None = None,
        home: HomeLocation | None = None,
        last_cluster_id: str | None = None,
    ) -> Resolution:
        flt = filters or TargetFilters()
        pool = [c for c in self.clusters if flt.matches(c)]
        raw_q = (query or "fastest").strip()
        q = norm_text(raw_q)

        if not q or q in ("fastest", "quick", "best", "auto"):
            best = select_best_cluster(pool, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="global",
                candidates=tuple(pool),
                choice=best,
                ambiguous=False,
                alternatives=(),
            )

        if q == "last":
            if last_cluster_id:
                for c in pool:
                    if c.id == last_cluster_id or norm_text(c.hostname) == norm_text(last_cluster_id) or norm_text(c.code) == norm_text(last_cluster_id):
                        return Resolution(
                            query=raw_q,
                            scope="cluster",
                            candidates=(c,),
                            choice=c,
                            ambiguous=False,
                            alternatives=((f"{c.label} ({c.code})", 1000.0),),
                        )
            best = select_best_cluster(pool, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="global",
                candidates=tuple(pool),
                choice=best,
                ambiguous=False,
                alternatives=(),
            )

        if q.startswith("fastest ") or q.startswith("best ") or q.startswith("quick "):
            sub_q = q.split(" ", 1)[1].strip()
            if sub_q:
                return self.resolve(
                    sub_q,
                    filters=flt,
                    latencies=latencies,
                    home=home,
                    last_cluster_id=last_cluster_id,
                )

        # Score each cluster and group by (country_code, short_city_name) for ambiguity analysis
        cluster_scores: list[tuple[Cluster, float, Literal["cluster", "city", "country", "region"]]] = []

        for c in pool:
            best_sc = 0.0
            best_scope: Literal["cluster", "city", "country", "region"] = "city"
            for term, weight, t_scope in self._cluster_terms(c):
                mult = _term_match_multiplier(q, term, is_city_name=(weight == 880.0))
                if mult > 0.0:
                    sc = weight * mult
                    if sc > best_sc:
                        best_sc = sc
                        best_scope = t_scope
            if best_sc > 0.0:
                cluster_scores.append((c, best_sc, best_scope))

        if not cluster_scores:
            return Resolution(
                query=raw_q,
                scope="cluster",
                candidates=(),
                choice=None,
                ambiguous=False,
                alternatives=(),
            )

        cluster_scores.sort(key=lambda item: (-item[1], item[0].load if item[0].load is not None else 50, item[0].hostname))
        top_cluster, top_score, top_scope = cluster_scores[0]

        # Exact cluster match (hostname, id, or code with score >= 950)
        if top_score >= 950.0:
            exact_cands = [c for c, sc, _ in cluster_scores if sc == top_score]
            chosen = select_best_cluster(exact_cands, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="cluster",
                candidates=tuple(exact_cands),
                choice=chosen,
                ambiguous=False,
                alternatives=((f"{top_cluster.label} ({top_cluster.code})", top_score),),
            )

        # Group by location (country_code, canonical short city) for city-level ambiguity check
        loc_groups: dict[tuple[str, str], tuple[float, Literal["cluster", "city", "country", "region"], list[Cluster]]] = {}
        for c, sc, scope_kind in cluster_scores:
            loc_key = (c.country_code, _short_city_name(c.location))
            if loc_key not in loc_groups:
                loc_groups[loc_key] = (sc, scope_kind, [c])
            else:
                prev_sc, prev_scope, prev_list = loc_groups[loc_key]
                prev_list.append(c)
                if sc > prev_sc:
                    loc_groups[loc_key] = (sc, scope_kind, prev_list)

        ranked_locs = sorted(
            loc_groups.items(),
            key=lambda kv: (-kv[1][0], kv[0][0], kv[0][1]),
        )

        alternatives: list[tuple[str, float]] = [
            (f"{city_lbl}, {cc}", sc_val)
            for (cc, city_lbl), (sc_val, _, _) in ranked_locs[:5]
        ]

        # If top match is a country or region scope (and not beaten by a higher-scoring city)
        if top_scope == "country" and top_score >= 770.0:
            target_cc = top_cluster.country_code
            cands = [c for c, sc, _ in cluster_scores if c.country_code == target_cc and sc >= top_score * 0.95]
            chosen = select_best_cluster(cands, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="country",
                candidates=tuple(cands),
                choice=chosen,
                ambiguous=False,
                alternatives=((f"{top_cluster.country} ({target_cc})", top_score),),
            )

        if top_scope == "region" and top_score >= 600.0:
            target_reg = top_cluster.region
            cands = [c for c, sc, _ in cluster_scores if c.region == target_reg and sc >= top_score * 0.95]
            chosen = select_best_cluster(cands, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="region",
                candidates=tuple(cands),
                choice=chosen,
                ambiguous=False,
                alternatives=((str(target_reg), top_score),),
            )

        # Ambiguity rule (§9.3): top two locations differ in city, both score >= 600, and second >= 0.92 * first
        is_ambiguous = False
        if len(ranked_locs) >= 2:
            (cc1, city1), (sc1, scope1, _) = ranked_locs[0]
            (cc2, city2), (sc2, scope2, _) = ranked_locs[1]
            # Only ambiguous if the second match is not merely a country-code collision beaten by an explicit city alias
            if (cc1, city1) != (cc2, city2) and sc1 >= 600.0 and sc2 >= 600.0 and sc2 >= 0.92 * sc1:
                is_ambiguous = True

        if is_ambiguous:
            ambig_cands: list[Cluster] = []
            for (_cc, _city), (sc_val, _, clist) in ranked_locs[:5]:
                if sc_val >= 0.92 * top_score and sc_val >= 600.0:
                    best_in_loc = select_best_cluster(clist, latencies=latencies, home=home)
                    if best_in_loc:
                        ambig_cands.append(best_in_loc)
            chosen = select_best_cluster(ambig_cands, latencies=latencies, home=home)
            return Resolution(
                query=raw_q,
                scope="city",
                candidates=tuple(ambig_cands),
                choice=chosen,
                ambiguous=True,
                alternatives=tuple(alternatives),
            )

        top_loc_clusters = ranked_locs[0][1][2]
        chosen = select_best_cluster(top_loc_clusters, latencies=latencies, home=home)
        return Resolution(
            query=raw_q,
            scope="city",
            candidates=tuple(top_loc_clusters),
            choice=chosen,
            ambiguous=False,
            alternatives=tuple(alternatives),
        )


class CatalogManager:
    """Manages cluster catalog cache, ETag refresh, official cache seeding, and ICMP latency probing."""

    def __init__(
        self,
        clusters_cache_path: Path,
        latency_cache_path: Path,
        api: SurfsharkAPI,
        clock: Callable[[], float] = time.time,
        official_cache_path: Path | None = None,
    ) -> None:
        self.clusters_cache_path = clusters_cache_path
        self.latency_cache_path = latency_cache_path
        self.api = api
        self._clock = clock
        self.official_cache_path = official_cache_path or (Path.home() / ".config" / "Surfshark" / "cache.json")

        self._clusters: list[Cluster] = []
        self._fetched_at: float | None = None
        self._etag: str | None = None
        self._source: str = "none"
        self._latencies: dict[str, dict[str, Any]] = {}

    @property
    def clusters(self) -> list[Cluster]:
        return list(self._clusters)

    @property
    def fetched_at(self) -> float | None:
        return self._fetched_at

    @property
    def source(self) -> str:
        return self._source

    def is_stale(self, max_age_s: float = FRESH_TTL_S) -> bool:
        if not self._clusters or self._fetched_at is None:
            return True
        return (self._clock() - self._fetched_at) > max_age_s

    def get_fresh_latencies(self) -> dict[str, float]:
        now = self._clock()
        out: dict[str, float] = {}
        for host, entry in self._latencies.items():
            if not isinstance(entry, dict):
                continue
            probed_at = iso_to_epoch(entry.get("probed_at"))
            rtt = entry.get("rtt_ms")
            if (
                probed_at is not None
                and (now - probed_at) <= LATENCY_TTL_S
                and isinstance(rtt, (int, float))
                and not entry.get("via_tunnel", False)
            ):
                out[host] = float(rtt)
        return out

    def load_cache(self) -> list[Cluster]:
        raw_lat = read_json_secure(self.latency_cache_path, check_perms=False)
        if isinstance(raw_lat, dict):
            self._latencies = raw_lat

        raw_cat = read_json_secure(self.clusters_cache_path, check_perms=False)
        if isinstance(raw_cat, dict) and isinstance(raw_cat.get("raw"), list):
            parsed = parse_clusters(raw_cat["raw"])
            if parsed:
                self._clusters = parsed
                self._fetched_at = iso_to_epoch(raw_cat.get("fetched_at"))
                self._etag = raw_cat.get("etag") if isinstance(raw_cat.get("etag"), str) else None
                self._source = str(raw_cat.get("source") or "cache")
                return list(self._clusters)

        # One-time seed from official ~/.config/Surfshark/cache.json if available
        if self.official_cache_path.is_file():
            try:
                off_data = json.loads(self.official_cache_path.read_text(encoding="utf-8"))
                raw_items = None
                for key in ("/v5/server/clusters/all", "locations_items"):
                    if isinstance(off_data.get(key), dict) and isinstance(off_data[key].get("value"), list):
                        raw_items = off_data[key]["value"]
                        break
                if raw_items:
                    parsed = parse_clusters(raw_items)
                    if parsed:
                        self._clusters = parsed
                        self._fetched_at = self._clock()
                        self._source = "official-seed"
                        self._save_clusters_cache(raw_items)
                        log.info("Seeded %d clusters from official Surfshark cache", len(parsed))
                        return list(self._clusters)
            except Exception:
                pass

        return list(self._clusters)

    def _save_clusters_cache(self, raw_items: list[dict[str, Any]]) -> None:
        payload = {
            "schema": 1,
            "fetched_at": epoch_to_iso(self._fetched_at),
            "etag": self._etag,
            "endpoint": "/v5/server/clusters/all",
            "source": self._source,
            "raw": raw_items,
        }
        atomic_write_json(self.clusters_cache_path, payload, mode=0o600)

    def refresh(self, bearer: str | None = None) -> list[Cluster]:
        raw_items, new_etag = self.api.clusters(bearer=bearer, etag=self._etag)
        now = self._clock()
        if raw_items is None:
            # 304 Not Modified
            self._fetched_at = now
            self._source = "api"
            return list(self._clusters)

        parsed = parse_clusters(raw_items)
        if not parsed:
            raise ValueError("Refreshed catalog contained 0 valid clusters")
        self._clusters = parsed
        self._fetched_at = now
        self._etag = new_etag
        self._source = "api"
        self._save_clusters_cache(raw_items)
        log.info("Refreshed server catalog: %d clusters", len(parsed))
        return list(self._clusters)

    def ensure_loaded(self, bearer: str | None = None) -> list[Cluster]:
        if not self._clusters:
            self.load_cache()
        if not self._clusters or self.is_stale(FRESH_TTL_S):
            try:
                self.refresh(bearer=bearer)
            except Exception as exc:
                if not self._clusters:
                    raise
                log.warning("Catalog refresh failed; serving cached clusters (%s)", exc)
        return list(self._clusters)

    def resolver(self) -> Resolver:
        return Resolver(self._clusters)

    def resolve_or_raise(
        self,
        query: str | None,
        *,
        filters: TargetFilters | None = None,
        home: HomeLocation | None = None,
        last_cluster_id: str | None = None,
        allow_ambiguous_top: bool = False,
        auto_probe: bool = False,
        tunnel_connected: bool = False,
    ) -> Resolution:
        lats = self.get_fresh_latencies()
        res = self.resolver().resolve(
            query,
            filters=filters,
            latencies=lats,
            home=home,
            last_cluster_id=last_cluster_id,
        )
        if res.choice is None or not res.candidates:
            raise TargetNotFoundError(query or "fastest")
        if res.ambiguous and not allow_ambiguous_top:
            raise TargetAmbiguousError(
                query or "",
                [c.to_summary(lats.get(c.hostname)) for c in res.candidates[:10]],
            )
        if (
            auto_probe
            and res.scope in ("country", "region", "global")
            and len(res.candidates) > 1
            and not any(c.hostname in lats for c in res.candidates)
        ):
            scope_str = (
                f"country:{res.choice.country_code}"
                if res.scope == "country" and res.choice is not None
                else "nearest"
            )
            try:
                self.probe_latencies(
                    scope=scope_str,
                    home=home,
                    last_cluster_id=last_cluster_id,
                    tunnel_connected=tunnel_connected,
                )
                lats = self.get_fresh_latencies()
                res = self.resolver().resolve(
                    query,
                    filters=filters,
                    latencies=lats,
                    home=home,
                    last_cluster_id=last_cluster_id,
                )
            except Exception as exc:
                log.debug("Auto-probe during resolve skipped: %s", exc)
        return res

    def _detect_local_region(self) -> str | None:
        tctl = shutil.which("timedatectl") if "shutil" in globals() else "/usr/bin/timedatectl"
        if os.path.exists(tctl):
            try:
                res = subprocess.run(
                    [tctl, "show", "-p", "Timezone", "--value"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                    shell=False,
                    env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                )
                if res.returncode == 0:
                    return region_from_timezone(res.stdout.decode("utf-8", errors="replace").strip())
            except Exception:
                pass
        return None

    def select_probe_candidates(
        self,
        scope: str = "nearest",
        *,
        home: HomeLocation | None = None,
        last_cluster_id: str | None = None,
        limit: int = 12,
    ) -> list[Cluster]:
        pool = [c for c in self._clusters if c.wg_connectable and c.kind == "generic"]
        if not pool:
            pool = [c for c in self._clusters if c.wg_connectable]
        if not pool:
            return []

        if scope.startswith("country:"):
            cc = normalize_country(scope.split(":", 1)[1])
            if cc:
                c_pool = [c for c in pool if c.country_code == cc]
                c_pool.sort(key=lambda c: (c.load if c.load is not None else 50, c.hostname))
                return c_pool[:limit]

        if scope == "all":
            pool.sort(key=lambda c: (c.load if c.load is not None else 50, c.hostname))
            return pool[:limit]

        selected: list[Cluster] = []
        if last_cluster_id:
            for c in pool:
                if c.id == last_cluster_id or c.hostname == last_cluster_id:
                    selected.append(c)
                    break

        if home is not None:
            with_coords = [c for c in pool if c.lat is not None and c.lon is not None and c not in selected]
            with_coords.sort(
                key=lambda c: (
                    haversine_km(home.lat, home.lon, c.lat or 0.0, c.lon or 0.0),
                    c.load if c.load is not None else 50,
                )
            )
            selected.extend(with_coords[: max(0, limit - len(selected))])
            return selected

        reg = self._detect_local_region()
        if reg:
            reg_pool = [c for c in pool if c.region == reg and c not in selected]
            reg_pool.sort(key=lambda c: (c.load if c.load is not None else 50, c.hostname))
            selected.extend(reg_pool[: max(0, limit - len(selected))])
            if len(selected) >= limit:
                return selected[:limit]

        rem = [c for c in pool if c not in selected]
        rem.sort(key=lambda c: (c.load if c.load is not None else 50, c.hostname))
        selected.extend(rem[: max(0, limit - len(selected))])
        return selected[:limit]

    def probe_latencies(
        self,
        scope: str = "nearest",
        *,
        home: HomeLocation | None = None,
        last_cluster_id: str | None = None,
        tunnel_connected: bool = False,
        probe_fn: Callable[..., Any] = icmp_echo_probe,
    ) -> dict[str, float]:
        candidates = self.select_probe_candidates(scope, home=home, last_cluster_id=last_cluster_id, limit=12)
        if not candidates:
            return {}

        bind_iface: str | None = None
        if tunnel_connected:
            bind_iface = get_physical_default_iface()

        now_iso = epoch_to_iso(self._clock())
        results: dict[str, float] = {}

        def _probe_one(c: Cluster) -> tuple[str, Any]:
            return c.hostname, probe_fn(c.hostname, count=3, interval_s=0.15, timeout_s=0.8, bind_iface=bind_iface)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futs = [ex.submit(_probe_one, c) for c in candidates]
            done, _ = concurrent.futures.wait(futs, timeout=3.0)
            for f in done:
                try:
                    host, res = f.result()
                    if res.ok and res.min_ms is not None:
                        results[host] = res.min_ms
                        if not res.via_tunnel:
                            self._latencies[host] = {
                                "rtt_ms": res.min_ms,
                                "median_ms": res.median_ms,
                                "probed_at": now_iso,
                                "via": bind_iface or "direct",
                            }
                except Exception:
                    pass

        if self._latencies:
            atomic_write_json(self.latency_cache_path, self._latencies, mode=0o600)
        return results

    def get_view(self) -> dict[str, Any]:
        return {
            "fetched_at": epoch_to_iso(self._fetched_at),
            "count": len(self._clusters),
            "source": self._source,
            "stale": self.is_stale(FRESH_TTL_S),
        }
