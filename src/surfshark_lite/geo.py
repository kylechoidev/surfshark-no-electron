"""Country normalization, flag emojis, haversine distance, and timezone-to-region mapping."""

from __future__ import annotations

import json
import math
import unicodedata
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CountryEntry:
    alpha2: str
    alpha3: str
    name: str
    aliases: tuple[str, ...]
    region: str


def norm_text(s: str) -> str:
    """Normalize text per §9.3: NFKD -> strip combining marks -> casefold -> [^a-z0-9.-]+ to space -> collapse."""
    if not s:
        return ""
    decomposed = unicodedata.normalize("NFKD", s)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    folded = stripped.casefold()
    cleaned = "".join(ch if (ch.isalnum() or ch in ".-") else " " for ch in folded)
    return " ".join(cleaned.split())


_DATA_DIR = Path(__file__).resolve().parent / "data"


def _load_countries() -> tuple[dict[str, CountryEntry], dict[str, str]]:
    raw = json.loads((_DATA_DIR / "countries.json").read_text(encoding="utf-8"))
    by_a2: dict[str, CountryEntry] = {}
    lookup: dict[str, str] = {"uk": "GB"}
    for item in raw:
        a2 = item["alpha2"].upper()
        a3 = item["alpha3"].upper()
        name = item["name"]
        aliases = tuple(norm_text(a) for a in item.get("aliases", ()))
        region = item.get("region", "Europe")
        entry = CountryEntry(alpha2=a2, alpha3=a3, name=name, aliases=aliases, region=region)
        by_a2[a2] = entry
        lookup[a2.lower()] = a2
        lookup[a3.lower()] = a2
        lookup[norm_text(name)] = a2
        for al in aliases:
            lookup[al] = a2
            lookup[al.replace(".", "")] = a2
    return by_a2, lookup


def _load_city_aliases() -> dict[str, str]:
    raw = json.loads((_DATA_DIR / "city_aliases.json").read_text(encoding="utf-8"))
    return {norm_text(k): v for k, v in raw.items()}


COUNTRIES_BY_A2, _COUNTRY_LOOKUP = _load_countries()
CITY_ALIASES: dict[str, str] = _load_city_aliases()


def normalize_country(val: str | None) -> str | None:
    """Normalize alpha-2, alpha-3, country name, or alias (including 'UK' -> 'GB') to uppercase ISO alpha-2."""
    if not val or not isinstance(val, str):
        return None
    s = norm_text(val)
    if not s:
        return None
    if s in _COUNTRY_LOOKUP:
        return _COUNTRY_LOOKUP[s]
    s_nodots = s.replace(".", "")
    if s_nodots in _COUNTRY_LOOKUP:
        return _COUNTRY_LOOKUP[s_nodots]
    if len(s) == 2 and s.isalpha():
        up = s.upper()
        return "GB" if up == "UK" else up
    return None


def get_country_entry(alpha2: str | None) -> CountryEntry | None:
    cc = normalize_country(alpha2)
    if not cc:
        return None
    return COUNTRIES_BY_A2.get(cc)


def flag(country_code: str | None) -> str:
    """Return Unicode regional indicator flag emoji for ISO alpha-2 country code."""
    cc = normalize_country(country_code)
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return chr(0x1F1E6 + ord(cc[0]) - ord("A")) + chr(0x1F1E6 + ord(cc[1]) - ord("A"))


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometers between two (lat, lon) coordinates."""
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * r * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


def region_from_timezone(tz: str | None) -> str | None:
    """Map an IANA timezone string (e.g. 'Asia/Ho_Chi_Minh') to a Surfshark coarse region."""
    if not tz or not isinstance(tz, str):
        return None
    prefix = tz.strip().split("/")[0].lower()
    if prefix in ("america", "us", "canada", "brazil", "chile", "mexico"):
        return "The Americas"
    if prefix in ("europe", "atlantic", "arctic"):
        return "Europe"
    if prefix in ("asia", "australia", "pacific", "indian"):
        return "Asia Pacific"
    if prefix in ("africa",):
        return "Middle East and Africa"
    return None
