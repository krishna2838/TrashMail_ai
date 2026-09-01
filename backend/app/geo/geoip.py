"""MaxMind GeoLite2 City and ASN IP geolocation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
import geoip2.database

DB_PATH = Path(__file__).parent / "data" / "GeoLite2-City.mmdb"
ASN_PATH = Path(__file__).parent / "data" / "GeoLite2-ASN.mmdb"


@lru_cache(maxsize=1)
def _city_reader() -> geoip2.database.Reader | None:
    """Load and cache the GeoLite2-City database reader."""
    if not DB_PATH.exists():
        return None
    try:
        return geoip2.database.Reader(str(DB_PATH))
    except Exception:
        return None


@lru_cache(maxsize=1)
def _asn_reader() -> geoip2.database.Reader | None:
    """Load and cache the optional GeoLite2-ASN database reader."""
    if not ASN_PATH.exists():
        return None
    try:
        return geoip2.database.Reader(str(ASN_PATH))
    except Exception:
        return None


def geolocate_ip(ip: str | None) -> dict[str, Any] | None:
    """
    Geolocate a public IPv4/IPv6 address using the local MaxMind GeoLite2 databases.
    Returns latitude, longitude, country, city, and ASN organization if available.
    """
    if not ip or not isinstance(ip, str):
        return None

    clean_ip = ip.strip()
    reader = _city_reader()
    if not reader:
        return None

    try:
        resp = reader.city(clean_ip)
    except Exception:
        return None

    # Query optional ASN organization
    asn_org: str | None = None
    asn_reader = _asn_reader()
    if asn_reader:
        try:
            asn_resp = asn_reader.asn(clean_ip)
            asn_org = asn_resp.autonomous_system_organization
        except Exception:
            asn_org = None

    return {
        "ip": clean_ip,
        "country": resp.country.name,
        "country_code": resp.country.iso_code,
        "city": resp.city.name,
        "latitude": resp.location.latitude,
        "longitude": resp.location.longitude,
        "asn_org": asn_org,
    }
