"""Lab geolocation for documentation-range IPs, plus haversine distance.

Production enrichment (MaxMind, IdP city, VPN gateway) is out of scope. The
tables below cover RFC 5737 TEST-NET addresses used by the synthetic generator
so impossible-travel logic runs offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import asin, cos, radians, sin, sqrt


@dataclass(frozen=True, slots=True)
class GeoPoint:
    city: str
    country: str
    lat: float
    lon: float


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    phi1, phi2 = radians(lat1), radians(lat2)
    d_phi = radians(lat2 - lat1)
    d_lambda = radians(lon2 - lon1)
    a = sin(d_phi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(d_lambda / 2) ** 2
    return 2 * radius * asin(sqrt(a))


def _fill(table: dict[str, GeoPoint], prefix: str, start: int, end: int, point: GeoPoint) -> None:
    for octet in range(start, end + 1):
        table[f"{prefix}.{octet}"] = point


_LONDON = GeoPoint("London", "GB", 51.5074, -0.1278)
_SINGAPORE = GeoPoint("Singapore", "SG", 1.3521, 103.8198)
_NEW_YORK = GeoPoint("New York", "US", 40.7128, -74.0060)

LAB_GEO: dict[str, GeoPoint] = {}
_fill(LAB_GEO, "198.51.100", 1, 254, _LONDON)
_fill(LAB_GEO, "203.0.113", 1, 254, _SINGAPORE)
_fill(LAB_GEO, "192.0.2", 1, 254, _NEW_YORK)


def lookup(ip: str | None) -> GeoPoint | None:
    if not ip:
        return None
    return LAB_GEO.get(ip)
