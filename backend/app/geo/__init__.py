"""Sender IP geolocation module using MaxMind GeoLite2."""

from __future__ import annotations

from app.geo.geoip import geolocate_ip

__all__ = ["geolocate_ip"]
