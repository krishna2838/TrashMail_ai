"""Unit tests for GeoIP module."""

from __future__ import annotations

from app.geo.geoip import geolocate_ip


def test_geolocate_public_ip():
    # Google public DNS
    result = geolocate_ip("8.8.8.8")
    assert result is not None
    assert result["ip"] == "8.8.8.8"
    assert result["country"] == "United States"
    assert result["country_code"] == "US"
    assert result["latitude"] is not None
    assert result["longitude"] is not None
    assert result["asn_org"] == "Google LLC"


def test_geolocate_private_ip():
    assert geolocate_ip("10.0.0.1") is None
    assert geolocate_ip("192.168.1.1") is None
    assert geolocate_ip("127.0.0.1") is None


def test_geolocate_invalid_ip():
    assert geolocate_ip(None) is None
    assert geolocate_ip("") is None
    assert geolocate_ip("not-an-ip") is None
