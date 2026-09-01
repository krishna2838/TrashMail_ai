"""Unit tests for VirusTotal threat intelligence module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from app.core.config import settings
from app.intel.virustotal import _IOC_CACHE, check_domain, check_ip, check_url


def test_virustotal_disabled_when_api_key_empty(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    _IOC_CACHE.clear()

    res_ip = check_ip("8.8.8.8")
    assert res_ip == {"available": False}

    res_dom = check_domain("example.com")
    assert res_dom == {"available": False}

    res_url = check_url("http://example.com/login")
    assert res_url == {"available": False}


def test_virustotal_malicious_detection(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_key")
    _IOC_CACHE.clear()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 2,
                    "harmless": 40,
                    "undetected": 10,
                }
            }
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = check_domain("malicious-phish-domain.com")
        assert res["available"] is True
        assert res["reputation"] == "malicious"
        assert res["malicious"] == 14
        assert res["total_vendors"] == 66


def test_virustotal_clean_detection(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_key")
    _IOC_CACHE.clear()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                }
            }
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = check_ip("1.1.1.1")
        assert res["available"] is True
        assert res["reputation"] == "clean"
        assert res["malicious"] == 0


def test_virustotal_cache_hits(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "dummy_key")
    _IOC_CACHE.clear()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 50,
                    "undetected": 0,
                }
            }
        }
    }

    with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
        check_domain("cached-domain.com")
        assert mock_get.call_count == 1

        # Second call should hit in-memory cache and not invoke httpx.Client.get
        check_domain("cached-domain.com")
        assert mock_get.call_count == 1
