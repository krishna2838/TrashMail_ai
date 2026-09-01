"""Unit tests for the hops extraction and originating IP identification."""

from __future__ import annotations

from app.parsing.hops import extract_hops, get_originating_ip


def test_extract_hops_chronological_order():
    received_headers = [
        # Newest (Hop 3)
        "by mx.google.com with SMTP id 123; Mon, 31 Aug 2026 04:15:31 -0700",
        # Middle (Hop 2)
        "from relay.internal.corp (relay.internal.corp [10.0.0.5]) by gate.google.com with ESMTP; Mon, 31 Aug 2026 04:15:30 -0700",
        # Oldest (Hop 1 - Originating)
        "from mail.origin.com (mail.origin.com [209.85.216.41]) by relay.internal.corp with ESMTP id 9988; Mon, 31 Aug 2026 04:15:25 -0700",
    ]

    hops = extract_hops(received_headers)
    assert len(hops) == 3

    # Check chronological ordering: sequence 1 is oldest
    assert hops[0]["sequence"] == 1
    assert hops[0]["from_host"] == "mail.origin.com"
    assert hops[0]["from_ip"] == "209.85.216.41"
    assert hops[0]["is_public_ip"] is True

    # Sequence 2 is middle (private relay)
    assert hops[1]["sequence"] == 2
    assert hops[1]["from_ip"] == "10.0.0.5"
    assert hops[1]["is_public_ip"] is False

    # Sequence 3 is final hop
    assert hops[2]["sequence"] == 3
    assert hops[2]["by_host"] == "mx.google.com"

    # Test originating IP selection (should pick the first public IP from oldest hop)
    origin_ip = get_originating_ip(hops)
    assert origin_ip == "209.85.216.41"


def test_hops_with_internal_only_ips():
    received_headers = [
        "from internal1.lan ([192.168.1.100]) by internal2.lan; Mon, 31 Aug 2026 01:00:00 +0000",
        "from [10.200.1.5] by internal1.lan; Mon, 31 Aug 2026 00:59:00 +0000",
    ]
    hops = extract_hops(received_headers)
    assert len(hops) == 2
    assert hops[0]["is_public_ip"] is False
    assert hops[1]["is_public_ip"] is False

    origin_ip = get_originating_ip(hops)
    assert origin_ip is None


def test_hops_resilience_to_malformed_headers():
    received_headers = [
        "weird nonstandard header without semicolons from mail.bad.com (HELO bad) (185.220.101.5)",
        "(qmail 12345 invoked by uid 500); 31 Aug 2026 12:00:00 -0000",
        "",  # Empty header
    ]
    hops = extract_hops(received_headers)
    assert len(hops) == 2
    assert hops[0]["timestamp"] is not None
    assert hops[1]["from_ip"] == "185.220.101.5"
    assert hops[1]["is_public_ip"] is True


def test_hops_ipv6_handling():
    received_headers = [
        "from 2001:db8:85a3::8a2e:370:7334 by mx.test.org; Mon, 31 Aug 2026 05:00:00 +0000"
    ]
    hops = extract_hops(received_headers)
    assert len(hops) == 1
    assert hops[0]["from_ip"] == "2001:db8:85a3::8a2e:370:7334"
