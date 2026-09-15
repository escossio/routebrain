from __future__ import annotations

from app.services.bgp_current_builder import build_current_route_payload
from app.services.bgp_prefix_normalizer import build_bgp_prefix_cidr
from app.services.bgp_raw_ingest import build_raw_route_payload


def test_raw_payload_preserves_normalized_prefix() -> None:
    normalized = build_bgp_prefix_cidr("1.1.1.0", 24)
    payload = build_raw_route_payload(
        {
            "source": "routeviews",
            "collector": "route-views2",
            "collected_at": None,
            "peer_ip": "1.2.3.4",
            "peer_asn": 65000,
            "prefix": normalized,
            "next_hop": "1.2.3.4",
            "as_path": "65000 13335",
            "origin_asn": 13335,
            "origin_type": "IGP",
            "raw_record": {"prefix": "1.1.1.0", "length": 24},
        }
    )
    assert payload["prefix"] == "1.1.1.0/24"


def test_current_payload_preserves_normalized_prefix() -> None:
    payload = build_current_route_payload(
        "routeviews",
        "route-views2",
        None,
        "1.2.3.4",
        65000,
        "1.1.1.0/24",
        "1.2.3.4",
        "65000 13335",
        13335,
        "IGP",
        {"prefix": "1.1.1.0", "length": 24},
    )
    assert payload["prefix"] == "1.1.1.0/24"
