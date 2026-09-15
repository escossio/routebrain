from __future__ import annotations

import pytest

from app.services.bgp_prefix_normalizer import build_bgp_prefix_cidr


@pytest.mark.parametrize(
    ("raw_prefix", "raw_length", "expected"),
    [
        ("1.1.1.0", 24, "1.1.1.0/24"),
        ("8.8.8.0", "24", "8.8.8.0/24"),
        ("0.0.0.0", 0, "0.0.0.0/0"),
        ("2001:db8::", 32, "2001:db8::/32"),
    ],
)
def test_build_bgp_prefix_cidr(raw_prefix: str, raw_length: int | str, expected: str) -> None:
    assert build_bgp_prefix_cidr(raw_prefix, raw_length) == expected


@pytest.mark.parametrize(
    "raw_length",
    [-1, 33, "abc", None, ""],
)
def test_build_bgp_prefix_cidr_rejects_invalid_length(raw_length) -> None:
    with pytest.raises(ValueError):
        build_bgp_prefix_cidr("1.1.1.0", raw_length)
