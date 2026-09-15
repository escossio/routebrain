from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RouteMemoryStatus = Literal[
    "observed",
    "candidate",
    "learned",
    "trusted",
    "changed",
    "stale",
    "contradicted",
    "unknown",
]

RouteMemorySegmentType = Literal[
    "local_lan",
    "silent_gap",
    "operator_private_core",
    "pre_public_edge",
    "public_operator_edge",
    "public_backbone",
    "mpls_backbone",
    "destination_edge",
    "unknown_gap",
]

RouteMemoryMatchType = Literal[
    "exact_prefix_match",
    "structural_prefix_match",
    "segment_match",
    "asn_sequence_match",
    "rdns_signature_match",
    "destination_asn_match",
    "partial_match",
    "divergence",
]


class RouteMemoryReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str
    resolved_ip: str | None = None
    source_node: str | None = None
    observation_id: int | None = None
    observed_at: str | None = None
    tool: str | None = None
    status: RouteMemoryStatus = "unknown"
    destination_bgp_prefix: str | None = None
    destination_origin_asn: int | None = None
    destination_as_path: str | None = None
    bgp_confidence: Literal["high", "medium", "low", "unknown"] = "unknown"
    has_existing_traceroute_measurement: bool = False
    existing_measurement_ids: list[int] = Field(default_factory=list)
    existing_routegraph_runs: list[str] = Field(default_factory=list)
    knowledge_status: str = "unknown"
    observed_segments: list[dict[str, object]] = Field(default_factory=list)
    known_segments: list[dict[str, object]] = Field(default_factory=list)
    segment_matches: list[dict[str, object]] = Field(default_factory=list)
    route_memory_events: list[dict[str, object]] = Field(default_factory=list)
    route_known_fraction: float = 0.0
    common_prefix_known_hops: int = 0
    divergence_hop: int | None = None
    destination_matches_bgp: bool = False
    what_routebrain_knows: list[str] = Field(default_factory=list)
    what_routebrain_does_not_know: list[str] = Field(default_factory=list)
    next_recommended_action: str = ""
