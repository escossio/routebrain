from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TargetRouteKnowledgeStatus = Literal[
    "bgp_known_traceroute_missing",
    "unknown_bgp_context",
    "private_destination_no_public_bgp",
    "bgp_known_traceroute_present",
]


class TargetRouteKnowledgeReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str
    resolved_ip: str | None = None
    destination_bgp_prefix: str | None = None
    destination_origin_asn: int | None = None
    destination_as_path: str | None = None
    bgp_confidence: Literal["high", "medium", "low", "unknown"] = "unknown"
    has_existing_traceroute_measurement: bool = False
    existing_measurement_ids: list[int] = Field(default_factory=list)
    existing_routegraph_runs: list[str] = Field(default_factory=list)
    knowledge_status: TargetRouteKnowledgeStatus = "unknown_bgp_context"
    what_routebrain_knows: list[str] = Field(default_factory=list)
    what_routebrain_does_not_know: list[str] = Field(default_factory=list)
    next_recommended_action: str = ""

