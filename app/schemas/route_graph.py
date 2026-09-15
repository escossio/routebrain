from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RouteGraphConfidence = Literal["high", "partial", "low", "unknown"]
RouteGraphNodeKind = Literal["source", "private_hop", "public_hop", "silent_hop", "destination", "unknown"]
RouteGraphEdgeKind = Literal["logical_next_hop"]
RouteGraphLayout = Literal["left_to_right"]


class RouteGraphSource(BaseModel):
    run_uid: str
    session_id: str | None = None
    target: str | None = None
    ip_family: Literal["ipv4", "ipv6", "unknown"] = "unknown"
    generated_at: datetime


class RouteGraphSummary(BaseModel):
    logical_hop_count: int = 0
    responding_hop_count: int = 0
    silent_hop_count: int = 0
    private_hop_count: int = 0
    public_hop_count: int = 0
    destination_reached: bool = False
    confidence: RouteGraphConfidence = "unknown"


class RouteGraphNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    kind: RouteGraphNodeKind = "unknown"
    hop_index: int
    label: str
    ip: str | None = None
    asn: int | None = None
    as_name: str | None = None
    latency_ms: float | None = None
    is_private: bool = False
    is_silent: bool = False
    is_destination: bool = False
    confidence: RouteGraphConfidence = "unknown"
    badges: list[str] = Field(default_factory=list)
    evidence: list[dict[str, object]] = Field(default_factory=list)


class RouteGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: RouteGraphEdgeKind = "logical_next_hop"
    confidence: RouteGraphConfidence = "unknown"


class RouteGraphAdapterHints(BaseModel):
    preferred_layout: RouteGraphLayout = "left_to_right"
    supports_timeline_comparison: bool = False


class RouteGraphV1(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal["routegraph.v1"] = "routegraph.v1"
    graph_uid: str
    source: RouteGraphSource
    summary: RouteGraphSummary
    nodes: list[RouteGraphNode]
    edges: list[RouteGraphEdge]
    groups: list[dict[str, object]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    adapter_hints: RouteGraphAdapterHints = Field(default_factory=RouteGraphAdapterHints)
