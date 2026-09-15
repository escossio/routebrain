from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    status: str
    service: str


class ChangeSummary(BaseModel):
    total_changes: int | None = None
    total_prefixes_changed: int | None = None
    total_peers_affected: int | None = None
    total_collectors: int | None = None
    first_change_at: datetime | None = None
    last_change_at: datetime | None = None


class CurrentSummary(BaseModel):
    total_current_routes: int | None = None
    total_prefixes: int | None = None
    total_peers: int | None = None
    total_peer_asns: int | None = None
    total_origin_asns: int | None = None
    total_collectors: int | None = None
    first_seen_min: datetime | None = None
    last_seen_max: datetime | None = None


class TracerouteHopSummary(BaseModel):
    total_hops: int | None = None
    responded_hops: int | None = None
    no_response_hops: int | None = None
    public_hops: int | None = None
    private_hops: int | None = None
    cgnat_hops: int | None = None
    matched_interface_hops: int | None = None
    unmatched_hops: int | None = None
    distinct_targets: int | None = None
    distinct_hop_ips: int | None = None


class TracerouteClassificationSummary(BaseModel):
    total_hops: int | None = None
    no_response_hops: int | None = None
    matched_interface_hops: int | None = None
    classified_hops: int | None = None
    unmatched_hops: int | None = None
    private_unmatched_hops: int | None = None
    private_classified_hops: int | None = None
    distinct_classified_hop_ips: int | None = None
    distinct_unmatched_hop_ips: int | None = None


class EnrichmentSummary(BaseModel):
    total_current_peers: int | None = None
    matched_current_peers: int | None = None
    unmatched_current_peers: int | None = None
    total_current_routes: int | None = None
    matched_current_routes: int | None = None
    unmatched_current_routes: int | None = None
    total_changes: int | None = None
    matched_changes: int | None = None
    unmatched_changes: int | None = None


class PingLatestItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str | None = None
    target_label: str | None = None
    source_label: str | None = None
    packets_sent: int | None = None
    packets_received: int | None = None
    packet_loss_percent: float | None = None
    rtt_min_ms: float | None = None
    rtt_avg_ms: float | None = None
    rtt_max_ms: float | None = None
    rtt_mdev_ms: float | None = None
    status: str | None = None
    measured_at: datetime | None = None


class PingSummaryItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    target: str | None = None
    total_measurements: int | None = None
    successful_measurements: int | None = None
    failed_measurements: int | None = None
    avg_packet_loss_percent: float | None = None
    avg_rtt_avg_ms: float | None = None
    min_rtt_avg_ms: float | None = None
    max_rtt_avg_ms: float | None = None
    first_measured_at: datetime | None = None
    last_measured_at: datetime | None = None


class PingEnrichmentSummary(BaseModel):
    total_observed_peers: int | None = None
    peers_with_ping: int | None = None
    peers_without_ping: int | None = None
    matched_peers_with_ping: int | None = None
    unmatched_peers_with_ping: int | None = None
    avg_rtt_avg_ms: float | None = None
    max_rtt_avg_ms: float | None = None
    avg_packet_loss_percent: float | None = None


class SyntheticSummary(BaseModel):
    synthetic_browser_runs_count: int | None = None
    synthetic_browser_hosts_count: int | None = None
    synthetic_browser_ip_measurements_count: int | None = None
    latest_synthetic_run_id: int | None = None
    latest_synthetic_url: str | None = None
    latest_synthetic_analyzed_at: datetime | None = None
    latest_synthetic_total_ips_measured: int | None = None
    latest_synthetic_ping_success: int | None = None
    latest_synthetic_avg_rtt_avg_ms: float | None = None
    latest_synthetic_traceroute_success: int | None = None
    latest_synthetic_ips_with_bgp_match: int | None = None


class SummaryResponse(BaseModel):
    bgp_raw_routes: int
    bgp_current_routes: int
    bgp_route_changes: int
    enrichment_summary: EnrichmentSummary
    current_summary: CurrentSummary
    change_summary: ChangeSummary
    ping_enrichment_summary: PingEnrichmentSummary | None = None
    active_ping_count: int | None = None
    active_traceroute_measurement_count: int | None = None
    active_traceroute_hop_count: int | None = None
    traceroute_summary_count_targets: int | None = None
    traceroute_hop_summary: TracerouteHopSummary | None = None
    traceroute_classification_summary: TracerouteClassificationSummary | None = None
    synthetic_summary: SyntheticSummary | None = None


class ExternalRoutesIngestRequest(BaseModel):
    dry_run: bool = True


class ExternalRoutesEnrichRequest(BaseModel):
    limit: int = 100


class ExternalRoutesTraceRequest(BaseModel):
    confirm: bool = False
    target_override: str | None = None
    max_hops: int = 20


class RouteLearningCloudflareDedicatedRunRequest(BaseModel):
    confirm: bool = False
    plan_uid: str
    target: str
    ip_family: str | None = None


class LatestChangeItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    detected_at: datetime | None = None
    source: str | None = None
    collector: str | None = None
    peer_ip: str | None = None
    peer_asn: int | None = None
    prefix: str | None = None
    change_type: str | None = None
    old_as_path: str | None = None
    new_as_path: str | None = None
    old_next_hop: str | None = None
    new_next_hop: str | None = None
    old_origin_asn: int | None = None
    new_origin_asn: int | None = None
    inventory_peer_name: str | None = None
    inventory_connection_type: str | None = None
    ixp_name: str | None = None
    router_hostname: str | None = None
    enrichment_status: str | None = None


class PeerInventoryItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    observed_peer_ip: str | None = None
    observed_peer_asn: int | None = None
    observed_routes: int | None = None
    observed_prefixes: int | None = None
    inventory_peer_name: str | None = None
    inventory_connection_type: str | None = None
    inventory_status: str | None = None
    router_hostname: str | None = None
    ixp_name: str | None = None
    site_name: str | None = None
    match_status: str | None = None


class PrefixSearchItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    prefix: str | None = None
    peer_ip: str | None = None
    peer_asn: int | None = None
    as_path: str | None = None
    origin_asn: int | None = None
    inventory_peer_name: str | None = None
    inventory_connection_type: str | None = None
    ixp_name: str | None = None
    enrichment_status: str | None = None


class PeerSummaryItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    observed_peer_ip: str | None = None
    observed_peer_asn: int | None = None
    observed_routes: int | None = None
    observed_prefixes: int | None = None
    inventory_peer_name: str | None = None
    inventory_connection_type: str | None = None
    inventory_status: str | None = None
    router_hostname: str | None = None
    router_role: str | None = None
    interface_name: str | None = None
    interface_description: str | None = None
    ixp_name: str | None = None
    site_name: str | None = None
    match_status: str | None = None


class LearningRequestCreate(BaseModel):
    question: str
    operator: str | None = None
    dry_run: bool = True


class QuestionAskRequest(BaseModel):
    question: str
    compact: bool = True
    operator: str | None = None


class QuestionExecuteActiveRequest(BaseModel):
    confirm: bool = False


class QuestionActionRequest(BaseModel):
    confirm: bool = False
    target_override: str | None = None
    asn: int | None = None
    label: str | None = None
    max_duration_seconds: int | None = None


class QuestionSpeechRequest(BaseModel):
    provider: str | None = None
    voice: str | None = None
    language: str | None = None
    text_mode: str = "answer"


class QuestionSpeechResponse(BaseModel):
    request_uid: str
    status: str
    tts_enabled: bool
    provider: str | None = None
    language: str | None = None
    voice: str | None = None
    audio_url: str | None = None
    audio_source_url: str | None = None
    filename: str | None = None
    audio_mime_type: str | None = None
    text_length: int | None = None
    message: str | None = None
    truncated: bool | None = None


class InventoryDiscoveryCollectRequest(BaseModel):
    source: str = "mikrotik"
    dry_run: bool = True
    limit: int | None = 500


class InventoryCandidatePromoteRequest(BaseModel):
    confirm: bool = False
    site_code: str | None = None


class InventoryCandidateIgnoreRequest(BaseModel):
    confirm: bool = False
    reason: str | None = None


class LearningRequestExecute(BaseModel):
    dry_run: bool = True
    allow_safe_tasks: bool = True
    allow_active_measurements: bool = False
    force_refresh: bool = False


class LearningRequestEnrich(BaseModel):
    force_refresh: bool = False
    allow_external: bool = True


class SemanticRebuildRequest(BaseModel):
    scope: str = "all"
    dry_run: bool = False
    limit: int | None = None
    skip_existing: bool = True
    force: bool = False
