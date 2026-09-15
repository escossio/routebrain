BEGIN;

CREATE TABLE IF NOT EXISTS route_memory_observations (
    id bigserial PRIMARY KEY,
    observation_uid text UNIQUE NOT NULL,
    source_node text NOT NULL,
    target text,
    resolved_ip inet,
    tool text,
    observed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    route_memory_version text,
    knowledge_status text,
    route_known_fraction numeric,
    summary text,
    raw_input_ref jsonb,
    report_json jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_route_memory_observations_source_node ON route_memory_observations (source_node);
CREATE INDEX IF NOT EXISTS idx_route_memory_observations_target ON route_memory_observations (target);
CREATE INDEX IF NOT EXISTS idx_route_memory_observations_resolved_ip ON route_memory_observations (resolved_ip);
CREATE INDEX IF NOT EXISTS idx_route_memory_observations_observed_at ON route_memory_observations (observed_at);
CREATE INDEX IF NOT EXISTS idx_route_memory_observations_created_at ON route_memory_observations (created_at);
CREATE INDEX IF NOT EXISTS idx_route_memory_observations_knowledge_status ON route_memory_observations (knowledge_status);

CREATE TABLE IF NOT EXISTS route_memory_hop_facts (
    id bigserial PRIMARY KEY,
    observation_uid text NOT NULL REFERENCES route_memory_observations(observation_uid) ON DELETE CASCADE,
    hop_index integer NOT NULL,
    ip inet,
    raw_host text,
    hop_type text,
    is_silent boolean NOT NULL DEFAULT false,
    is_private boolean NOT NULL DEFAULT false,
    is_public boolean NOT NULL DEFAULT false,
    is_destination boolean NOT NULL DEFAULT false,
    loss_percent numeric,
    avg_ms numeric,
    reverse_dns text,
    rdns_domain text,
    bgp_prefix cidr,
    origin_asn integer,
    as_path text,
    confidence text,
    evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_route_memory_hop_facts_observation_uid ON route_memory_hop_facts (observation_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_hop_facts_ip ON route_memory_hop_facts (ip);
CREATE INDEX IF NOT EXISTS idx_route_memory_hop_facts_origin_asn ON route_memory_hop_facts (origin_asn);
CREATE INDEX IF NOT EXISTS idx_route_memory_hop_facts_hop_type ON route_memory_hop_facts (hop_type);
CREATE INDEX IF NOT EXISTS idx_route_memory_hop_facts_is_destination ON route_memory_hop_facts (is_destination);

CREATE TABLE IF NOT EXISTS route_memory_segments_observed (
    id bigserial PRIMARY KEY,
    observed_segment_uid text UNIQUE NOT NULL,
    observation_uid text NOT NULL REFERENCES route_memory_observations(observation_uid) ON DELETE CASCADE,
    source_node text NOT NULL,
    segment_index integer NOT NULL,
    segment_type text NOT NULL,
    start_hop integer,
    end_hop integer,
    hop_count integer,
    contains_private boolean NOT NULL DEFAULT false,
    contains_public boolean NOT NULL DEFAULT false,
    contains_silent boolean NOT NULL DEFAULT false,
    contains_mpls boolean NOT NULL DEFAULT false,
    context_asn integer,
    first_public_asn integer,
    last_public_asn integer,
    next_public_asn integer,
    previous_public_asn integer,
    rdns_signature text,
    exact_fingerprint text,
    structural_fingerprint text,
    confidence text,
    state text NOT NULL DEFAULT 'observed',
    human_summary text,
    evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_observation_uid ON route_memory_segments_observed (observation_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_source_node ON route_memory_segments_observed (source_node);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_segment_type ON route_memory_segments_observed (segment_type);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_context_asn ON route_memory_segments_observed (context_asn);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_structural_fingerprint ON route_memory_segments_observed (structural_fingerprint);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_exact_fingerprint ON route_memory_segments_observed (exact_fingerprint);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_state ON route_memory_segments_observed (state);
CREATE INDEX IF NOT EXISTS idx_route_memory_segments_observed_created_at ON route_memory_segments_observed (created_at);

CREATE TABLE IF NOT EXISTS route_memory_segment_matches (
    id bigserial PRIMARY KEY,
    match_uid text UNIQUE NOT NULL,
    observation_uid text NOT NULL REFERENCES route_memory_observations(observation_uid) ON DELETE CASCADE,
    observed_segment_uid text NOT NULL REFERENCES route_memory_segments_observed(observed_segment_uid) ON DELETE CASCADE,
    matched_observed_segment_uid text,
    matched_known_segment_uid text,
    match_type text,
    match_score numeric,
    matched_hops_count integer,
    divergence_hop integer,
    divergence_type text,
    decision text,
    confidence text,
    evidence jsonb,
    explanation text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_observation_uid ON route_memory_segment_matches (observation_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_observed_segment_uid ON route_memory_segment_matches (observed_segment_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_matched_observed_segment_uid ON route_memory_segment_matches (matched_observed_segment_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_match_type ON route_memory_segment_matches (match_type);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_divergence_type ON route_memory_segment_matches (divergence_type);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_decision ON route_memory_segment_matches (decision);
CREATE INDEX IF NOT EXISTS idx_route_memory_segment_matches_match_score ON route_memory_segment_matches (match_score);

CREATE TABLE IF NOT EXISTS route_memory_events (
    id bigserial PRIMARY KEY,
    event_uid text UNIQUE NOT NULL,
    source_node text NOT NULL,
    observation_uid text REFERENCES route_memory_observations(observation_uid) ON DELETE SET NULL,
    observed_segment_uid text REFERENCES route_memory_segments_observed(observed_segment_uid) ON DELETE SET NULL,
    event_type text NOT NULL,
    severity text,
    old_value jsonb,
    new_value jsonb,
    explanation text,
    evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_route_memory_events_source_node ON route_memory_events (source_node);
CREATE INDEX IF NOT EXISTS idx_route_memory_events_observation_uid ON route_memory_events (observation_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_events_observed_segment_uid ON route_memory_events (observed_segment_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_events_event_type ON route_memory_events (event_type);
CREATE INDEX IF NOT EXISTS idx_route_memory_events_severity ON route_memory_events (severity);
CREATE INDEX IF NOT EXISTS idx_route_memory_events_created_at ON route_memory_events (created_at);

CREATE TABLE IF NOT EXISTS route_memory_graph_snapshots (
    id bigserial PRIMARY KEY,
    graph_uid text UNIQUE NOT NULL,
    source_node text NOT NULL,
    title text,
    graph_type text NOT NULL DEFAULT 'route_memory_graph',
    route_count integer,
    observation_uids text[] NOT NULL,
    schema_version text NOT NULL,
    payload_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_route_memory_graph_snapshots_source_node ON route_memory_graph_snapshots (source_node);
CREATE INDEX IF NOT EXISTS idx_route_memory_graph_snapshots_graph_uid ON route_memory_graph_snapshots (graph_uid);
CREATE INDEX IF NOT EXISTS idx_route_memory_graph_snapshots_created_at ON route_memory_graph_snapshots (created_at);
CREATE INDEX IF NOT EXISTS idx_route_memory_graph_snapshots_observation_uids ON route_memory_graph_snapshots USING gin (observation_uids);
CREATE INDEX IF NOT EXISTS idx_route_memory_graph_snapshots_payload_json ON route_memory_graph_snapshots USING gin (payload_json);

COMMIT;
