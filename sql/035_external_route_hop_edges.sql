CREATE TABLE IF NOT EXISTS external_route_traceroute_runs (
    run_uid text PRIMARY KEY,
    service_uid text NOT NULL,
    target_uid text,
    target_host text,
    target_resolved_ip inet,
    target_source text NOT NULL DEFAULT 'service_target',
    target_selection_reason text,
    status text NOT NULL DEFAULT 'running',
    max_hops integer NOT NULL DEFAULT 20,
    hop_count integer NOT NULL DEFAULT 0,
    unknown_count integer NOT NULL DEFAULT 0,
    edge_count integer NOT NULL DEFAULT 0,
    graph_available boolean NOT NULL DEFAULT false,
    graph_url text,
    requested_by_role text,
    requested_by_username text,
    observed_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (run_uid <> ''),
    CHECK (service_uid <> ''),
    CHECK (status <> ''),
    CHECK (target_source <> '')
);

CREATE TABLE IF NOT EXISTS external_route_hop_edges (
    edge_uid text PRIMARY KEY,
    service_uid text NOT NULL,
    target_uid text,
    traceroute_run_ref text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    from_hop_ip inet,
    from_hop_index integer,
    to_hop_ip inet,
    to_hop_index integer,
    from_ip_type text NOT NULL DEFAULT 'unknown',
    to_ip_type text NOT NULL DEFAULT 'unknown',
    rtt_delta_ms numeric(10,3),
    transition_type text NOT NULL DEFAULT 'unknown_transition',
    confidence text NOT NULL DEFAULT 'unknown',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (edge_uid <> ''),
    CHECK (service_uid <> ''),
    CHECK (traceroute_run_ref <> ''),
    CHECK (from_ip_type <> ''),
    CHECK (to_ip_type <> ''),
    CHECK (transition_type <> ''),
    CHECK (confidence <> '')
);

CREATE INDEX IF NOT EXISTS idx_external_route_traceroute_runs_service_uid
    ON external_route_traceroute_runs (service_uid);

CREATE INDEX IF NOT EXISTS idx_external_route_traceroute_runs_target_uid
    ON external_route_traceroute_runs (target_uid);

CREATE INDEX IF NOT EXISTS idx_external_route_traceroute_runs_observed_at
    ON external_route_traceroute_runs (observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_service_uid
    ON external_route_hop_edges (service_uid);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_target_uid
    ON external_route_hop_edges (target_uid);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_traceroute_run_ref
    ON external_route_hop_edges (traceroute_run_ref);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_from_hop_ip
    ON external_route_hop_edges (from_hop_ip);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_to_hop_ip
    ON external_route_hop_edges (to_hop_ip);

CREATE INDEX IF NOT EXISTS idx_external_route_hop_edges_transition_type
    ON external_route_hop_edges (transition_type);
