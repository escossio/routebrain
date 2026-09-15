CREATE TABLE IF NOT EXISTS inventory_discovery_runs (
    id bigserial PRIMARY KEY,
    run_uid text UNIQUE NOT NULL,
    source text NOT NULL,
    mode text NOT NULL,
    status text NOT NULL,
    started_at timestamptz DEFAULT now(),
    finished_at timestamptz,
    raw_seen integer DEFAULT 0,
    candidates_seen integer DEFAULT 0,
    inserted integer DEFAULT 0,
    updated integer DEFAULT 0,
    skipped integer DEFAULT 0,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    CHECK (source IN ('mikrotik', 'manual', 'traceroute', 'system')),
    CHECK (mode IN ('dry_run', 'collect')),
    CHECK (status IN ('running', 'ok', 'partial', 'error'))
);

CREATE TABLE IF NOT EXISTS inventory_host_candidates (
    id bigserial PRIMARY KEY,
    candidate_uid text UNIQUE NOT NULL,
    first_seen_at timestamptz DEFAULT now(),
    last_seen_at timestamptz DEFAULT now(),
    source text NOT NULL,
    source_detail text,
    ip inet,
    mac text,
    hostname text,
    interface_name text,
    interface_mac text,
    vlan text,
    site_code text,
    vendor text,
    device_type text,
    confidence numeric DEFAULT 0,
    confidence_reason jsonb DEFAULT '[]'::jsonb,
    status text DEFAULT 'candidate',
    promoted_host_id bigint REFERENCES inventory_hosts(id) ON DELETE SET NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    CHECK (status IN ('candidate', 'promoted', 'ignored', 'merged'))
);

CREATE TABLE IF NOT EXISTS inventory_host_candidate_evidence (
    id bigserial PRIMARY KEY,
    candidate_uid text NOT NULL,
    run_uid text NOT NULL,
    evidence_type text NOT NULL,
    observed_at timestamptz DEFAULT now(),
    ip inet,
    mac text,
    hostname text,
    interface_name text,
    raw_summary jsonb DEFAULT '{}'::jsonb,
    CHECK (evidence_type IN ('arp', 'dhcp_lease', 'dns_cache', 'bridge_host', 'neighbor', 'interface', 'traceroute_hop', 'manual'))
);

CREATE INDEX IF NOT EXISTS idx_inventory_discovery_runs_started_at
    ON inventory_discovery_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidates_ip
    ON inventory_host_candidates (ip);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidates_mac
    ON inventory_host_candidates (mac);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidates_hostname
    ON inventory_host_candidates (hostname);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidates_status
    ON inventory_host_candidates (status);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidate_evidence_candidate_uid
    ON inventory_host_candidate_evidence (candidate_uid);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidate_evidence_run_uid
    ON inventory_host_candidate_evidence (run_uid);

CREATE INDEX IF NOT EXISTS idx_inventory_host_candidate_evidence_observed_at
    ON inventory_host_candidate_evidence (observed_at DESC);
