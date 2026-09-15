CREATE TABLE IF NOT EXISTS bgp_raw_routes (
    id bigserial PRIMARY KEY,
    source text NOT NULL,
    collector text,
    collected_at timestamptz,
    peer_ip inet,
    peer_asn bigint,
    prefix cidr,
    next_hop inet,
    as_path text,
    origin_asn bigint,
    origin_type text,
    med bigint,
    local_pref bigint,
    communities text,
    raw_record jsonb,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bgp_current_routes (
    source text NOT NULL,
    collector text NOT NULL,
    peer_ip inet NOT NULL,
    prefix cidr NOT NULL,
    peer_asn bigint,
    next_hop inet,
    as_path text,
    origin_asn bigint,
    origin_type text,
    first_seen timestamptz,
    last_seen timestamptz,
    raw_record jsonb,
    PRIMARY KEY (source, collector, peer_ip, prefix)
);

CREATE TABLE IF NOT EXISTS bgp_route_changes (
    id bigserial PRIMARY KEY,
    source text NOT NULL,
    collector text,
    peer_ip inet,
    peer_asn bigint,
    prefix cidr,
    change_type text NOT NULL,
    old_next_hop inet,
    new_next_hop inet,
    old_as_path text,
    new_as_path text,
    old_origin_asn bigint,
    new_origin_asn bigint,
    detected_at timestamptz DEFAULT now(),
    raw_before jsonb,
    raw_after jsonb
);

CREATE INDEX IF NOT EXISTS idx_bgp_raw_routes_prefix
    ON bgp_raw_routes (prefix);

CREATE INDEX IF NOT EXISTS idx_bgp_raw_routes_origin_asn
    ON bgp_raw_routes (origin_asn);

CREATE INDEX IF NOT EXISTS idx_bgp_raw_routes_collected_at
    ON bgp_raw_routes (collected_at);

CREATE INDEX IF NOT EXISTS idx_bgp_route_changes_prefix
    ON bgp_route_changes (prefix);

CREATE INDEX IF NOT EXISTS idx_bgp_route_changes_detected_at
    ON bgp_route_changes (detected_at);

CREATE INDEX IF NOT EXISTS idx_bgp_current_routes_origin_asn
    ON bgp_current_routes (origin_asn);
