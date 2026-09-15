-- Summaries operacionais BGP.
-- Idempotente: pode ser reaplicado sem destruir dados brutos.

CREATE TABLE IF NOT EXISTS bgp_summary_current_by_peer (
    peer_ip inet,
    peer_asn bigint,
    route_count bigint NOT NULL,
    prefix_count bigint NOT NULL,
    origin_asn_count bigint NOT NULL,
    collector_count bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_summary_current_by_peer_peer_ip
    ON bgp_summary_current_by_peer (peer_ip);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_current_by_peer_route_count_desc
    ON bgp_summary_current_by_peer (route_count DESC, peer_ip);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_current_by_peer_prefix_count_desc
    ON bgp_summary_current_by_peer (prefix_count DESC, peer_ip);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_current_by_peer_peer_asn
    ON bgp_summary_current_by_peer (peer_asn);

CREATE TABLE IF NOT EXISTS bgp_summary_current_by_origin_asn (
    origin_asn bigint,
    route_count bigint NOT NULL,
    prefix_count bigint NOT NULL,
    peer_count bigint NOT NULL,
    collector_count bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_summary_current_by_origin_asn_origin_asn
    ON bgp_summary_current_by_origin_asn (origin_asn);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_current_by_origin_asn_route_count_desc
    ON bgp_summary_current_by_origin_asn (route_count DESC, origin_asn);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_current_by_origin_asn_prefix_count_desc
    ON bgp_summary_current_by_origin_asn (prefix_count DESC, origin_asn);

CREATE TABLE IF NOT EXISTS bgp_summary_changes_by_prefix (
    prefix cidr,
    total_changes bigint NOT NULL,
    new_route_count bigint NOT NULL,
    as_path_changed_count bigint NOT NULL,
    origin_type_changed_count bigint NOT NULL,
    first_change_at timestamptz,
    last_change_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_prefix_prefix
    ON bgp_summary_changes_by_prefix (prefix);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_prefix_total_changes_desc
    ON bgp_summary_changes_by_prefix (total_changes DESC, last_change_at DESC, prefix);

CREATE TABLE IF NOT EXISTS bgp_summary_changes_by_origin_asn (
    origin_asn bigint,
    total_changes bigint NOT NULL,
    new_route_count bigint NOT NULL,
    as_path_changed_count bigint NOT NULL,
    origin_type_changed_count bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_origin_asn_origin_asn
    ON bgp_summary_changes_by_origin_asn (origin_asn);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_origin_asn_total_changes_desc
    ON bgp_summary_changes_by_origin_asn (total_changes DESC, origin_asn);

CREATE TABLE IF NOT EXISTS bgp_summary_changes_by_peer (
    peer_ip inet,
    peer_asn bigint,
    total_changes bigint NOT NULL,
    new_route_count bigint NOT NULL,
    as_path_changed_count bigint NOT NULL,
    origin_type_changed_count bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_peer_peer_ip_peer_asn
    ON bgp_summary_changes_by_peer (peer_ip, peer_asn);

CREATE INDEX IF NOT EXISTS idx_bgp_summary_changes_by_peer_total_changes_desc
    ON bgp_summary_changes_by_peer (total_changes DESC, peer_ip, peer_asn);
