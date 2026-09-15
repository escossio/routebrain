CREATE OR REPLACE VIEW v_bgp_change_summary AS
SELECT
    count(*) AS total_changes,
    count(DISTINCT prefix) AS total_prefixes_changed,
    count(DISTINCT peer_ip) AS total_peers_affected,
    count(DISTINCT collector) AS total_collectors,
    min(detected_at) AS first_change_at,
    max(detected_at) AS last_change_at
FROM bgp_route_changes;

CREATE OR REPLACE VIEW v_bgp_changes_by_type AS
SELECT
    change_type,
    count(*) AS total_changes
FROM bgp_route_changes
GROUP BY change_type;

CREATE OR REPLACE VIEW v_bgp_top_changed_prefixes AS
SELECT
    prefix,
    count(*) AS total_changes,
    min(detected_at) AS first_change_at,
    max(detected_at) AS last_change_at
FROM bgp_route_changes
GROUP BY prefix;

CREATE OR REPLACE VIEW v_bgp_top_changed_peers AS
SELECT
    peer_ip,
    peer_asn,
    count(*) AS total_changes,
    min(detected_at) AS first_change_at,
    max(detected_at) AS last_change_at
FROM bgp_route_changes
GROUP BY peer_ip, peer_asn;

CREATE OR REPLACE VIEW v_bgp_latest_changes AS
SELECT
    id,
    detected_at,
    source,
    collector,
    peer_ip,
    peer_asn,
    prefix,
    change_type,
    old_next_hop,
    new_next_hop,
    old_as_path,
    new_as_path,
    old_origin_asn,
    new_origin_asn
FROM bgp_route_changes;

CREATE OR REPLACE VIEW v_bgp_current_summary AS
SELECT
    count(*) AS total_current_routes,
    count(DISTINCT prefix) AS total_prefixes,
    count(DISTINCT peer_ip) AS total_peers,
    count(DISTINCT peer_asn) AS total_peer_asns,
    count(DISTINCT origin_asn) AS total_origin_asns,
    count(DISTINCT collector) AS total_collectors,
    min(first_seen) AS first_seen_min,
    max(last_seen) AS last_seen_max
FROM bgp_current_routes;

CREATE OR REPLACE VIEW v_bgp_current_by_origin_asn AS
SELECT
    origin_asn,
    count(*) AS total_routes,
    count(DISTINCT prefix) AS total_prefixes,
    count(DISTINCT peer_ip) AS total_peers,
    min(first_seen) AS first_seen_min,
    max(last_seen) AS last_seen_max
FROM bgp_current_routes
GROUP BY origin_asn;

CREATE OR REPLACE VIEW v_bgp_current_by_peer AS
SELECT
    peer_ip,
    peer_asn,
    count(*) AS total_routes,
    count(DISTINCT prefix) AS total_prefixes,
    count(DISTINCT origin_asn) AS total_origin_asns,
    min(first_seen) AS first_seen_min,
    max(last_seen) AS last_seen_max
FROM bgp_current_routes
GROUP BY peer_ip, peer_asn;
