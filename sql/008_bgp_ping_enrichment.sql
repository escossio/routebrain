CREATE OR REPLACE VIEW v_bgp_peer_with_latest_ping AS
SELECT
    ipm.observed_peer_ip,
    ipm.observed_peer_asn,
    ipm.observed_routes,
    ipm.observed_prefixes,
    ipm.inventory_peer_id,
    ipm.inventory_peer_name,
    ipm.inventory_connection_type,
    ipm.inventory_status,
    ipm.router_hostname,
    ipm.router_role,
    ipm.interface_name,
    ipm.interface_description,
    ipm.ixp_name,
    ipm.site_name,
    ipm.match_status,
    ap.status AS ping_status,
    ap.packets_sent,
    ap.packets_received,
    ap.packet_loss_percent,
    ap.rtt_min_ms,
    ap.rtt_avg_ms,
    ap.rtt_max_ms,
    ap.rtt_mdev_ms,
    ap.measured_at AS ping_measured_at
FROM v_bgp_peer_inventory_match ipm
LEFT JOIN v_active_ping_latest ap
    ON ipm.observed_peer_ip = ap.target;

CREATE OR REPLACE VIEW v_bgp_current_routes_with_ping AS
SELECT
    c.source,
    c.collector,
    c.peer_ip,
    c.peer_asn,
    c.prefix,
    c.next_hop,
    c.as_path,
    c.origin_asn,
    c.origin_type,
    c.first_seen,
    c.last_seen,
    c.inventory_peer_name,
    c.inventory_connection_type,
    c.inventory_peer_status,
    c.router_hostname,
    c.router_role,
    c.interface_name,
    c.interface_description,
    c.ixp_name,
    c.site_name,
    c.enrichment_status,
    ap.status AS ping_status,
    ap.packet_loss_percent,
    ap.rtt_avg_ms,
    ap.rtt_max_ms,
    ap.measured_at AS ping_measured_at
FROM v_bgp_current_routes_enriched c
LEFT JOIN v_active_ping_latest ap
    ON c.peer_ip = ap.target;

CREATE OR REPLACE VIEW v_bgp_route_changes_with_ping AS
SELECT
    rc.id,
    rc.detected_at,
    rc.source,
    rc.collector,
    rc.peer_ip,
    rc.peer_asn,
    rc.prefix,
    rc.change_type,
    rc.old_next_hop,
    rc.new_next_hop,
    rc.old_as_path,
    rc.new_as_path,
    rc.old_origin_asn,
    rc.new_origin_asn,
    rc.inventory_peer_name,
    rc.inventory_connection_type,
    rc.inventory_peer_status,
    rc.router_hostname,
    rc.router_role,
    rc.interface_name,
    rc.interface_description,
    rc.ixp_name,
    rc.site_name,
    rc.enrichment_status,
    ap.status AS ping_status,
    ap.packet_loss_percent,
    ap.rtt_avg_ms,
    ap.rtt_max_ms,
    ap.measured_at AS ping_measured_at
FROM v_bgp_route_changes_enriched rc
LEFT JOIN v_active_ping_latest ap
    ON rc.peer_ip = ap.target;

CREATE OR REPLACE VIEW v_bgp_ping_enrichment_summary AS
WITH peers AS (
    SELECT
        ipm.*,
        ap.status AS ping_status,
        ap.packet_loss_percent,
        ap.rtt_avg_ms
    FROM v_bgp_peer_inventory_match ipm
    LEFT JOIN v_active_ping_latest ap
        ON ipm.observed_peer_ip = ap.target
)
SELECT
    count(*) AS total_observed_peers,
    count(*) FILTER (WHERE ping_status IS NOT NULL) AS peers_with_ping,
    count(*) FILTER (WHERE ping_status IS NULL) AS peers_without_ping,
    count(*) FILTER (WHERE ping_status IS NOT NULL AND match_status = 'MATCHED') AS matched_peers_with_ping,
    count(*) FILTER (WHERE ping_status IS NOT NULL AND match_status = 'UNMATCHED') AS unmatched_peers_with_ping,
    round(avg(rtt_avg_ms), 3)::numeric(12,3) AS avg_rtt_avg_ms,
    round(max(rtt_avg_ms), 3)::numeric(12,3) AS max_rtt_avg_ms,
    round(avg(packet_loss_percent), 2)::numeric(6,2) AS avg_packet_loss_percent
FROM peers;
