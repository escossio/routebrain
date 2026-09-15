CREATE OR REPLACE VIEW v_bgp_peer_inventory_match AS
WITH observed_peers AS (
    SELECT
        peer_ip,
        peer_asn,
        count(*) AS observed_routes,
        count(DISTINCT prefix) AS observed_prefixes
    FROM bgp_current_routes
    GROUP BY peer_ip, peer_asn
)
SELECT
    op.peer_ip AS observed_peer_ip,
    op.peer_asn AS observed_peer_asn,
    op.observed_routes,
    op.observed_prefixes,
    inv.id AS inventory_peer_id,
    inv.peer_name AS inventory_peer_name,
    inv.connection_type AS inventory_connection_type,
    inv.status AS inventory_status,
    r.hostname AS router_hostname,
    r.role AS router_role,
    i.interface_name AS interface_name,
    i.description AS interface_description,
    ix.name AS ixp_name,
    s.name AS site_name,
    CASE
        WHEN inv.id IS NULL THEN 'UNMATCHED'
        ELSE 'MATCHED'
    END AS match_status
FROM observed_peers op
LEFT JOIN LATERAL (
    SELECT
        p.id,
        p.peer_name,
        p.connection_type,
        p.status,
        p.router_id,
        p.interface_id,
        p.ixp_id
    FROM network_bgp_peers p
    WHERE p.peer_ip = op.peer_ip
    ORDER BY
        CASE
            WHEN p.peer_asn = op.peer_asn THEN 0
            ELSE 1
        END,
        p.id
    LIMIT 1
) inv ON TRUE
LEFT JOIN network_routers r
    ON r.id = inv.router_id
LEFT JOIN network_interfaces i
    ON i.id = inv.interface_id
LEFT JOIN network_ixps ix
    ON ix.id = inv.ixp_id
LEFT JOIN network_sites s
    ON s.id = r.site_id;

CREATE OR REPLACE VIEW v_bgp_current_routes_enriched AS
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
    inv.peer_name AS inventory_peer_name,
    inv.connection_type AS inventory_connection_type,
    inv.status AS inventory_peer_status,
    r.hostname AS router_hostname,
    r.role AS router_role,
    i.interface_name AS interface_name,
    i.description AS interface_description,
    ix.name AS ixp_name,
    s.name AS site_name,
    CASE
        WHEN inv.id IS NULL THEN 'UNMATCHED'
        ELSE 'MATCHED'
    END AS enrichment_status
FROM bgp_current_routes c
LEFT JOIN LATERAL (
    SELECT
        p.id,
        p.peer_name,
        p.connection_type,
        p.status,
        p.router_id,
        p.interface_id,
        p.ixp_id
    FROM network_bgp_peers p
    WHERE p.peer_ip = c.peer_ip
    ORDER BY
        CASE
            WHEN p.peer_asn = c.peer_asn THEN 0
            ELSE 1
        END,
        p.id
    LIMIT 1
) inv ON TRUE
LEFT JOIN network_routers r
    ON r.id = inv.router_id
LEFT JOIN network_interfaces i
    ON i.id = inv.interface_id
LEFT JOIN network_ixps ix
    ON ix.id = inv.ixp_id
LEFT JOIN network_sites s
    ON s.id = r.site_id;

CREATE OR REPLACE VIEW v_bgp_route_changes_enriched AS
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
    inv.peer_name AS inventory_peer_name,
    inv.connection_type AS inventory_connection_type,
    inv.status AS inventory_peer_status,
    r.hostname AS router_hostname,
    r.role AS router_role,
    i.interface_name AS interface_name,
    i.description AS interface_description,
    ix.name AS ixp_name,
    s.name AS site_name,
    CASE
        WHEN inv.id IS NULL THEN 'UNMATCHED'
        ELSE 'MATCHED'
    END AS enrichment_status
FROM bgp_route_changes rc
LEFT JOIN LATERAL (
    SELECT
        p.id,
        p.peer_name,
        p.connection_type,
        p.status,
        p.router_id,
        p.interface_id,
        p.ixp_id
    FROM network_bgp_peers p
    WHERE p.peer_ip = rc.peer_ip
    ORDER BY
        CASE
            WHEN p.peer_asn = rc.peer_asn THEN 0
            ELSE 1
        END,
        p.id
    LIMIT 1
) inv ON TRUE
LEFT JOIN network_routers r
    ON r.id = inv.router_id
LEFT JOIN network_interfaces i
    ON i.id = inv.interface_id
LEFT JOIN network_ixps ix
    ON ix.id = inv.ixp_id
LEFT JOIN network_sites s
    ON s.id = r.site_id;

CREATE OR REPLACE VIEW v_bgp_enrichment_summary AS
WITH current_peer_counts AS (
    SELECT *
    FROM v_bgp_peer_inventory_match
),
current_route_counts AS (
    SELECT *
    FROM v_bgp_current_routes_enriched
),
change_counts AS (
    SELECT *
    FROM v_bgp_route_changes_enriched
)
SELECT
    (SELECT count(*) FROM current_peer_counts) AS total_current_peers,
    (SELECT count(*) FROM current_peer_counts WHERE match_status = 'MATCHED') AS matched_current_peers,
    (SELECT count(*) FROM current_peer_counts WHERE match_status = 'UNMATCHED') AS unmatched_current_peers,
    (SELECT count(*) FROM current_route_counts) AS total_current_routes,
    (SELECT count(*) FROM current_route_counts WHERE enrichment_status = 'MATCHED') AS matched_current_routes,
    (SELECT count(*) FROM current_route_counts WHERE enrichment_status = 'UNMATCHED') AS unmatched_current_routes,
    (SELECT count(*) FROM change_counts) AS total_changes,
    (SELECT count(*) FROM change_counts WHERE enrichment_status = 'MATCHED') AS matched_changes,
    (SELECT count(*) FROM change_counts WHERE enrichment_status = 'UNMATCHED') AS unmatched_changes;
