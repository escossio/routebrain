CREATE OR REPLACE VIEW v_active_traceroute_hops_classified AS
SELECT
    h.measurement_id,
    h.target,
    m.target_label,
    m.measured_at,
    h.hop_number,
    h.hop_ip,
    h.responded,
    h.rtt_avg_ms,
    h.raw_line,
    CASE
        WHEN NOT h.responded OR h.hop_ip IS NULL THEN 'NO_RESPONSE'
        WHEN h.hop_ip << inet '10.0.0.0/8' THEN 'PRIVATE_10'
        WHEN h.hop_ip << inet '172.16.0.0/12' THEN 'PRIVATE_172_16'
        WHEN h.hop_ip << inet '192.168.0.0/16' THEN 'PRIVATE_192_168'
        WHEN h.hop_ip << inet '100.64.0.0/10' THEN 'CGNAT_100_64'
        WHEN h.hop_ip << inet '127.0.0.0/8' THEN 'LOOPBACK'
        WHEN h.hop_ip << inet '169.254.0.0/16' THEN 'LINK_LOCAL'
        WHEN h.hop_ip << inet '224.0.0.0/4' THEN 'MULTICAST'
        ELSE 'PUBLIC'
    END AS ip_scope,
    CASE
        WHEN NOT h.responded OR h.hop_ip IS NULL THEN false
        WHEN h.hop_ip << inet '10.0.0.0/8' THEN true
        WHEN h.hop_ip << inet '172.16.0.0/12' THEN true
        WHEN h.hop_ip << inet '192.168.0.0/16' THEN true
        WHEN h.hop_ip << inet '100.64.0.0/10' THEN true
        ELSE false
    END AS is_private,
    CASE
        WHEN NOT h.responded OR h.hop_ip IS NULL THEN false
        WHEN h.hop_ip << inet '10.0.0.0/8' THEN false
        WHEN h.hop_ip << inet '172.16.0.0/12' THEN false
        WHEN h.hop_ip << inet '192.168.0.0/16' THEN false
        WHEN h.hop_ip << inet '100.64.0.0/10' THEN false
        WHEN h.hop_ip << inet '127.0.0.0/8' THEN false
        WHEN h.hop_ip << inet '169.254.0.0/16' THEN false
        WHEN h.hop_ip << inet '224.0.0.0/4' THEN false
        ELSE true
    END AS is_public
FROM active_traceroute_hops h
JOIN active_traceroute_measurements m ON m.id = h.measurement_id;

CREATE OR REPLACE VIEW v_active_traceroute_hops_enriched AS
SELECT
    c.measurement_id,
    c.target,
    c.target_label,
    c.measured_at,
    c.hop_number,
    c.hop_ip,
    c.responded,
    c.rtt_avg_ms,
    c.raw_line,
    c.ip_scope,
    c.is_private,
    c.is_public,
    ni.id AS interface_id,
    ni.interface_name,
    ni.description AS interface_description,
    ni.interface_type,
    nr.id AS router_id,
    nr.hostname AS router_hostname,
    nr.role AS router_role,
    nr.management_ip AS router_management_ip,
    ns.name AS site_name,
    ns.city AS site_city,
    CASE
        WHEN c.ip_scope = 'NO_RESPONSE' THEN 'NO_RESPONSE'
        WHEN ni.id IS NOT NULL THEN 'MATCHED_INTERFACE'
        ELSE 'UNMATCHED'
    END AS inventory_match_status
FROM v_active_traceroute_hops_classified c
LEFT JOIN network_interfaces ni
    ON host(ni.ip_address) = host(c.hop_ip)
LEFT JOIN network_routers nr
    ON ni.router_id = nr.id
LEFT JOIN network_sites ns
    ON nr.site_id = ns.id;

CREATE OR REPLACE VIEW v_active_traceroute_latest_hops_enriched AS
WITH latest_measurements AS (
    SELECT measurement_id
    FROM v_active_traceroute_latest
)
SELECT
    e.measurement_id,
    e.target,
    e.target_label,
    e.measured_at,
    e.hop_number,
    e.hop_ip,
    e.responded,
    e.rtt_avg_ms,
    e.raw_line,
    e.ip_scope,
    e.is_private,
    e.is_public,
    e.interface_id,
    e.interface_name,
    e.interface_description,
    e.interface_type,
    e.router_id,
    e.router_hostname,
    e.router_role,
    e.router_management_ip,
    e.site_name,
    e.site_city,
    e.inventory_match_status
FROM v_active_traceroute_hops_enriched e
JOIN latest_measurements lm ON lm.measurement_id = e.measurement_id
ORDER BY e.target, e.hop_number;

CREATE OR REPLACE VIEW v_active_traceroute_hop_summary AS
SELECT
    count(*) AS total_hops,
    count(*) FILTER (WHERE responded) AS responded_hops,
    count(*) FILTER (WHERE inventory_match_status = 'NO_RESPONSE') AS no_response_hops,
    count(*) FILTER (WHERE ip_scope = 'PUBLIC') AS public_hops,
    count(*) FILTER (WHERE is_private) AS private_hops,
    count(*) FILTER (WHERE ip_scope = 'CGNAT_100_64') AS cgnat_hops,
    count(*) FILTER (WHERE inventory_match_status = 'MATCHED_INTERFACE') AS matched_interface_hops,
    count(*) FILTER (WHERE inventory_match_status = 'UNMATCHED') AS unmatched_hops,
    count(DISTINCT target) AS distinct_targets,
    count(DISTINCT hop_ip) AS distinct_hop_ips
FROM v_active_traceroute_hops_enriched;

CREATE OR REPLACE VIEW v_active_traceroute_top_unmatched_private_hops AS
SELECT
    hop_ip,
    ip_scope,
    count(*) AS occurrences,
    count(DISTINCT target) AS distinct_targets,
    avg(rtt_avg_ms)::numeric(12,3) AS avg_rtt_avg_ms,
    min(measured_at) AS first_seen,
    max(measured_at) AS last_seen
FROM v_active_traceroute_hops_enriched
WHERE is_private = true
  AND inventory_match_status = 'UNMATCHED'
  AND hop_ip IS NOT NULL
GROUP BY hop_ip, ip_scope;
