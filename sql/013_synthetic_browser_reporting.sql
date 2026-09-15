DROP VIEW IF EXISTS
    v_synthetic_browser_latest_domain_report,
    v_synthetic_browser_run_ip_detail,
    v_synthetic_browser_ip_results,
    v_synthetic_browser_run_host_detail,
    v_synthetic_browser_run_operational_summary,
    v_synthetic_browser_host_summary,
    v_synthetic_browser_domain_summary
CASCADE;

CREATE OR REPLACE VIEW v_synthetic_browser_domain_summary AS
WITH latest AS (
    SELECT DISTINCT ON (coalesce(nullif(final_url, ''), url))
        id AS last_run_id,
        coalesce(nullif(final_url, ''), url) AS domain_key,
        url,
        final_url,
        title,
        analyzed_at
    FROM synthetic_browser_runs
    ORDER BY coalesce(nullif(final_url, ''), url), analyzed_at DESC, id DESC
),
run_metrics AS (
    SELECT
        coalesce(nullif(r.final_url, ''), r.url) AS domain_key,
        count(*) AS total_runs,
        min(r.analyzed_at) AS first_analyzed_at,
        max(r.analyzed_at) AS last_analyzed_at,
        sum(coalesce(r.total_hosts, 0)) AS total_hosts_observed,
        sum(coalesce(r.total_ips_measured, 0)) AS total_ips_measured,
        sum(coalesce(r.total_ping_success, 0)) AS total_ping_success,
        sum(coalesce(r.total_ping_failed, 0)) AS total_ping_failed,
        sum(coalesce(r.total_traceroutes_run, 0)) AS total_traceroutes_run,
        sum(coalesce(r.total_ips_with_bgp_match, 0)) AS total_ips_with_bgp_match
    FROM synthetic_browser_runs r
    GROUP BY coalesce(nullif(r.final_url, ''), r.url)
),
measurement_metrics AS (
    SELECT
        coalesce(nullif(r.final_url, ''), r.url) AS domain_key,
        avg(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS avg_rtt_avg_ms,
        min(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS min_rtt_avg_ms,
        max(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS max_rtt_avg_ms,
        sum(CASE WHEN m.traceroute_status = 'SUCCESS' THEN 1 ELSE 0 END) AS total_traceroute_success,
        avg(m.traceroute_hop_count) FILTER (WHERE m.traceroute_hop_count IS NOT NULL) AS avg_traceroute_hops
    FROM synthetic_browser_runs r
    LEFT JOIN synthetic_browser_ip_measurements m ON m.run_id = r.id
    GROUP BY coalesce(nullif(r.final_url, ''), r.url)
)
SELECT
    latest.url,
    latest.final_url,
    latest.title,
    run_metrics.total_runs,
    latest.last_run_id,
    run_metrics.first_analyzed_at,
    run_metrics.last_analyzed_at,
    run_metrics.total_hosts_observed,
    run_metrics.total_ips_measured,
    run_metrics.total_ping_success,
    run_metrics.total_ping_failed,
    measurement_metrics.avg_rtt_avg_ms,
    measurement_metrics.min_rtt_avg_ms,
    measurement_metrics.max_rtt_avg_ms,
    run_metrics.total_traceroutes_run,
    measurement_metrics.total_traceroute_success,
    measurement_metrics.avg_traceroute_hops,
    run_metrics.total_ips_with_bgp_match
FROM latest
JOIN run_metrics ON run_metrics.domain_key = latest.domain_key
LEFT JOIN measurement_metrics ON measurement_metrics.domain_key = latest.domain_key;

CREATE OR REPLACE VIEW v_synthetic_browser_run_operational_summary AS
SELECT
    r.id AS run_id,
    r.url,
    r.final_url,
    r.title,
    r.label,
    r.analyzed_at,
    r.total_requests,
    r.total_hosts,
    r.total_ipv4,
    r.total_ipv6,
    r.total_ips_measured,
    count(m.id) AS measured_rows,
    count(*) FILTER (WHERE m.ping_status = 'SUCCESS') AS ping_success,
    count(*) FILTER (WHERE m.ping_status = 'FAILED') AS ping_failed,
    avg(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS avg_rtt_avg_ms,
    min(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS min_rtt_avg_ms,
    max(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS max_rtt_avg_ms,
    count(*) FILTER (WHERE m.traceroute_status = 'SUCCESS') AS traceroute_success,
    count(*) FILTER (WHERE m.traceroute_status = 'FAILED') AS traceroute_failed,
    avg(m.traceroute_hop_count) FILTER (WHERE m.traceroute_hop_count IS NOT NULL) AS avg_traceroute_hop_count,
    count(*) FILTER (WHERE coalesce(m.bgp_route_count, 0) > 0) AS ips_with_bgp_match,
    count(distinct m.hostname) FILTER (WHERE coalesce(m.bgp_route_count, 0) > 0) AS hosts_with_bgp_match,
    count(distinct m.hostname) FILTER (WHERE m.ping_status = 'FAILED') AS hosts_with_ping_failure,
    count(distinct m.hostname) FILTER (WHERE m.traceroute_status = 'FAILED') AS hosts_with_traceroute_failure
FROM synthetic_browser_runs r
LEFT JOIN synthetic_browser_ip_measurements m ON m.run_id = r.id
GROUP BY
    r.id,
    r.url,
    r.final_url,
    r.title,
    r.label,
    r.analyzed_at,
    r.total_requests,
    r.total_hosts,
    r.total_ipv4,
    r.total_ipv6,
    r.total_ips_measured;

CREATE OR REPLACE VIEW v_synthetic_browser_run_host_detail AS
SELECT
    r.id AS run_id,
    r.analyzed_at,
    r.url,
    r.final_url,
    h.hostname,
    h.request_count,
    h.dns_error,
    coalesce(cardinality(h.ipv4_addresses), 0) AS ipv4_count,
    coalesce(cardinality(h.ipv6_addresses), 0) AS ipv6_count,
    coalesce(cardinality(h.selected_ipv4_addresses), 0) AS selected_ipv4_count,
    count(m.id) AS measured_ips,
    count(*) FILTER (WHERE m.ping_status = 'SUCCESS') AS ping_success,
    count(*) FILTER (WHERE m.ping_status = 'FAILED') AS ping_failed,
    avg(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS avg_rtt_avg_ms,
    max(m.rtt_avg_ms) FILTER (WHERE m.rtt_avg_ms IS NOT NULL) AS max_rtt_avg_ms,
    count(*) FILTER (WHERE m.traceroute_status = 'SUCCESS') AS traceroute_success,
    count(*) FILTER (WHERE m.traceroute_status = 'FAILED') AS traceroute_failed,
    avg(m.traceroute_hop_count) FILTER (WHERE m.traceroute_hop_count IS NOT NULL) AS avg_traceroute_hop_count,
    count(*) FILTER (WHERE coalesce(m.bgp_route_count, 0) > 0) AS ips_with_bgp_match
FROM synthetic_browser_runs r
JOIN synthetic_browser_hosts h ON h.run_id = r.id
LEFT JOIN synthetic_browser_ip_measurements m ON m.host_id = h.id
GROUP BY
    r.id,
    r.analyzed_at,
    r.url,
    r.final_url,
    h.hostname,
    h.request_count,
    h.dns_error,
    h.ipv4_addresses,
    h.ipv6_addresses,
    h.selected_ipv4_addresses;

CREATE OR REPLACE VIEW v_synthetic_browser_ip_results AS
SELECT
    r.id AS run_id,
    r.analyzed_at,
    r.url,
    r.final_url,
    r.title,
    h.hostname,
    m.ip,
    m.bgp_route_count,
    m.ping_status,
    m.packet_loss_percent,
    m.rtt_min_ms,
    m.rtt_avg_ms,
    m.rtt_max_ms,
    m.rtt_mdev_ms,
    m.traceroute_status,
    m.traceroute_hop_count,
    m.traceroute_responded_hop_count
FROM synthetic_browser_runs r
JOIN synthetic_browser_hosts h ON h.run_id = r.id
JOIN synthetic_browser_ip_measurements m ON m.run_id = r.id AND m.host_id = h.id;

CREATE OR REPLACE VIEW v_synthetic_browser_run_ip_detail AS
SELECT
    run_id,
    analyzed_at,
    url,
    final_url,
    title,
    hostname,
    ip,
    bgp_route_count,
    (coalesce(bgp_route_count, 0) > 0) AS has_bgp_match,
    ping_status,
    packet_loss_percent,
    rtt_avg_ms,
    rtt_max_ms,
    traceroute_status,
    traceroute_hop_count,
    traceroute_responded_hop_count
FROM v_synthetic_browser_ip_results;

CREATE OR REPLACE VIEW v_synthetic_browser_host_summary AS
SELECT
    hostname,
    count(DISTINCT run_id) AS total_runs,
    count(*) AS total_ips_measured,
    avg(rtt_avg_ms) FILTER (WHERE rtt_avg_ms IS NOT NULL) AS avg_rtt_avg_ms,
    min(rtt_avg_ms) FILTER (WHERE rtt_avg_ms IS NOT NULL) AS min_rtt_avg_ms,
    max(rtt_avg_ms) FILTER (WHERE rtt_avg_ms IS NOT NULL) AS max_rtt_avg_ms,
    count(*) FILTER (WHERE coalesce(bgp_route_count, 0) > 0) AS total_bgp_matches,
    max(analyzed_at) AS last_seen
FROM v_synthetic_browser_run_ip_detail
GROUP BY hostname;

CREATE OR REPLACE VIEW v_synthetic_browser_latest_domain_report AS
WITH ranked AS (
    SELECT
        run_id,
        url,
        final_url,
        title,
        analyzed_at,
        total_requests,
        total_hosts,
        total_ips_measured,
        ping_success,
        ping_failed,
        avg_rtt_avg_ms,
        min_rtt_avg_ms,
        max_rtt_avg_ms,
        traceroute_success,
        traceroute_failed,
        avg_traceroute_hop_count,
        ips_with_bgp_match,
        row_number() OVER (
            PARTITION BY coalesce(nullif(final_url, ''), url)
            ORDER BY analyzed_at DESC, run_id DESC
        ) AS rn
    FROM v_synthetic_browser_run_operational_summary
)
SELECT
    run_id,
    url,
    final_url,
    title,
    analyzed_at,
    total_requests,
    total_hosts,
    total_ips_measured,
    ping_success,
    ping_failed,
    avg_rtt_avg_ms,
    max_rtt_avg_ms,
    traceroute_success,
    traceroute_failed,
    ips_with_bgp_match
FROM ranked
WHERE rn = 1
ORDER BY analyzed_at DESC, run_id DESC;
