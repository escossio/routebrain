CREATE TABLE IF NOT EXISTS synthetic_browser_runs (
    id bigserial PRIMARY KEY,
    source_json_path text,
    url text NOT NULL,
    final_url text,
    title text,
    label text,
    total_requests integer,
    total_hosts integer,
    total_ipv4 integer,
    total_ipv6 integer,
    total_ips_measured integer,
    total_ping_success integer,
    total_ping_failed integer,
    total_traceroutes_run integer,
    total_ips_with_bgp_match integer,
    parameters jsonb,
    summary jsonb,
    started_at timestamptz,
    finished_at timestamptz,
    analyzed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS synthetic_browser_hosts (
    id bigserial PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES synthetic_browser_runs(id) ON DELETE CASCADE,
    hostname text NOT NULL,
    dns_error text,
    ipv4_addresses inet[],
    ipv6_addresses inet[],
    selected_ipv4_addresses inet[],
    request_count integer,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS synthetic_browser_ip_measurements (
    id bigserial PRIMARY KEY,
    run_id bigint NOT NULL REFERENCES synthetic_browser_runs(id) ON DELETE CASCADE,
    host_id bigint REFERENCES synthetic_browser_hosts(id) ON DELETE CASCADE,
    hostname text NOT NULL,
    ip inet NOT NULL,
    bgp_route_count integer DEFAULT 0,
    bgp_routes jsonb,
    ping_status text,
    packet_loss_percent numeric(6,2),
    rtt_min_ms numeric(12,3),
    rtt_avg_ms numeric(12,3),
    rtt_max_ms numeric(12,3),
    rtt_mdev_ms numeric(12,3),
    traceroute_status text,
    traceroute_hop_count integer,
    traceroute_responded_hop_count integer,
    traceroute jsonb,
    measured_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_runs_analyzed_at
    ON synthetic_browser_runs (analyzed_at);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_runs_url
    ON synthetic_browser_runs (url);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_hosts_run_id
    ON synthetic_browser_hosts (run_id);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_hosts_hostname
    ON synthetic_browser_hosts (hostname);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_ip_measurements_run_id
    ON synthetic_browser_ip_measurements (run_id);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_ip_measurements_hostname
    ON synthetic_browser_ip_measurements (hostname);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_ip_measurements_ip
    ON synthetic_browser_ip_measurements (ip);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_ip_measurements_ping_status
    ON synthetic_browser_ip_measurements (ping_status);

CREATE INDEX IF NOT EXISTS idx_synthetic_browser_ip_measurements_traceroute_status
    ON synthetic_browser_ip_measurements (traceroute_status);

CREATE OR REPLACE VIEW v_synthetic_browser_run_summary AS
SELECT
    id AS run_id,
    source_json_path,
    url,
    final_url,
    title,
    label,
    total_requests,
    total_hosts,
    total_ipv4,
    total_ipv6,
    total_ips_measured,
    total_ping_success,
    total_ping_failed,
    total_traceroutes_run,
    total_ips_with_bgp_match,
    parameters,
    summary,
    started_at,
    finished_at,
    analyzed_at,
    created_at
FROM synthetic_browser_runs;

CREATE OR REPLACE VIEW v_synthetic_browser_latest_runs AS
SELECT *
FROM v_synthetic_browser_run_summary
ORDER BY analyzed_at DESC, run_id DESC;

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
    m.rtt_avg_ms,
    m.traceroute_status,
    m.traceroute_hop_count,
    m.traceroute_responded_hop_count
FROM synthetic_browser_runs r
JOIN synthetic_browser_hosts h ON h.run_id = r.id
JOIN synthetic_browser_ip_measurements m ON m.run_id = r.id AND m.host_id = h.id;

CREATE OR REPLACE VIEW v_synthetic_browser_host_summary AS
SELECT
    hostname,
    count(distinct run_id) AS total_runs,
    count(*) AS total_ips_measured,
    avg(rtt_avg_ms) AS avg_rtt_avg_ms,
    min(rtt_avg_ms) AS min_rtt_avg_ms,
    max(rtt_avg_ms) AS max_rtt_avg_ms,
    sum(coalesce(bgp_route_count, 0)) AS total_bgp_matches,
    max(analyzed_at) AS last_seen
FROM v_synthetic_browser_ip_results
GROUP BY hostname;
