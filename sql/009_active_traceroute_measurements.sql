CREATE TABLE IF NOT EXISTS active_traceroute_measurements (
    id bigserial PRIMARY KEY,
    target inet NOT NULL,
    target_label text,
    source_label text,
    mode text NOT NULL,
    max_hops integer,
    timeout_seconds integer,
    probes integer,
    command text,
    returncode integer,
    status text NOT NULL,
    hop_count integer NOT NULL DEFAULT 0,
    responded_hop_count integer NOT NULL DEFAULT 0,
    raw_output text,
    error_output text,
    measured_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS active_traceroute_hops (
    id bigserial PRIMARY KEY,
    measurement_id bigint NOT NULL REFERENCES active_traceroute_measurements(id) ON DELETE CASCADE,
    target inet NOT NULL,
    hop_number integer NOT NULL,
    hop_ip inet,
    responded boolean NOT NULL DEFAULT false,
    rtt_ms_values numeric(12,3)[],
    rtt_avg_ms numeric(12,3),
    raw_line text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_active_traceroute_measurements_target ON active_traceroute_measurements(target);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_measurements_measured_at ON active_traceroute_measurements(measured_at);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_measurements_status ON active_traceroute_measurements(status);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_measurements_target_measured_at_desc ON active_traceroute_measurements(target, measured_at DESC);

CREATE INDEX IF NOT EXISTS idx_active_traceroute_hops_measurement_id ON active_traceroute_hops(measurement_id);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_hops_target ON active_traceroute_hops(target);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_hops_hop_ip ON active_traceroute_hops(hop_ip);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_hops_hop_number ON active_traceroute_hops(hop_number);
CREATE INDEX IF NOT EXISTS idx_active_traceroute_hops_responded ON active_traceroute_hops(responded);

CREATE OR REPLACE VIEW v_active_traceroute_latest AS
SELECT DISTINCT ON (m.target)
    m.id AS measurement_id,
    m.target,
    m.target_label,
    m.source_label,
    m.mode,
    m.status,
    m.hop_count,
    m.responded_hop_count,
    m.measured_at,
    m.command
FROM active_traceroute_measurements m
ORDER BY m.target, m.measured_at DESC, m.id DESC;

CREATE OR REPLACE VIEW v_active_traceroute_latest_hops AS
WITH latest_measurements AS (
    SELECT DISTINCT ON (target)
        id AS measurement_id,
        target,
        target_label,
        mode,
        measured_at
    FROM active_traceroute_measurements
    ORDER BY target, measured_at DESC, id DESC
)
SELECT
    h.measurement_id,
    h.target,
    lm.target_label,
    lm.mode,
    lm.measured_at,
    h.hop_number,
    h.hop_ip,
    h.responded,
    h.rtt_avg_ms,
    h.raw_line
FROM active_traceroute_hops h
JOIN latest_measurements lm ON lm.measurement_id = h.measurement_id
ORDER BY h.target, h.hop_number;

CREATE OR REPLACE VIEW v_active_traceroute_summary_by_target AS
SELECT
    target,
    count(*) AS total_measurements,
    count(*) FILTER (WHERE status = 'SUCCESS') AS successful_measurements,
    count(*) FILTER (WHERE status <> 'SUCCESS') AS failed_measurements,
    avg(hop_count)::numeric(12,3) AS avg_hop_count,
    avg(responded_hop_count)::numeric(12,3) AS avg_responded_hop_count,
    min(measured_at) AS first_measured_at,
    max(measured_at) AS last_measured_at
FROM active_traceroute_measurements
GROUP BY target;

CREATE OR REPLACE VIEW v_active_traceroute_private_hops AS
SELECT
    h.measurement_id,
    h.target,
    h.hop_number,
    h.hop_ip,
    h.rtt_avg_ms,
    m.measured_at,
    h.raw_line
FROM active_traceroute_hops h
JOIN active_traceroute_measurements m ON m.id = h.measurement_id
WHERE h.hop_ip IS NOT NULL
  AND (
        h.hop_ip << inet '10.0.0.0/8'
        OR h.hop_ip << inet '172.16.0.0/12'
        OR h.hop_ip << inet '192.168.0.0/16'
        OR h.hop_ip << inet '100.64.0.0/10'
      );
