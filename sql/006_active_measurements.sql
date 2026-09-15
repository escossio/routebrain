CREATE TABLE IF NOT EXISTS active_ping_measurements (
    id bigserial PRIMARY KEY,
    target inet NOT NULL,
    target_label text,
    source_label text,
    packets_sent integer NOT NULL,
    packets_received integer NOT NULL,
    packet_loss_percent numeric(6,2),
    rtt_min_ms numeric(12,3),
    rtt_avg_ms numeric(12,3),
    rtt_max_ms numeric(12,3),
    rtt_mdev_ms numeric(12,3),
    command text,
    raw_output text,
    status text NOT NULL,
    measured_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_active_ping_measurements_target
    ON active_ping_measurements (target);

CREATE INDEX IF NOT EXISTS idx_active_ping_measurements_measured_at
    ON active_ping_measurements (measured_at);

CREATE INDEX IF NOT EXISTS idx_active_ping_measurements_status
    ON active_ping_measurements (status);

CREATE INDEX IF NOT EXISTS idx_active_ping_measurements_target_measured_at_desc
    ON active_ping_measurements (target, measured_at DESC);

CREATE OR REPLACE VIEW v_active_ping_latest AS
SELECT DISTINCT ON (m.target)
    m.target,
    m.target_label,
    m.source_label,
    m.packets_sent,
    m.packets_received,
    m.packet_loss_percent,
    m.rtt_min_ms,
    m.rtt_avg_ms,
    m.rtt_max_ms,
    m.rtt_mdev_ms,
    m.status,
    m.measured_at
FROM active_ping_measurements m
ORDER BY m.target, m.measured_at DESC, m.id DESC;

CREATE OR REPLACE VIEW v_active_ping_summary_by_target AS
SELECT
    target,
    count(*) AS total_measurements,
    count(*) FILTER (WHERE status = 'SUCCESS') AS successful_measurements,
    count(*) FILTER (WHERE status = 'FAILED') AS failed_measurements,
    avg(packet_loss_percent) AS avg_packet_loss_percent,
    avg(rtt_avg_ms) AS avg_rtt_avg_ms,
    min(rtt_avg_ms) AS min_rtt_avg_ms,
    max(rtt_avg_ms) AS max_rtt_avg_ms,
    min(measured_at) AS first_measured_at,
    max(measured_at) AS last_measured_at
FROM active_ping_measurements
GROUP BY target;
