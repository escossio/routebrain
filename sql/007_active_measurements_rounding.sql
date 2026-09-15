DROP VIEW IF EXISTS v_active_ping_summary_by_target;

CREATE VIEW v_active_ping_summary_by_target AS
SELECT
    target,
    count(*) AS total_measurements,
    count(*) FILTER (WHERE status = 'SUCCESS') AS successful_measurements,
    count(*) FILTER (WHERE status = 'FAILED') AS failed_measurements,
    round(avg(packet_loss_percent), 2)::numeric(6,2) AS avg_packet_loss_percent,
    round(avg(rtt_avg_ms), 3)::numeric(12,3) AS avg_rtt_avg_ms,
    round(min(rtt_avg_ms), 3)::numeric(12,3) AS min_rtt_avg_ms,
    round(max(rtt_avg_ms), 3)::numeric(12,3) AS max_rtt_avg_ms,
    min(measured_at) AS first_measured_at,
    max(measured_at) AS last_measured_at
FROM active_ping_measurements
GROUP BY target;
