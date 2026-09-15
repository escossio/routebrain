CREATE TABLE IF NOT EXISTS network_hop_classifications (
    id bigserial PRIMARY KEY,
    hop_ip inet NOT NULL UNIQUE,
    classification text NOT NULL,
    confidence text NOT NULL DEFAULT 'manual',
    owner text,
    provider text,
    site_id bigint REFERENCES network_sites(id) ON DELETE SET NULL,
    router_id bigint REFERENCES network_routers(id) ON DELETE SET NULL,
    interface_id bigint REFERENCES network_interfaces(id) ON DELETE SET NULL,
    notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_network_hop_classifications_hop_ip
    ON network_hop_classifications (hop_ip);

CREATE INDEX IF NOT EXISTS idx_network_hop_classifications_classification
    ON network_hop_classifications (classification);

CREATE INDEX IF NOT EXISTS idx_network_hop_classifications_confidence
    ON network_hop_classifications (confidence);

CREATE INDEX IF NOT EXISTS idx_network_hop_classifications_provider
    ON network_hop_classifications (provider);

CREATE OR REPLACE VIEW v_active_traceroute_hops_enriched_with_classification AS
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
    e.inventory_match_status,
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
    hc.id AS classification_id,
    hc.classification AS hop_classification,
    hc.confidence AS classification_confidence,
    hc.owner AS classification_owner,
    hc.provider AS classification_provider,
    hc.notes AS classification_notes,
    CASE
        WHEN e.inventory_match_status = 'NO_RESPONSE' THEN 'NO_RESPONSE'
        WHEN e.inventory_match_status = 'MATCHED_INTERFACE' THEN 'MATCHED_INTERFACE'
        WHEN hc.id IS NOT NULL THEN 'CLASSIFIED_HOP'
        ELSE 'UNMATCHED'
    END AS effective_context_status
FROM v_active_traceroute_hops_enriched e
LEFT JOIN network_hop_classifications hc
    ON host(hc.hop_ip) = host(e.hop_ip);

CREATE OR REPLACE VIEW v_active_traceroute_latest_hops_with_classification AS
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
    e.inventory_match_status,
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
    e.classification_id,
    e.hop_classification,
    e.classification_confidence,
    e.classification_owner,
    e.classification_provider,
    e.classification_notes,
    e.effective_context_status
FROM v_active_traceroute_hops_enriched_with_classification e
JOIN latest_measurements lm
    ON lm.measurement_id = e.measurement_id
ORDER BY e.target, e.hop_number;

CREATE OR REPLACE VIEW v_active_traceroute_classification_summary AS
SELECT
    count(*) AS total_hops,
    count(*) FILTER (WHERE effective_context_status = 'NO_RESPONSE') AS no_response_hops,
    count(*) FILTER (WHERE effective_context_status = 'MATCHED_INTERFACE') AS matched_interface_hops,
    count(*) FILTER (WHERE effective_context_status = 'CLASSIFIED_HOP') AS classified_hops,
    count(*) FILTER (WHERE effective_context_status = 'UNMATCHED') AS unmatched_hops,
    count(*) FILTER (WHERE is_private AND effective_context_status = 'UNMATCHED') AS private_unmatched_hops,
    count(*) FILTER (WHERE is_private AND effective_context_status = 'CLASSIFIED_HOP') AS private_classified_hops,
    count(DISTINCT hop_ip) FILTER (WHERE effective_context_status = 'CLASSIFIED_HOP') AS distinct_classified_hop_ips,
    count(DISTINCT hop_ip) FILTER (WHERE effective_context_status = 'UNMATCHED') AS distinct_unmatched_hop_ips
FROM v_active_traceroute_hops_enriched_with_classification;

CREATE OR REPLACE VIEW v_active_traceroute_top_unclassified_private_hops AS
SELECT
    hop_ip,
    ip_scope,
    count(*) AS occurrences,
    count(DISTINCT target) AS distinct_targets,
    avg(rtt_avg_ms)::numeric(12,3) AS avg_rtt_avg_ms,
    min(measured_at) AS first_seen,
    max(measured_at) AS last_seen
FROM v_active_traceroute_hops_enriched_with_classification
WHERE is_private = true
  AND hop_ip IS NOT NULL
  AND effective_context_status = 'UNMATCHED'
GROUP BY hop_ip, ip_scope;
