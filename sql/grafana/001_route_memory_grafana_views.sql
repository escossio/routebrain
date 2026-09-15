CREATE OR REPLACE VIEW route_memory_grafana_latest_graph AS
SELECT
    s.graph_uid,
    s.source_node,
    s.title,
    s.graph_type,
    s.route_count,
    s.schema_version,
    s.created_at,
    s.payload_json
FROM route_memory_graph_snapshots AS s
ORDER BY s.created_at DESC, s.id DESC
LIMIT 1;

CREATE OR REPLACE VIEW route_memory_grafana_summary_latest AS
SELECT
    s.graph_uid,
    s.source_node,
    s.title,
    s.graph_type,
    s.schema_version,
    s.created_at,
    s.route_count,
    COALESCE(jsonb_array_length(s.payload_json->'routes'), 0) AS routes_count,
    COALESCE(jsonb_array_length(s.payload_json->'nodes'), 0) AS nodes_count,
    COALESCE(jsonb_array_length(s.payload_json->'edges'), 0) AS edges_count,
    COALESCE(jsonb_array_length(s.payload_json->'segments'), 0) AS segments_count,
    COALESCE(jsonb_array_length(s.payload_json->'divergences'), 0) AS divergences_count,
    COALESCE((
        SELECT count(*)
        FROM jsonb_array_elements(COALESCE(s.payload_json->'nodes', '[]'::jsonb)) AS node
        WHERE CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END
    ), 0) AS shared_nodes_count,
    COALESCE((
        SELECT count(*)
        FROM jsonb_array_elements(COALESCE(s.payload_json->'edges', '[]'::jsonb)) AS edge
        WHERE CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END
    ), 0) AS shared_edges_count
FROM route_memory_graph_snapshots AS s
WHERE (s.created_at, s.id) = (
    SELECT s2.created_at, s2.id
    FROM route_memory_graph_snapshots AS s2
    ORDER BY s2.created_at DESC, s2.id DESC
    LIMIT 1
);

CREATE OR REPLACE VIEW route_memory_grafana_nodes_latest AS
SELECT
    s.graph_uid,
    node->>'node_id' AS id,
    COALESCE(node->>'label', node->>'canonical_key', node->>'node_id') AS title,
    COALESCE(node->>'node_type', node->>'segment_type', node->>'ip', node->>'canonical_key') AS subtitle,
    CASE WHEN CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END THEN 'Shared' ELSE 'Node' END AS mainstat,
    COALESCE(jsonb_array_length(COALESCE(node->'route_ids', '[]'::jsonb)), 0)::text || ' route(s)' AS secondarystat,
    node->>'node_type' AS node_type,
    node->>'ip' AS ip,
    node->>'asn' AS asn,
    node->>'canonical_key' AS canonical_key,
    node->>'segment_type' AS segment_type,
    CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END AS shared,
    COALESCE(node->'route_ids', '[]'::jsonb) AS route_ids,
    COALESCE(node->'source_node_ids', '[]'::jsonb) AS source_node_ids,
    node->>'ip' AS detail__ip,
    node->>'asn' AS detail__asn,
    node->>'canonical_key' AS detail__canonical_key,
    COALESCE(node->'route_ids', '[]'::jsonb) AS detail__route_ids,
    node->>'node_type' AS detail__node_type,
    node->>'segment_type' AS detail__segment_type,
    CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END AS detail__shared,
    COALESCE(node->'source_node_ids', '[]'::jsonb) AS detail__source_node_ids,
    node AS raw_node
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'nodes', '[]'::jsonb)) AS node
WHERE (s.created_at, s.id) = (
    SELECT s2.created_at, s2.id
    FROM route_memory_graph_snapshots AS s2
    ORDER BY s2.created_at DESC, s2.id DESC
    LIMIT 1
);

CREATE OR REPLACE VIEW route_memory_grafana_edges_latest AS
SELECT
    s.graph_uid,
    edge->>'edge_id' AS id,
    edge->>'source' AS source,
    edge->>'target' AS target,
    CASE WHEN CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END THEN 'Shared' ELSE COALESCE(edge->>'edge_type', 'Edge') END AS mainstat,
    COALESCE(jsonb_array_length(COALESCE(edge->'route_ids', '[]'::jsonb)), 0)::text || ' route(s)' AS secondarystat,
    edge->>'edge_type' AS edge_type,
    CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END AS shared,
    COALESCE(edge->'route_ids', '[]'::jsonb) AS route_ids,
    edge->>'source_key' AS source_key,
    edge->>'target_key' AS target_key,
    COALESCE(edge->'route_ids', '[]'::jsonb) AS detail__route_ids,
    edge->>'edge_type' AS detail__edge_type,
    CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END AS detail__shared,
    edge->>'source_key' AS detail__source_key,
    edge->>'target_key' AS detail__target_key,
    edge AS raw_edge
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'edges', '[]'::jsonb)) AS edge
WHERE (s.created_at, s.id) = (
    SELECT s2.created_at, s2.id
    FROM route_memory_graph_snapshots AS s2
    ORDER BY s2.created_at DESC, s2.id DESC
    LIMIT 1
);

CREATE OR REPLACE VIEW route_memory_grafana_divergences_latest AS
SELECT
    s.graph_uid,
    divergence->>'divergence_id' AS divergence_id,
    divergence->>'divergence_type' AS divergence_type,
    divergence->>'severity' AS severity,
    divergence->>'summary' AS summary,
    COALESCE(divergence->'route_ids', '[]'::jsonb) AS route_ids,
    divergence->>'at_segment' AS at_segment,
    divergence AS raw_divergence
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'divergences', '[]'::jsonb)) AS divergence
WHERE (s.created_at, s.id) = (
    SELECT s2.created_at, s2.id
    FROM route_memory_graph_snapshots AS s2
    ORDER BY s2.created_at DESC, s2.id DESC
    LIMIT 1
);

CREATE OR REPLACE VIEW route_memory_grafana_summary AS
SELECT
    s.graph_uid,
    s.source_node,
    s.title,
    s.graph_type,
    s.schema_version,
    s.created_at,
    s.route_count,
    COALESCE(jsonb_array_length(s.payload_json->'routes'), 0) AS routes_count,
    COALESCE(jsonb_array_length(s.payload_json->'nodes'), 0) AS nodes_count,
    COALESCE(jsonb_array_length(s.payload_json->'edges'), 0) AS edges_count,
    COALESCE(jsonb_array_length(s.payload_json->'segments'), 0) AS segments_count,
    COALESCE(jsonb_array_length(s.payload_json->'divergences'), 0) AS divergences_count,
    COALESCE((
        SELECT count(*)
        FROM jsonb_array_elements(COALESCE(s.payload_json->'nodes', '[]'::jsonb)) AS node
        WHERE CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END
    ), 0) AS shared_nodes_count,
    COALESCE((
        SELECT count(*)
        FROM jsonb_array_elements(COALESCE(s.payload_json->'edges', '[]'::jsonb)) AS edge
        WHERE CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END
    ), 0) AS shared_edges_count
FROM route_memory_graph_snapshots AS s;

CREATE OR REPLACE VIEW route_memory_grafana_nodes AS
SELECT
    s.graph_uid,
    node->>'node_id' AS id,
    COALESCE(node->>'label', node->>'canonical_key', node->>'node_id') AS title,
    COALESCE(node->>'node_type', node->>'segment_type', node->>'ip', node->>'canonical_key') AS subtitle,
    CASE WHEN CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END THEN 'Shared' ELSE 'Node' END AS mainstat,
    COALESCE(jsonb_array_length(COALESCE(node->'route_ids', '[]'::jsonb)), 0)::text || ' route(s)' AS secondarystat,
    node->>'node_type' AS node_type,
    node->>'ip' AS ip,
    node->>'asn' AS asn,
    node->>'canonical_key' AS canonical_key,
    node->>'segment_type' AS segment_type,
    CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END AS shared,
    COALESCE(node->'route_ids', '[]'::jsonb) AS route_ids,
    COALESCE(node->'source_node_ids', '[]'::jsonb) AS source_node_ids,
    node->>'ip' AS detail__ip,
    node->>'asn' AS detail__asn,
    node->>'canonical_key' AS detail__canonical_key,
    COALESCE(node->'route_ids', '[]'::jsonb) AS detail__route_ids,
    node->>'node_type' AS detail__node_type,
    node->>'segment_type' AS detail__segment_type,
    CASE WHEN lower(COALESCE(node->>'shared', 'false')) = 'true' THEN true ELSE false END AS detail__shared,
    COALESCE(node->'source_node_ids', '[]'::jsonb) AS detail__source_node_ids,
    node AS raw_node
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'nodes', '[]'::jsonb)) AS node;

CREATE OR REPLACE VIEW route_memory_grafana_edges AS
SELECT
    s.graph_uid,
    edge->>'edge_id' AS id,
    edge->>'source' AS source,
    edge->>'target' AS target,
    CASE WHEN CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END THEN 'Shared' ELSE COALESCE(edge->>'edge_type', 'Edge') END AS mainstat,
    COALESCE(jsonb_array_length(COALESCE(edge->'route_ids', '[]'::jsonb)), 0)::text || ' route(s)' AS secondarystat,
    edge->>'edge_type' AS edge_type,
    CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END AS shared,
    COALESCE(edge->'route_ids', '[]'::jsonb) AS route_ids,
    edge->>'source_key' AS source_key,
    edge->>'target_key' AS target_key,
    COALESCE(edge->'route_ids', '[]'::jsonb) AS detail__route_ids,
    edge->>'edge_type' AS detail__edge_type,
    CASE WHEN lower(COALESCE(edge->>'shared', 'false')) = 'true' THEN true ELSE false END AS detail__shared,
    edge->>'source_key' AS detail__source_key,
    edge->>'target_key' AS detail__target_key,
    edge AS raw_edge
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'edges', '[]'::jsonb)) AS edge;

CREATE OR REPLACE VIEW route_memory_grafana_divergences AS
SELECT
    s.graph_uid,
    divergence->>'divergence_id' AS divergence_id,
    divergence->>'divergence_type' AS divergence_type,
    divergence->>'severity' AS severity,
    divergence->>'summary' AS summary,
    COALESCE(divergence->'route_ids', '[]'::jsonb) AS route_ids,
    divergence->>'at_segment' AS at_segment,
    divergence AS raw_divergence
FROM route_memory_graph_snapshots AS s
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s.payload_json->'divergences', '[]'::jsonb)) AS divergence;

GRANT SELECT ON route_memory_grafana_latest_graph TO routebrain;
GRANT SELECT ON route_memory_grafana_summary_latest TO routebrain;
GRANT SELECT ON route_memory_grafana_nodes_latest TO routebrain;
GRANT SELECT ON route_memory_grafana_edges_latest TO routebrain;
GRANT SELECT ON route_memory_grafana_divergences_latest TO routebrain;
GRANT SELECT ON route_memory_grafana_summary TO routebrain;
GRANT SELECT ON route_memory_grafana_nodes TO routebrain;
GRANT SELECT ON route_memory_grafana_edges TO routebrain;
GRANT SELECT ON route_memory_grafana_divergences TO routebrain;
