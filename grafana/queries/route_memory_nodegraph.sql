-- RouteBrain Grafana Node Graph Queries
-- Read-only reference queries for manual dashboard assembly.

-- Summary
SELECT *
FROM route_memory_grafana_summary_latest;

-- Nodes for Node Graph
SELECT
  id,
  title,
  subtitle,
  mainstat,
  secondarystat,
  detail__ip,
  detail__asn,
  detail__canonical_key,
  detail__route_ids,
  detail__node_type,
  detail__segment_type,
  detail__shared,
  detail__source_node_ids
FROM route_memory_grafana_nodes_latest;

-- Edges for Node Graph
SELECT
  id,
  source,
  target,
  mainstat,
  secondarystat,
  detail__route_ids,
  detail__edge_type,
  detail__shared,
  detail__source_key,
  detail__target_key
FROM route_memory_grafana_edges_latest;

-- Divergences table
SELECT
  graph_uid,
  divergence_id,
  divergence_type,
  severity,
  summary,
  route_ids,
  at_segment
FROM route_memory_grafana_divergences_latest;

-- Graph snapshots list
SELECT
  graph_uid,
  source_node,
  title,
  graph_type,
  route_count,
  schema_version,
  created_at
FROM route_memory_grafana_summary
ORDER BY created_at DESC;

-- Shared nodes
SELECT *
FROM route_memory_grafana_nodes_latest
WHERE shared = true;

-- Shared edges
SELECT *
FROM route_memory_grafana_edges_latest
WHERE shared = true;

-- Nodes by graph_uid
SELECT *
FROM route_memory_grafana_nodes
WHERE graph_uid = '${graph_uid}';

-- Edges by graph_uid
SELECT *
FROM route_memory_grafana_edges
WHERE graph_uid = '${graph_uid}';

