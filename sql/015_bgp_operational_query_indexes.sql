-- Índices leves para acelerar consultas operacionais read-only.
-- Rodar fora de transação: CREATE INDEX CONCURRENTLY.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bgp_current_routes_prefix
ON bgp_current_routes (prefix);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bgp_current_routes_peer_ip
ON bgp_current_routes (peer_ip);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bgp_current_routes_peer_ip_prefix_collector
ON bgp_current_routes (peer_ip, prefix, collector);
