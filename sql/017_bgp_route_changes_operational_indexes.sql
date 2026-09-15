-- Índices de apoio para consultas operacionais em bgp_route_changes.

CREATE INDEX IF NOT EXISTS idx_bgp_route_changes_peer_ip_detected_at
    ON bgp_route_changes (peer_ip, detected_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_bgp_route_changes_peer_asn_detected_at
    ON bgp_route_changes (peer_asn, detected_at DESC, id DESC);
