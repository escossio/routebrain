CREATE TABLE IF NOT EXISTS network_sites (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    city text,
    state text,
    country text DEFAULT 'BR',
    notes text,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_ixps (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    city text,
    country text DEFAULT 'BR',
    fabric_prefixes text,
    website text,
    notes text,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_routers (
    id bigserial PRIMARY KEY,
    hostname text NOT NULL UNIQUE,
    management_ip inet,
    vendor text,
    model text,
    role text,
    site_id bigint REFERENCES network_sites(id),
    local_asn bigint,
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    id bigserial PRIMARY KEY,
    router_id bigint NOT NULL REFERENCES network_routers(id) ON DELETE CASCADE,
    interface_name text NOT NULL,
    ip_address inet,
    description text,
    status text,
    interface_type text,
    connected_to text,
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    UNIQUE (router_id, interface_name)
);

CREATE TABLE IF NOT EXISTS network_bgp_peers (
    id bigserial PRIMARY KEY,
    router_id bigint REFERENCES network_routers(id) ON DELETE CASCADE,
    local_asn bigint,
    peer_ip inet NOT NULL,
    peer_asn bigint,
    peer_name text,
    session_type text,
    connection_type text,
    interface_id bigint REFERENCES network_interfaces(id),
    ixp_id bigint REFERENCES network_ixps(id),
    status text,
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    UNIQUE (router_id, peer_ip)
);

CREATE TABLE IF NOT EXISTS network_links (
    id bigserial PRIMARY KEY,
    local_router_id bigint REFERENCES network_routers(id),
    local_interface_id bigint REFERENCES network_interfaces(id),
    remote_router_id bigint REFERENCES network_routers(id),
    remote_interface_id bigint REFERENCES network_interfaces(id),
    link_type text,
    provider text,
    circuit_id text,
    status text,
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_network_routers_hostname
    ON network_routers (hostname);

CREATE INDEX IF NOT EXISTS idx_network_routers_management_ip
    ON network_routers (management_ip);

CREATE INDEX IF NOT EXISTS idx_network_interfaces_ip_address
    ON network_interfaces (ip_address);

CREATE INDEX IF NOT EXISTS idx_network_bgp_peers_peer_ip
    ON network_bgp_peers (peer_ip);

CREATE INDEX IF NOT EXISTS idx_network_bgp_peers_peer_asn
    ON network_bgp_peers (peer_asn);

CREATE INDEX IF NOT EXISTS idx_network_bgp_peers_connection_type
    ON network_bgp_peers (connection_type);

CREATE INDEX IF NOT EXISTS idx_network_links_local_router_id
    ON network_links (local_router_id);

CREATE INDEX IF NOT EXISTS idx_network_links_remote_router_id
    ON network_links (remote_router_id);
