CREATE TABLE IF NOT EXISTS inventory_sites (
    id bigserial PRIMARY KEY,
    site_code text NOT NULL UNIQUE,
    name text NOT NULL,
    site_type text,
    city text,
    state text,
    country text DEFAULT 'BR',
    facility text,
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inventory_hosts (
    id bigserial PRIMARY KEY,
    hostname text NOT NULL UNIQUE,
    mgmt_ip inet,
    site_id bigint REFERENCES inventory_sites(id) ON DELETE SET NULL,
    role text DEFAULT 'unknown',
    vendor text,
    model text,
    os_name text,
    status text DEFAULT 'active',
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inventory_interfaces (
    id bigserial PRIMARY KEY,
    host_id bigint NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    interface_name text NOT NULL,
    interface_ip inet,
    description text,
    speed_mbps integer,
    vlan text,
    circuit_ref text,
    peer_ip inet,
    peer_asn bigint,
    status text DEFAULT 'active',
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    UNIQUE (host_id, interface_name)
);

CREATE TABLE IF NOT EXISTS inventory_tags (
    id bigserial PRIMARY KEY,
    tag text NOT NULL UNIQUE,
    description text
);

CREATE TABLE IF NOT EXISTS inventory_host_tags (
    host_id bigint NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    tag_id bigint NOT NULL REFERENCES inventory_tags(id) ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);

CREATE TABLE IF NOT EXISTS inventory_peer_links (
    id bigserial PRIMARY KEY,
    peer_ip inet NOT NULL,
    peer_asn bigint,
    host_id bigint REFERENCES inventory_hosts(id) ON DELETE SET NULL,
    interface_id bigint REFERENCES inventory_interfaces(id) ON DELETE SET NULL,
    site_id bigint REFERENCES inventory_sites(id) ON DELETE SET NULL,
    relation_type text DEFAULT 'bgp-peer',
    confidence text DEFAULT 'confirmed',
    source text DEFAULT 'manual',
    notes text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS inventory_host_observations (
    id bigserial PRIMARY KEY,
    host_id bigint NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    observation_type text,
    observation text NOT NULL,
    source text,
    created_at timestamptz DEFAULT now()
);

CREATE OR REPLACE FUNCTION inventory_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_inventory_sites_touch_updated_at ON inventory_sites;
CREATE TRIGGER trg_inventory_sites_touch_updated_at
BEFORE UPDATE ON inventory_sites
FOR EACH ROW
EXECUTE FUNCTION inventory_touch_updated_at();

DROP TRIGGER IF EXISTS trg_inventory_hosts_touch_updated_at ON inventory_hosts;
CREATE TRIGGER trg_inventory_hosts_touch_updated_at
BEFORE UPDATE ON inventory_hosts
FOR EACH ROW
EXECUTE FUNCTION inventory_touch_updated_at();

DROP TRIGGER IF EXISTS trg_inventory_interfaces_touch_updated_at ON inventory_interfaces;
CREATE TRIGGER trg_inventory_interfaces_touch_updated_at
BEFORE UPDATE ON inventory_interfaces
FOR EACH ROW
EXECUTE FUNCTION inventory_touch_updated_at();

DROP TRIGGER IF EXISTS trg_inventory_peer_links_touch_updated_at ON inventory_peer_links;
CREATE TRIGGER trg_inventory_peer_links_touch_updated_at
BEFORE UPDATE ON inventory_peer_links
FOR EACH ROW
EXECUTE FUNCTION inventory_touch_updated_at();

CREATE INDEX IF NOT EXISTS idx_inventory_sites_site_code
    ON inventory_sites (site_code);

CREATE INDEX IF NOT EXISTS idx_inventory_hosts_hostname
    ON inventory_hosts (hostname);

CREATE INDEX IF NOT EXISTS idx_inventory_hosts_mgmt_ip
    ON inventory_hosts (mgmt_ip);

CREATE INDEX IF NOT EXISTS idx_inventory_hosts_site_id
    ON inventory_hosts (site_id);

CREATE INDEX IF NOT EXISTS idx_inventory_hosts_role
    ON inventory_hosts (role);

CREATE INDEX IF NOT EXISTS idx_inventory_interfaces_host_id
    ON inventory_interfaces (host_id);

CREATE INDEX IF NOT EXISTS idx_inventory_interfaces_interface_ip
    ON inventory_interfaces (interface_ip);

CREATE INDEX IF NOT EXISTS idx_inventory_interfaces_peer_ip
    ON inventory_interfaces (peer_ip);

CREATE INDEX IF NOT EXISTS idx_inventory_interfaces_peer_asn
    ON inventory_interfaces (peer_asn);

CREATE INDEX IF NOT EXISTS idx_inventory_host_tags_tag_id
    ON inventory_host_tags (tag_id);

CREATE INDEX IF NOT EXISTS idx_inventory_peer_links_peer_ip
    ON inventory_peer_links (peer_ip);

CREATE INDEX IF NOT EXISTS idx_inventory_peer_links_peer_asn
    ON inventory_peer_links (peer_asn);

CREATE INDEX IF NOT EXISTS idx_inventory_peer_links_site_id
    ON inventory_peer_links (site_id);

CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_peer_links_peer_host_interface
    ON inventory_peer_links (peer_ip, host_id, interface_id, relation_type)
    WHERE host_id IS NOT NULL AND interface_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_peer_links_peer_host_relation
    ON inventory_peer_links (peer_ip, host_id, relation_type)
    WHERE host_id IS NOT NULL AND interface_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_peer_links_peer_interface_relation
    ON inventory_peer_links (peer_ip, interface_id, relation_type)
    WHERE interface_id IS NOT NULL AND host_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_peer_links_peer_relation_unbound
    ON inventory_peer_links (peer_ip, relation_type)
    WHERE host_id IS NULL AND interface_id IS NULL;
