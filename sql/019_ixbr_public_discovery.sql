CREATE TABLE IF NOT EXISTS ixbr_locations (
    id bigserial PRIMARY KEY,
    locality_code text NOT NULL UNIQUE,
    name text NOT NULL,
    city text,
    state text,
    country text DEFAULT 'BR',
    source_url text,
    fetched_at timestamptz,
    raw_metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ixbr_participants (
    id bigserial PRIMARY KEY,
    locality_code text NOT NULL,
    asn bigint NOT NULL,
    participant_name text,
    participant_url text,
    participation_type text,
    atm_v4 boolean,
    atm_v6 boolean,
    transport_l2 boolean,
    cix boolean,
    raw_row jsonb DEFAULT '{}'::jsonb,
    source_url text,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    UNIQUE (locality_code, asn)
);

CREATE TABLE IF NOT EXISTS ixbr_route_server_observations (
    id bigserial PRIMARY KEY,
    locality_code text NOT NULL,
    route_server text,
    peer_ip inet,
    peer_asn bigint,
    state text,
    description text,
    raw_data jsonb DEFAULT '{}'::jsonb,
    source_url text,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ixbr_discovery_runs (
    id bigserial PRIMARY KEY,
    locality_code text NOT NULL,
    source text NOT NULL,
    source_url text,
    status text NOT NULL,
    participants_found integer DEFAULT 0,
    route_server_peers_found integer DEFAULT 0,
    error text,
    started_at timestamptz DEFAULT now(),
    finished_at timestamptz,
    report_path text
);

CREATE TABLE IF NOT EXISTS inventory_evidence (
    id bigserial PRIMARY KEY,
    evidence_scope text NOT NULL,
    object_type text NOT NULL,
    object_ref text NOT NULL,
    site_id bigint REFERENCES inventory_sites(id) ON DELETE SET NULL,
    evidence_type text NOT NULL,
    confidence text NOT NULL DEFAULT 'suggested',
    reason text,
    source text,
    source_url text,
    raw_data jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

CREATE OR REPLACE FUNCTION ixbr_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_ixbr_locations_touch_updated_at ON ixbr_locations;
CREATE TRIGGER trg_ixbr_locations_touch_updated_at
BEFORE UPDATE ON ixbr_locations
FOR EACH ROW
EXECUTE FUNCTION ixbr_touch_updated_at();

DROP TRIGGER IF EXISTS trg_ixbr_participants_touch_updated_at ON ixbr_participants;
CREATE TRIGGER trg_ixbr_participants_touch_updated_at
BEFORE UPDATE ON ixbr_participants
FOR EACH ROW
EXECUTE FUNCTION ixbr_touch_updated_at();

CREATE INDEX IF NOT EXISTS idx_ixbr_participants_locality_code
    ON ixbr_participants (locality_code);

CREATE INDEX IF NOT EXISTS idx_ixbr_participants_asn
    ON ixbr_participants (asn);

CREATE INDEX IF NOT EXISTS idx_ixbr_route_server_observations_locality_code
    ON ixbr_route_server_observations (locality_code);

CREATE INDEX IF NOT EXISTS idx_ixbr_route_server_observations_peer_asn
    ON ixbr_route_server_observations (peer_asn);

CREATE INDEX IF NOT EXISTS idx_ixbr_route_server_observations_peer_ip
    ON ixbr_route_server_observations (peer_ip);

CREATE INDEX IF NOT EXISTS idx_inventory_evidence_site_id
    ON inventory_evidence (site_id);

CREATE INDEX IF NOT EXISTS idx_inventory_evidence_object_ref
    ON inventory_evidence (object_ref);

CREATE INDEX IF NOT EXISTS idx_inventory_evidence_evidence_type
    ON inventory_evidence (evidence_type);

CREATE UNIQUE INDEX IF NOT EXISTS ux_inventory_evidence_public_match
    ON inventory_evidence (evidence_scope, object_type, object_ref, evidence_type, site_id, source_url);

INSERT INTO ixbr_locations (locality_code, name, city, state, country, source_url, raw_metadata)
VALUES (
    'CE',
    'IX.br Fortaleza / PTT-CE',
    'Fortaleza',
    'CE',
    'BR',
    'https://ix.br/particip/ce',
    '{}'::jsonb
)
ON CONFLICT (locality_code) DO UPDATE SET
    name = EXCLUDED.name,
    city = EXCLUDED.city,
    state = EXCLUDED.state,
    country = EXCLUDED.country,
    source_url = EXCLUDED.source_url,
    updated_at = now();
