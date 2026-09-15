CREATE TABLE IF NOT EXISTS external_enrichment_cache (
    id bigserial PRIMARY KEY,
    cache_key text UNIQUE NOT NULL,
    source text NOT NULL,
    entity_type text NOT NULL,
    entity_value text NOT NULL,
    status text NOT NULL DEFAULT 'ok',
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text,
    fetched_at timestamptz DEFAULT now(),
    expires_at timestamptz,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS external_enrichment_runs (
    id bigserial PRIMARY KEY,
    source text NOT NULL,
    entity_type text NOT NULL,
    entity_value text NOT NULL,
    status text NOT NULL,
    cache_hit boolean DEFAULT false,
    started_at timestamptz DEFAULT now(),
    finished_at timestamptz,
    error text,
    report_path text
);

CREATE TABLE IF NOT EXISTS external_asn_enrichment (
    id bigserial PRIMARY KEY,
    asn bigint UNIQUE NOT NULL,
    source_priority text,
    organization_name text,
    country text,
    network_name text,
    website text,
    looking_glass text,
    route_server text,
    network_type text,
    info_type text,
    info_prefixes4 integer,
    info_prefixes6 integer,
    peering_policy text,
    source text,
    confidence text DEFAULT 'suggested',
    raw_data jsonb DEFAULT '{}'::jsonb,
    fetched_at timestamptz,
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS external_ip_enrichment (
    id bigserial PRIMARY KEY,
    ip inet UNIQUE NOT NULL,
    asn bigint,
    organization_name text,
    country text,
    network_name text,
    source text,
    confidence text DEFAULT 'suggested',
    raw_data jsonb DEFAULT '{}'::jsonb,
    fetched_at timestamptz,
    updated_at timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_external_enrichment_cache_source_entity
    ON external_enrichment_cache (source, entity_type, entity_value);

CREATE INDEX IF NOT EXISTS idx_external_enrichment_cache_expires_at
    ON external_enrichment_cache (expires_at);

CREATE INDEX IF NOT EXISTS idx_external_asn_enrichment_asn
    ON external_asn_enrichment (asn);

CREATE INDEX IF NOT EXISTS idx_external_asn_enrichment_country
    ON external_asn_enrichment (country);

CREATE INDEX IF NOT EXISTS idx_external_asn_enrichment_organization_name
    ON external_asn_enrichment (organization_name);

CREATE INDEX IF NOT EXISTS idx_external_ip_enrichment_ip
    ON external_ip_enrichment (ip);

CREATE INDEX IF NOT EXISTS idx_external_ip_enrichment_asn
    ON external_ip_enrichment (asn);

DROP TRIGGER IF EXISTS trg_external_enrichment_cache_touch_updated_at ON external_enrichment_cache;
CREATE TRIGGER trg_external_enrichment_cache_touch_updated_at
BEFORE UPDATE ON external_enrichment_cache
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_external_asn_enrichment_touch_updated_at ON external_asn_enrichment;
CREATE TRIGGER trg_external_asn_enrichment_touch_updated_at
BEFORE UPDATE ON external_asn_enrichment
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_external_ip_enrichment_touch_updated_at ON external_ip_enrichment;
CREATE TRIGGER trg_external_ip_enrichment_touch_updated_at
BEFORE UPDATE ON external_ip_enrichment
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();
