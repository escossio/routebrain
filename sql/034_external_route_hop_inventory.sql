CREATE TABLE IF NOT EXISTS external_route_services (
    id bigserial PRIMARY KEY,
    service_slug text NOT NULL UNIQUE,
    display_name text NOT NULL,
    category text NOT NULL DEFAULT 'service',
    description text,
    is_ptt boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (service_slug <> ''),
    CHECK (category <> '')
);

CREATE TABLE IF NOT EXISTS external_route_targets (
    id bigserial PRIMARY KEY,
    service_id bigint NOT NULL REFERENCES external_route_services(id) ON DELETE CASCADE,
    target_host text NOT NULL,
    target_kind text NOT NULL DEFAULT 'domain',
    target_label text,
    notes text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (service_id, target_host),
    CHECK (target_host <> ''),
    CHECK (target_kind IN ('domain', 'hostname', 'ip', 'ix', 'context'))
);

CREATE TABLE IF NOT EXISTS external_route_hops (
    id bigserial PRIMARY KEY,
    hop_ip inet NOT NULL UNIQUE,
    reverse_dns text,
    asn bigint,
    organization text,
    country text,
    category text NOT NULL DEFAULT 'unknown',
    role text NOT NULL DEFAULT 'unknown',
    confidence text NOT NULL DEFAULT 'unknown',
    confidence_rank smallint NOT NULL DEFAULT 0,
    source_priority text,
    evidence_sources jsonb NOT NULL DEFAULT '{}'::jsonb,
    observation_count integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (category <> ''),
    CHECK (role <> ''),
    CHECK (confidence <> ''),
    CHECK (confidence_rank >= 0)
);

CREATE TABLE IF NOT EXISTS external_route_observations (
    id bigserial PRIMARY KEY,
    observation_uid text NOT NULL UNIQUE,
    service_id bigint NOT NULL REFERENCES external_route_services(id) ON DELETE CASCADE,
    target_id bigint REFERENCES external_route_targets(id) ON DELETE SET NULL,
    hop_id bigint REFERENCES external_route_hops(id) ON DELETE CASCADE,
    target_host text,
    source_kind text NOT NULL,
    source_ref text NOT NULL,
    source_key text NOT NULL,
    hop_number integer,
    hop_role text,
    observed_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (source_kind <> ''),
    CHECK (source_ref <> ''),
    CHECK (source_key <> '')
);

CREATE TABLE IF NOT EXISTS external_route_service_hop_summary (
    id bigserial PRIMARY KEY,
    service_id bigint NOT NULL REFERENCES external_route_services(id) ON DELETE CASCADE,
    hop_id bigint NOT NULL REFERENCES external_route_hops(id) ON DELETE CASCADE,
    hop_ip inet NOT NULL,
    occurrence_count integer NOT NULL DEFAULT 0,
    target_count integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    min_hop_number integer,
    max_hop_number integer,
    asn bigint,
    organization text,
    country text,
    category text NOT NULL DEFAULT 'unknown',
    role text NOT NULL DEFAULT 'unknown',
    confidence text NOT NULL DEFAULT 'unknown',
    confidence_rank smallint NOT NULL DEFAULT 0,
    source_priority text,
    target_hosts jsonb NOT NULL DEFAULT '[]'::jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (service_id, hop_id)
);

CREATE INDEX IF NOT EXISTS idx_external_route_services_category
    ON external_route_services (category);

CREATE INDEX IF NOT EXISTS idx_external_route_targets_service_id
    ON external_route_targets (service_id);

CREATE INDEX IF NOT EXISTS idx_external_route_targets_target_host
    ON external_route_targets (target_host);

CREATE INDEX IF NOT EXISTS idx_external_route_hops_asn
    ON external_route_hops (asn);

CREATE INDEX IF NOT EXISTS idx_external_route_hops_category
    ON external_route_hops (category);

CREATE INDEX IF NOT EXISTS idx_external_route_hops_role
    ON external_route_hops (role);

CREATE INDEX IF NOT EXISTS idx_external_route_hops_confidence
    ON external_route_hops (confidence);

CREATE INDEX IF NOT EXISTS idx_external_route_hops_last_seen_at
    ON external_route_hops (last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_external_route_observations_service_id
    ON external_route_observations (service_id);

CREATE INDEX IF NOT EXISTS idx_external_route_observations_target_id
    ON external_route_observations (target_id);

CREATE INDEX IF NOT EXISTS idx_external_route_observations_hop_id
    ON external_route_observations (hop_id);

CREATE INDEX IF NOT EXISTS idx_external_route_observations_observed_at
    ON external_route_observations (observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_external_route_service_hop_summary_service_id
    ON external_route_service_hop_summary (service_id);

CREATE INDEX IF NOT EXISTS idx_external_route_service_hop_summary_hop_id
    ON external_route_service_hop_summary (hop_id);

CREATE INDEX IF NOT EXISTS idx_external_route_service_hop_summary_asn
    ON external_route_service_hop_summary (asn);

CREATE INDEX IF NOT EXISTS idx_external_route_service_hop_summary_role
    ON external_route_service_hop_summary (role);

CREATE INDEX IF NOT EXISTS idx_external_route_service_hop_summary_category
    ON external_route_service_hop_summary (category);

DROP TRIGGER IF EXISTS trg_external_route_services_touch_updated_at ON external_route_services;
CREATE TRIGGER trg_external_route_services_touch_updated_at
BEFORE UPDATE ON external_route_services
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_external_route_targets_touch_updated_at ON external_route_targets;
CREATE TRIGGER trg_external_route_targets_touch_updated_at
BEFORE UPDATE ON external_route_targets
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_external_route_hops_touch_updated_at ON external_route_hops;
CREATE TRIGGER trg_external_route_hops_touch_updated_at
BEFORE UPDATE ON external_route_hops
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_external_route_service_hop_summary_touch_updated_at ON external_route_service_hop_summary;
CREATE TRIGGER trg_external_route_service_hop_summary_touch_updated_at
BEFORE UPDATE ON external_route_service_hop_summary
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

INSERT INTO external_route_services (service_slug, display_name, category, description, is_ptt)
VALUES
    ('google', 'Google', 'service', 'Rotas externas associadas a google.com, gstatic.com e googleapis.com.', false),
    ('youtube', 'YouTube', 'service', 'Rotas externas associadas a youtube.com, googlevideo.com e ytimg.com.', false),
    ('facebook', 'Facebook', 'service', 'Rotas externas associadas a facebook.com e fbcdn.net.', false),
    ('instagram', 'Instagram', 'service', 'Rotas externas associadas a instagram.com e cdninstagram.com.', false),
    ('whatsapp', 'WhatsApp', 'service', 'Rotas externas associadas a whatsapp.com, web.whatsapp.com e whatsapp.net.', false),
    ('netflix', 'Netflix', 'service', 'Rotas externas associadas a netflix.com, nflxvideo.net e nflximg.net.', false),
    ('ptt', 'PTT / IX', 'ix', 'Contexto de PTT/IX observável em hops externos, sem inventar IPs ou hops.', true),
    ('cloudflare', 'Cloudflare', 'service', 'Rotas e hops associados a cloudflare.com e 1.1.1.1.', false)
ON CONFLICT (service_slug) DO UPDATE
SET display_name = EXCLUDED.display_name,
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    is_ptt = EXCLUDED.is_ptt,
    enabled = true,
    updated_at = now();

WITH service_targets AS (
    SELECT s.id AS service_id, v.target_host, v.target_kind, v.target_label, v.notes
    FROM external_route_services s
    JOIN (
        VALUES
            ('google', 'google.com', 'domain', 'google.com', 'seed'),
            ('google', 'gstatic.com', 'domain', 'gstatic.com', 'seed'),
            ('google', 'googleapis.com', 'domain', 'googleapis.com', 'seed'),
            ('youtube', 'youtube.com', 'domain', 'youtube.com', 'seed'),
            ('youtube', 'googlevideo.com', 'domain', 'googlevideo.com', 'seed'),
            ('youtube', 'ytimg.com', 'domain', 'ytimg.com', 'seed'),
            ('facebook', 'facebook.com', 'domain', 'facebook.com', 'seed'),
            ('facebook', 'fbcdn.net', 'domain', 'fbcdn.net', 'seed'),
            ('instagram', 'instagram.com', 'domain', 'instagram.com', 'seed'),
            ('instagram', 'cdninstagram.com', 'domain', 'cdninstagram.com', 'seed'),
            ('whatsapp', 'whatsapp.com', 'domain', 'whatsapp.com', 'seed'),
            ('whatsapp', 'web.whatsapp.com', 'hostname', 'web.whatsapp.com', 'seed'),
            ('whatsapp', 'whatsapp.net', 'domain', 'whatsapp.net', 'seed'),
            ('netflix', 'netflix.com', 'domain', 'netflix.com', 'seed'),
            ('netflix', 'nflxvideo.net', 'domain', 'nflxvideo.net', 'seed'),
            ('netflix', 'nflximg.net', 'domain', 'nflximg.net', 'seed'),
            ('cloudflare', 'cloudflare.com', 'domain', 'cloudflare.com', 'seed'),
            ('cloudflare', '1.1.1.1', 'ip', '1.1.1.1', 'seed')
    ) AS v(service_slug, target_host, target_kind, target_label, notes)
      ON s.service_slug = v.service_slug
)
INSERT INTO external_route_targets (service_id, target_host, target_kind, target_label, notes)
SELECT service_id, target_host, target_kind, target_label, notes
FROM service_targets
ON CONFLICT (service_id, target_host) DO UPDATE
SET target_kind = EXCLUDED.target_kind,
    target_label = EXCLUDED.target_label,
    notes = EXCLUDED.notes,
    updated_at = now();
