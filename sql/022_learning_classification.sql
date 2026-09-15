CREATE TABLE IF NOT EXISTS learning_classifications (
    id bigserial PRIMARY KEY,
    request_id bigint NOT NULL REFERENCES learning_requests(id) ON DELETE CASCADE,
    entity_type text NOT NULL,
    entity_value text NOT NULL,
    classification_type text NOT NULL,
    classification_value text NOT NULL,
    confidence text DEFAULT 'suggested',
    source text,
    source_ref text,
    reason text,
    data jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS learning_known_networks (
    id bigserial PRIMARY KEY,
    match_type text NOT NULL,
    match_value text NOT NULL,
    classification_type text NOT NULL,
    classification_value text NOT NULL,
    confidence text DEFAULT 'suggested',
    description text,
    source text DEFAULT 'local_seed',
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    CONSTRAINT uq_learning_known_networks UNIQUE (
        match_type,
        match_value,
        classification_type,
        classification_value
    )
);

CREATE INDEX IF NOT EXISTS idx_learning_classifications_entity_type_entity_value
    ON learning_classifications (entity_type, entity_value);

CREATE INDEX IF NOT EXISTS idx_learning_classifications_classification_type_classification_value
    ON learning_classifications (classification_type, classification_value);

CREATE INDEX IF NOT EXISTS idx_learning_known_networks_match_type_match_value
    ON learning_known_networks (match_type, match_value);

DROP TRIGGER IF EXISTS trg_learning_classifications_touch_updated_at ON learning_classifications;
CREATE TRIGGER trg_learning_classifications_touch_updated_at
BEFORE UPDATE ON learning_classifications
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_learning_known_networks_touch_updated_at ON learning_known_networks;
CREATE TRIGGER trg_learning_known_networks_touch_updated_at
BEFORE UPDATE ON learning_known_networks
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

INSERT INTO learning_known_networks (
    match_type,
    match_value,
    classification_type,
    classification_value,
    confidence,
    description,
    source
)
VALUES
    ('domain_contains', 'cloudflare', 'cdn_context', 'cloudflare', 'probable', 'Dominios com "cloudflare" costumam indicar CDN/Anycast Cloudflare.', 'local_seed'),
    ('domain_contains', 'baidu', 'country_context', 'CN', 'suggested', 'Dominios com "baidu" costumam indicar contexto operacional na China.', 'local_seed'),
    ('domain_contains', 'baidu', 'network_role', 'content_provider/search', 'suggested', 'Dominios com "baidu" costumam ser provedores de conteúdo/busca.', 'local_seed'),
    ('domain_contains', 'google', 'cdn_context', 'google', 'suggested', 'Dominios com "google" podem indicar contexto CDN/serviço Google.', 'local_seed'),
    ('domain_contains', 'akamai', 'cdn_context', 'akamai', 'probable', 'Dominios com "akamai" tendem a indicar CDN Akamai.', 'local_seed'),
    ('domain_contains', 'amazon', 'cloud_provider_context', 'aws', 'suggested', 'Dominios com "amazon" podem indicar contexto AWS/Amazon.', 'local_seed'),
    ('organization_contains', 'Cloudflare', 'cdn_context', 'cloudflare', 'probable', 'Nome de organização indica Cloudflare como CDN/contexto operacional.', 'local_seed'),
    ('organization_contains', 'Akamai', 'cdn_context', 'akamai', 'probable', 'Nome de organização indica Akamai como CDN/contexto operacional.', 'local_seed'),
    ('organization_contains', 'Amazon', 'cloud_provider_context', 'aws', 'suggested', 'Nome de organização indica Amazon/AWS como contexto operacional.', 'local_seed')
ON CONFLICT (match_type, match_value, classification_type, classification_value) DO NOTHING;
