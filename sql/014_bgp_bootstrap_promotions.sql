CREATE TABLE IF NOT EXISTS bgp_bootstrap_promotions (
    id bigserial PRIMARY KEY,
    source_file text NOT NULL UNIQUE,
    source_key text NOT NULL UNIQUE,
    batch_id text NOT NULL,
    start_record integer NOT NULL,
    limit_records integer NOT NULL,
    staging_rows bigint NOT NULL,
    inserted_raw_rows bigint NOT NULL,
    raw_id_min bigint,
    raw_id_max bigint,
    raw_count_before bigint NOT NULL,
    raw_count_after bigint NOT NULL,
    raw_max_before bigint NOT NULL,
    raw_max_after bigint NOT NULL,
    cursor_before bigint NOT NULL,
    cursor_after bigint NOT NULL,
    promoted_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL,
    report_json text,
    notes text
);

CREATE INDEX IF NOT EXISTS idx_bgp_bootstrap_promotions_batch
    ON bgp_bootstrap_promotions (start_record, limit_records);

CREATE INDEX IF NOT EXISTS idx_bgp_bootstrap_promotions_status
    ON bgp_bootstrap_promotions (status);
