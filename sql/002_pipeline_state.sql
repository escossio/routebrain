CREATE TABLE IF NOT EXISTS bgp_pipeline_state (
    pipeline_name text PRIMARY KEY,
    last_raw_route_id bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO bgp_pipeline_state (pipeline_name, last_raw_route_id)
VALUES ('routeviews_raw_to_current', 0)
ON CONFLICT (pipeline_name) DO NOTHING;
