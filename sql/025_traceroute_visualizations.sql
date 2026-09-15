CREATE TABLE IF NOT EXISTS traceroute_visualizations (
    id bigserial PRIMARY KEY,
    visualization_uid text UNIQUE NOT NULL,
    name text NOT NULL,
    description text,
    measurement_id bigint,
    target text,
    source_label text,
    graph_version text NOT NULL,
    layout_algorithm text NOT NULL,
    selected_view_mode text NOT NULL,
    payload jsonb NOT NULL,
    node_positions jsonb NOT NULL DEFAULT '{}'::jsonb,
    cluster_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    filters jsonb NOT NULL DEFAULT '{}'::jsonb,
    notes jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_traceroute_visualizations_measurement_id
    ON traceroute_visualizations (measurement_id);

CREATE INDEX IF NOT EXISTS idx_traceroute_visualizations_target
    ON traceroute_visualizations (target);

CREATE INDEX IF NOT EXISTS idx_traceroute_visualizations_updated_at
    ON traceroute_visualizations (updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_traceroute_visualizations_selected_view_mode
    ON traceroute_visualizations (selected_view_mode);

CREATE OR REPLACE FUNCTION traceroute_visualizations_touch_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_traceroute_visualizations_touch_updated_at ON traceroute_visualizations;
CREATE TRIGGER trg_traceroute_visualizations_touch_updated_at
BEFORE UPDATE ON traceroute_visualizations
FOR EACH ROW
EXECUTE FUNCTION traceroute_visualizations_touch_updated_at();
