create table if not exists observed_destination_baseline_measurements (
    id bigserial primary key,
    measurement_uid text unique not null,
    baseline_uid text not null,
    destination_ip inet not null,
    measurement_type text not null,
    status text not null,
    started_at timestamptz not null default now(),
    finished_at timestamptz null,
    ping_summary jsonb not null default '{}'::jsonb,
    traceroute_summary jsonb not null default '{}'::jsonb,
    traceroute_run_id text null,
    graph_available boolean not null default false,
    errors jsonb not null default '[]'::jsonb,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists idx_observed_destination_baseline_measurements_baseline_uid
    on observed_destination_baseline_measurements (baseline_uid);
create index if not exists idx_observed_destination_baseline_measurements_destination_ip
    on observed_destination_baseline_measurements (destination_ip);
create index if not exists idx_observed_destination_baseline_measurements_measurement_type
    on observed_destination_baseline_measurements (measurement_type);
create index if not exists idx_observed_destination_baseline_measurements_started_at_desc
    on observed_destination_baseline_measurements (started_at desc);
create index if not exists idx_observed_destination_baseline_measurements_status
    on observed_destination_baseline_measurements (status);
