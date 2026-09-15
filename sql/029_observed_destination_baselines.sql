create table if not exists observed_destination_baselines (
    id bigserial primary key,
    baseline_uid text unique not null,
    destination_ip inet not null,
    status text not null default 'monitoring',
    source text not null default 'observed_destination',
    promoted_at timestamptz not null default now(),
    promoted_from_observed_destination_id bigint null,
    promoted_from_run_uid text null,
    asn integer null,
    asn_source text null,
    bgp_confirmed boolean not null default false,
    asn_confidence text null,
    organization text null,
    country text null,
    category text null,
    domain_guess text null,
    reverse_dns text null,
    observation_count integer not null default 0,
    first_seen timestamptz null,
    last_seen timestamptz null,
    observed_ports jsonb not null default '[]'::jsonb,
    bgp_visibility jsonb not null default '{}'::jsonb,
    baseline_snapshot jsonb not null default '{}'::jsonb,
    notes jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique(destination_ip, source)
);

create table if not exists observed_destination_baseline_snapshots (
    id bigserial primary key,
    baseline_uid text not null,
    destination_ip inet not null,
    snapshot_at timestamptz not null default now(),
    snapshot_type text not null default 'baseline',
    summary jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists idx_observed_destination_baselines_destination_ip on observed_destination_baselines (destination_ip);
create index if not exists idx_observed_destination_baselines_status on observed_destination_baselines (status);
create index if not exists idx_observed_destination_baselines_asn on observed_destination_baselines (asn);
create index if not exists idx_observed_destination_baselines_category on observed_destination_baselines (category);
create index if not exists idx_observed_destination_baselines_promoted_at_desc on observed_destination_baselines (promoted_at desc);
create index if not exists idx_observed_destination_baselines_last_seen_desc on observed_destination_baselines (last_seen desc);
