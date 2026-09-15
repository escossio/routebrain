create table if not exists asn_route_monitoring_targets (
    id bigserial primary key,
    asn integer not null unique,
    label text null,
    status text not null default 'monitoring',
    reason text null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    created_from_request_uid text null,
    baseline_status text not null default 'pending',
    baseline_started_at timestamptz null,
    baseline_last_checked_at timestamptz null,
    notes jsonb not null default '{}'::jsonb
);

create table if not exists asn_route_monitoring_snapshots (
    id bigserial primary key,
    asn integer not null references asn_route_monitoring_targets(asn) on delete cascade,
    snapshot_at timestamptz not null default now(),
    current_route_count integer null,
    prefix_count integer null,
    peer_count integer null,
    sample_prefixes jsonb not null default '[]'::jsonb,
    summary jsonb not null default '{}'::jsonb
);

create index if not exists idx_asn_route_monitoring_snapshots_asn_snapshot_at
    on asn_route_monitoring_snapshots (asn, snapshot_at desc);
