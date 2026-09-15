create table if not exists observed_destination_runs (
    id bigserial primary key,
    run_uid text unique not null,
    source text not null default 'mikrotik_connection_tracking',
    status text not null,
    started_at timestamptz not null default now(),
    finished_at timestamptz null,
    raw_seen integer not null default 0,
    skipped_private integer not null default 0,
    skipped_invalid integer not null default 0,
    destinations_seen integer not null default 0,
    destinations_inserted integer not null default 0,
    destinations_updated integer not null default 0,
    errors jsonb not null default '[]'::jsonb,
    summary jsonb not null default '{}'::jsonb
);

create table if not exists observed_destinations (
    id bigserial primary key,
    destination_ip inet not null,
    destination_port integer null,
    protocol text null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    observation_count integer not null default 1,
    source text not null default 'mikrotik_connection_tracking',
    last_run_uid text null,
    asn integer null,
    organization text null,
    country text null,
    reverse_dns text null,
    domain_guess text null,
    category text null,
    enrichment_status text not null default 'pending',
    metadata jsonb not null default '{}'::jsonb,
    unique(destination_ip, destination_port, protocol, source)
);

create table if not exists observed_destination_dns (
    id bigserial primary key,
    domain text not null,
    address inet not null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    ttl integer null,
    source text not null default 'mikrotik_dns_cache',
    last_run_uid text null,
    metadata jsonb not null default '{}'::jsonb,
    unique(domain, address, source)
);

create index if not exists idx_observed_destination_runs_started_at_desc on observed_destination_runs (started_at desc);
create index if not exists idx_observed_destinations_destination_ip on observed_destinations (destination_ip);
create index if not exists idx_observed_destinations_asn on observed_destinations (asn);
create index if not exists idx_observed_destinations_category on observed_destinations (category);
create index if not exists idx_observed_destinations_last_seen_desc on observed_destinations (last_seen desc);
create index if not exists idx_observed_destinations_observation_count_desc on observed_destinations (observation_count desc);
create index if not exists idx_observed_destinations_domain_guess on observed_destinations (domain_guess);
create index if not exists idx_observed_destinations_organization on observed_destinations (organization);
create index if not exists idx_observed_destination_dns_address on observed_destination_dns (address);
create index if not exists idx_observed_destination_dns_domain on observed_destination_dns (domain);
