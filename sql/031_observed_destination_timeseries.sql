create table if not exists observed_destination_run_items (
    id bigserial primary key,
    run_uid text not null,
    observed_at timestamptz not null default now(),
    destination_ip inet not null,
    destination_port integer null,
    protocol text null,
    observation_count integer not null default 1,
    asn integer null,
    asn_source text null,
    bgp_confirmed boolean not null default false,
    asn_confidence text null,
    organization text null,
    country text null,
    category text null,
    domain_guess text null,
    enrichment_status text null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    unique(run_uid, destination_ip, destination_port, protocol)
);

create index if not exists idx_observed_destination_run_items_run_uid on observed_destination_run_items (run_uid);
create index if not exists idx_observed_destination_run_items_observed_at_desc on observed_destination_run_items (observed_at desc);
create index if not exists idx_observed_destination_run_items_destination_ip on observed_destination_run_items (destination_ip);
create index if not exists idx_observed_destination_run_items_asn on observed_destination_run_items (asn);
create index if not exists idx_observed_destination_run_items_category on observed_destination_run_items (category);
create index if not exists idx_observed_destination_run_items_organization on observed_destination_run_items (organization);
create index if not exists idx_observed_destination_run_items_observation_count_desc on observed_destination_run_items (observation_count desc);
