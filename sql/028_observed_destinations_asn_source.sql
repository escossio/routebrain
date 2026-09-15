alter table if exists observed_destinations
    add column if not exists asn_source text null,
    add column if not exists bgp_confirmed boolean not null default false,
    add column if not exists asn_confidence text null;

create index if not exists idx_observed_destinations_asn_source on observed_destinations (asn_source);
create index if not exists idx_observed_destinations_bgp_confirmed on observed_destinations (bgp_confirmed);
create index if not exists idx_observed_destinations_asn_confidence on observed_destinations (asn_confidence);
