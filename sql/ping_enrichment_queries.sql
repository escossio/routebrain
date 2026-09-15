-- RouteBrain BGP + ping enrichment queries

select * from v_bgp_ping_enrichment_summary;

select
  observed_peer_ip::text,
  observed_peer_asn,
  observed_routes,
  inventory_peer_name,
  ixp_name,
  match_status,
  ping_status,
  packet_loss_percent,
  rtt_avg_ms,
  ping_measured_at
from v_bgp_peer_with_latest_ping
where ping_status is not null
order by rtt_avg_ms desc nulls last;

select
  observed_peer_ip::text,
  observed_peer_asn,
  observed_routes,
  observed_prefixes,
  match_status
from v_bgp_peer_with_latest_ping
where ping_status is null
order by observed_routes desc
limit 20;

select
  detected_at,
  prefix::text,
  peer_ip::text,
  peer_asn,
  change_type,
  inventory_peer_name,
  ixp_name,
  ping_status,
  rtt_avg_ms,
  packet_loss_percent
from v_bgp_route_changes_with_ping
order by detected_at desc
limit 20;
