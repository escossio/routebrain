-- RouteBrain enrichment queries

-- Resumo de enriquecimento
select * from v_bgp_enrichment_summary;

-- Peers observados versus inventário
select * from v_bgp_peer_inventory_match order by observed_routes desc;

-- Mudanças enriquecidas
select
  detected_at,
  prefix::text,
  peer_ip::text,
  peer_asn,
  change_type,
  inventory_peer_name,
  inventory_connection_type,
  ixp_name,
  router_hostname
from v_bgp_route_changes_enriched
order by detected_at desc
limit 20;

-- Rotas atuais enriquecidas
select
  prefix::text,
  peer_ip::text,
  peer_asn,
  as_path,
  inventory_peer_name,
  inventory_connection_type,
  ixp_name,
  router_hostname
from v_bgp_current_routes_enriched
where enrichment_status = 'MATCHED'
order by prefix
limit 50;

-- Top peers sem inventário
select
  observed_peer_ip::text,
  observed_peer_asn,
  observed_routes,
  observed_prefixes
from v_bgp_peer_inventory_match
where match_status = 'UNMATCHED'
order by observed_routes desc
limit 20;
