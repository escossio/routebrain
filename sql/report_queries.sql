-- RouteBrain dashboard queries

-- Change summary
select
    count(*) as total_changes,
    count(distinct prefix) as total_prefixes_changed,
    count(distinct peer_ip) as total_peers_affected,
    count(distinct collector) as total_collectors,
    min(detected_at) as first_change_at,
    max(detected_at) as last_change_at
from bgp_route_changes;

-- Changes by type
select change_type, count(*) as total_changes
from bgp_route_changes
group by change_type
order by total_changes desc, change_type asc;

-- Top changed prefixes
select
    prefix,
    count(*) as total_changes,
    min(detected_at) as first_change_at,
    max(detected_at) as last_change_at
from bgp_route_changes
group by prefix
order by total_changes desc, last_change_at desc, prefix asc
limit 10;

-- Top changed origin ASNs
select
    coalesce(new_origin_asn, old_origin_asn) as origin_asn,
    count(*) as total_changes
from bgp_route_changes
group by coalesce(new_origin_asn, old_origin_asn)
order by total_changes desc, origin_asn asc
limit 10;

-- Top changed peers
select
    peer_ip,
    peer_asn,
    count(*) as total_changes
from bgp_route_changes
group by peer_ip, peer_asn
order by total_changes desc, peer_ip asc, peer_asn asc
limit 10;

-- Latest changes
select
    id,
    detected_at,
    source,
    collector,
    peer_ip,
    peer_asn,
    prefix,
    change_type,
    old_next_hop,
    new_next_hop,
    old_as_path,
    new_as_path,
    old_origin_asn,
    new_origin_asn
from bgp_route_changes
order by detected_at desc, id desc
limit 20;

-- Current routes summary
select
    count(*) as total_current_routes,
    count(distinct prefix) as total_prefixes,
    count(distinct peer_ip) as total_peers,
    count(distinct peer_asn) as total_peer_asns,
    count(distinct origin_asn) as total_origin_asns,
    count(distinct collector) as total_collectors,
    min(first_seen) as first_seen_min,
    max(last_seen) as last_seen_max
from bgp_current_routes;

-- Grafana-ready views

-- Change summary
select * from v_bgp_change_summary;

-- Changes by type
select * from v_bgp_changes_by_type order by total_changes desc;

-- Top changed prefixes
select * from v_bgp_top_changed_prefixes order by total_changes desc, prefix limit 10;

-- Top changed peers
select * from v_bgp_top_changed_peers order by total_changes desc, peer_ip limit 10;

-- Latest changes
select * from v_bgp_latest_changes order by detected_at desc, id desc limit 20;

-- Current summary
select * from v_bgp_current_summary;

-- Current by origin ASN
select * from v_bgp_current_by_origin_asn order by total_routes desc, origin_asn limit 10;

-- Current by peer
select * from v_bgp_current_by_peer order by total_routes desc, peer_ip limit 10;
