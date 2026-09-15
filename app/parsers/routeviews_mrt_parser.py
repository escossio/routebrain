from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Iterable

from mrtparse import Reader

from app.services.bgp_prefix_normalizer import build_bgp_prefix_cidr


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, OrderedDict):
        return {str(key): _to_jsonable(val) for key, val in value.items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _read_collected_at(record: dict[str, Any]) -> datetime | None:
    timestamp = record.get("timestamp")
    if not isinstance(timestamp, dict) or not timestamp:
        return None

    raw_ts = next(iter(timestamp.keys()))
    try:
        return datetime.fromtimestamp(int(raw_ts), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    if isinstance(value, dict) and value:
        candidate = next(iter(value.keys()))
        if isinstance(candidate, int):
            return candidate
        if isinstance(candidate, str) and candidate.isdigit():
            return int(candidate)
    return None


def _stringify_type(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        if not value:
            return None
        key, nested = next(iter(value.items()))
        if nested is None:
            return str(key)
        return f"{key}:{nested}"
    return str(value)


def _find_first(node: Any, keys: tuple[str, ...]) -> Any | None:
    if isinstance(node, dict):
        for key in keys:
            value = node.get(key)
            if value is not None:
                return value
        for value in node.values():
            found = _find_first(value, keys)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_first(item, keys)
            if found is not None:
                return found
    return None


def _extract_prefix_list(value: Any) -> list[str]:
    prefixes: list[str] = []

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, str):
            text = node.strip()
            if text:
                prefixes.append(text)
            return
        if isinstance(node, dict):
            if "prefix" in node and node["prefix"] is not None:
                walk(node["prefix"])
                return
            if "prefixes" in node and node["prefixes"] is not None:
                walk(node["prefixes"])
                return
            if "value" in node and len(node) == 1:
                walk(node["value"])
                return
            for item in node.values():
                walk(item)
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        text = str(node).strip()
        if text:
            prefixes.append(text)

    walk(value)

    seen: set[str] = set()
    unique_prefixes: list[str] = []
    for prefix in prefixes:
        if prefix not in seen:
            seen.add(prefix)
            unique_prefixes.append(prefix)
    return unique_prefixes


def _extract_prefix_items(value: Any) -> list[tuple[str, Any | None]]:
    items: list[tuple[str, Any | None]] = []

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, str):
            text = node.strip()
            if text:
                items.append((text, None))
            return
        if isinstance(node, dict):
            prefix_value = node.get("prefix")
            length_value = node.get("length")
            if isinstance(prefix_value, str):
                text = prefix_value.strip()
                if text:
                    items.append((text, length_value))
                    return
            if "prefixes" in node and node["prefixes"] is not None:
                walk(node["prefixes"])
                return
            if "value" in node and len(node) == 1:
                walk(node["value"])
                return
            for item in node.values():
                walk(item)
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        text = str(node).strip()
        if text:
            items.append((text, None))

    walk(value)

    seen: set[tuple[str, Any | None]] = set()
    unique_items: list[tuple[str, Any | None]] = []
    for prefix, length in items:
        key = (prefix, length)
        if key not in seen:
            seen.add(key)
            unique_items.append((prefix, length))
    return unique_items


def _extract_peer(peer_entries: list[dict[str, Any]], peer_index: int | None) -> tuple[str | None, int | None]:
    if peer_index is None or peer_index < 0 or peer_index >= len(peer_entries):
        return None, None

    peer = peer_entries[peer_index]
    peer_ip = peer.get("peer_ip")
    peer_as_raw = peer.get("peer_as")
    if isinstance(peer_as_raw, int):
        peer_asn = peer_as_raw
    elif isinstance(peer_as_raw, str) and peer_as_raw.isdigit():
        peer_asn = int(peer_as_raw)
    else:
        peer_asn = None
    return peer_ip, peer_asn


def _extract_path_attributes(
    path_attributes: list[dict[str, Any]],
) -> tuple[str | None, int | None, str | None, str | None, int | None, int | None, str | None]:
    as_path_parts: list[str] = []
    origin_type: str | None = None
    next_hop: str | None = None
    communities: str | None = None
    med: int | None = None
    local_pref: int | None = None

    for attr in path_attributes:
        attr_type = attr.get("type", {})
        value = attr.get("value")

        if attr_type == {1: "ORIGIN"}:
            if isinstance(value, dict) and value:
                origin_type = str(next(iter(value.values())))
        elif attr_type == {2: "AS_PATH"}:
            if isinstance(value, list):
                for segment in value:
                    if not isinstance(segment, dict):
                        continue
                    segment_values = segment.get("value", [])
                    if isinstance(segment_values, list):
                        as_path_parts.extend(str(item) for item in segment_values)
        elif attr_type == {3: "NEXT_HOP"}:
            if isinstance(value, str):
                next_hop = value
        elif attr_type == {4: "MULTI_EXIT_DISC"}:
            if isinstance(value, dict) and value:
                raw_med = next(iter(value.keys()))
                try:
                    med = int(raw_med)
                except (TypeError, ValueError):
                    med = None
            elif isinstance(value, int):
                med = value
        elif attr_type == {5: "LOCAL_PREF"}:
            if isinstance(value, dict) and value:
                raw_local_pref = next(iter(value.keys()))
                try:
                    local_pref = int(raw_local_pref)
                except (TypeError, ValueError):
                    local_pref = None
            elif isinstance(value, int):
                local_pref = value
        elif attr_type == {8: "COMMUNITY"}:
            if isinstance(value, list):
                communities = " ".join(str(item) for item in value) or None

    as_path = " ".join(as_path_parts) if as_path_parts else None
    origin_asn: int | None = None
    if as_path_parts:
        for token in reversed(as_path_parts):
            if token.isdigit():
                origin_asn = int(token)
                break

    return as_path, origin_asn, origin_type, next_hop, med, local_pref, communities


def _extract_rib_record(record: dict[str, Any], collector: str, peer_entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    rib_entries = record.get("rib_entries")
    if not isinstance(rib_entries, list) or not rib_entries:
        return None

    first_entry = rib_entries[0]
    if not isinstance(first_entry, dict):
        return None

    peer_index = first_entry.get("peer_index")
    peer_ip, peer_asn = _extract_peer(peer_entries, peer_index if isinstance(peer_index, int) else None)
    path_attributes = first_entry.get("path_attributes", [])
    if not isinstance(path_attributes, list):
        path_attributes = []

    as_path, origin_asn, origin_type, next_hop, med, local_pref, communities = _extract_path_attributes(path_attributes)

    raw_prefix = record.get("prefix")
    raw_length = record.get("length")
    prefix_cidr = None
    if raw_prefix is not None:
        try:
            prefix_cidr = build_bgp_prefix_cidr(raw_prefix, raw_length)
        except ValueError:
            prefix_cidr = str(raw_prefix).strip() or None

    return {
        "source": "routeviews",
        "collector": collector,
        "collected_at": _read_collected_at(record),
        "peer_ip": peer_ip,
        "peer_asn": peer_asn,
        "prefix": prefix_cidr,
        "raw_prefix": raw_prefix,
        "raw_length": raw_length,
        "next_hop": next_hop,
        "as_path": as_path,
        "origin_asn": origin_asn,
        "origin_type": origin_type,
        "med": med,
        "local_pref": local_pref,
        "communities": communities,
        "raw_record": _to_jsonable(record),
    }


def _extract_update_record(record: dict[str, Any], collector: str) -> dict[str, Any] | None:
    record_type = _stringify_type(record.get("type")) or _stringify_type(record.get("subtype"))
    path_attributes = _find_first(record, ("path_attributes", "path-attributes"))
    if not isinstance(path_attributes, list):
        path_attributes = []

    as_path, origin_asn, origin_type, next_hop, _med, _local_pref, communities = _extract_path_attributes(path_attributes)

    announced_prefixes = _extract_prefix_list(_find_first(record, ("nlri", "announced", "announce", "announced_prefixes", "prefix")))
    withdrawn_prefixes = _extract_prefix_list(_find_first(record, ("withdrawn", "withdrawn_prefixes", "withdrawn-routes")))

    if not announced_prefixes:
        fallback_prefix = _find_first(record, ("prefix",))
        if fallback_prefix is not None:
            announced_prefixes = _extract_prefix_list(fallback_prefix)

    announced_items = _extract_prefix_items(_find_first(record, ("nlri", "announced", "announce", "announced_prefixes", "prefix")))
    if not announced_items and announced_prefixes:
        announced_items = [(prefix, None) for prefix in announced_prefixes]

    normalized_prefixes: list[str] = []
    raw_lengths: list[Any | None] = []
    for announced_prefix, prefix_length in announced_items:
        try:
            normalized_prefixes.append(build_bgp_prefix_cidr(announced_prefix, prefix_length))
        except ValueError:
            normalized_prefixes.append(announced_prefix)
        raw_lengths.append(prefix_length)

    peer_ip = _find_first(record, ("peer_ip", "peer-ip", "from_ip", "from", "neighbor", "neighbor_ip"))
    if not isinstance(peer_ip, str):
        peer_ip = None

    peer_asn = _coerce_int(_find_first(record, ("peer_as", "peer_asn", "peer-as")))

    if not any([record_type, peer_ip, peer_asn, announced_prefixes, withdrawn_prefixes, as_path, next_hop, origin_asn, origin_type, communities]):
        return None

    return {
        "source": "routeviews",
        "collector": collector,
        "collected_at": _read_collected_at(record),
        "record_type": record_type,
        "peer_ip": peer_ip,
        "peer_asn": peer_asn,
        "announced_prefixes": normalized_prefixes,
        "withdrawn_prefixes": withdrawn_prefixes,
        "prefix": normalized_prefixes[0] if len(normalized_prefixes) == 1 else None,
        "raw_prefix": announced_prefixes[0] if len(announced_prefixes) == 1 else None,
        "raw_length": raw_lengths[0] if len(raw_lengths) == 1 else None,
        "next_hop": next_hop,
        "as_path": as_path,
        "origin_asn": origin_asn,
        "origin_type": origin_type,
        "communities": communities,
        "raw_record": _to_jsonable(record),
    }


def parse_rib_records(
    rib_path: str | Path,
    collector: str,
    start_record: int = 0,
    limit: int | None = None,
) -> Generator[dict[str, Any], None, None]:
    reader = Reader(str(rib_path))
    peer_entries: list[dict[str, Any]] = []
    yielded = 0
    skipped = 0

    for _ in reader:
        try:
            record = reader.data
            if not isinstance(record, dict):
                continue

            subtype = record.get("subtype", {})
            if subtype == {1: "PEER_INDEX_TABLE"}:
                entries = record.get("peer_entries", [])
                if isinstance(entries, list):
                    peer_entries = [entry for entry in entries if isinstance(entry, dict)]
                continue

            parsed = _extract_rib_record(record, collector, peer_entries)
            if parsed is None:
                continue

            if skipped < start_record:
                skipped += 1
                continue

            yielded += 1
            yield parsed
            if limit is not None and yielded >= limit:
                break
        except Exception:
            continue


def parse_update_records(
    update_path: str | Path,
    collector: str,
    start_record: int = 0,
    limit: int | None = None,
) -> Generator[dict[str, Any], None, None]:
    reader = Reader(str(update_path))
    yielded = 0
    skipped = 0

    for _ in reader:
        try:
            record = reader.data
            if not isinstance(record, dict):
                continue

            parsed = _extract_update_record(record, collector)
            if parsed is None:
                continue

            if skipped < start_record:
                skipped += 1
                continue

            yielded += 1
            yield parsed
            if limit is not None and yielded >= limit:
                break
        except Exception:
            continue
