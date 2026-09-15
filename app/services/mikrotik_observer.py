from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import struct
from dataclasses import dataclass
from collections import Counter
from typing import Any, Iterable

from app.services.observed_destinations import (
    create_observed_destination_run,
    finish_observed_destination_run,
    is_public_destination,
    normalize_port,
    normalize_protocol,
    upsert_observed_destination_run_item,
    upsert_observed_destination,
    upsert_observed_dns,
)
from app.services.inventory_discovery import (
    finish_discovery_run,
    ingest_discovery_candidates,
    normalize_ip,
    normalize_mac,
    sanitize_raw_summary,
    start_discovery_run,
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return struct.pack("B", length)
    if length < 0x4000:
        length |= 0x8000
        return struct.pack(">H", length)
    if length < 0x200000:
        length |= 0xC00000
        return struct.pack(">I", length)[1:]
    if length < 0x10000000:
        length |= 0xE0000000
        return struct.pack(">I", length)
    return b"\xF0" + struct.pack(">I", length)


def _decode_length(sock: socket.socket) -> int:
    first = sock.recv(1)
    if not first:
        raise EOFError("unexpected EOF while reading API length")
    b = first[0]
    if (b & 0x80) == 0x00:
        return b
    if (b & 0xC0) == 0x80:
        rest = sock.recv(1)
        return ((b & ~0xC0) << 8) + rest[0]
    if (b & 0xE0) == 0xC0:
        rest = sock.recv(2)
        return ((b & ~0xE0) << 16) + struct.unpack(">H", rest)[0]
    if (b & 0xF0) == 0xE0:
        rest = sock.recv(3)
        return ((b & ~0xF0) << 24) + struct.unpack(">I", b"\x00" + rest)[0]
    rest = sock.recv(4)
    return struct.unpack(">I", rest)[0]


def _write_word(sock: socket.socket, word: str) -> None:
    data = word.encode("utf-8")
    sock.sendall(_encode_length(len(data)) + data)


def _read_word(sock: socket.socket) -> str:
    length = _decode_length(sock)
    if length == 0:
        return ""
    data = sock.recv(length)
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected EOF while reading API word")
        data += chunk
    return data.decode("utf-8", errors="replace")


def _write_sentence(sock: socket.socket, words: Iterable[str]) -> None:
    for word in words:
        _write_word(sock, word)
    _write_word(sock, "")


def _read_sentence(sock: socket.socket) -> list[str]:
    words: list[str] = []
    while True:
        word = _read_word(sock)
        if word == "":
            return words
        words.append(word)


def _parse_attrs(words: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for word in words:
        if not word.startswith("="):
            continue
        parts = word.split("=", 2)
        if len(parts) == 3:
            out[parts[1]] = parts[2]
    return out


@dataclass
class ApiResult:
    ok: bool
    rows: list[dict[str, str]]
    errors: list[str]


class RouterOsApiClient:
    def __init__(self, host: str, port: int, timeout: int) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def __enter__(self) -> "RouterOsApiClient":
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def call(self, words: list[str]) -> ApiResult:
        assert self.sock is not None
        _write_sentence(self.sock, words)
        rows: list[dict[str, str]] = []
        errors: list[str] = []
        while True:
            sentence = _read_sentence(self.sock)
            if not sentence:
                continue
            kind = sentence[0]
            attrs = _parse_attrs(sentence[1:])
            if kind == "!re":
                rows.append(attrs)
                continue
            if kind == "!done":
                return ApiResult(ok=True, rows=rows, errors=errors)
            if kind == "!trap":
                msg = attrs.get("message") or attrs.get("category") or "routeros_api_trap"
                errors.append(msg)
                return ApiResult(ok=False, rows=rows, errors=errors)
            if kind == "!fatal":
                msg = attrs.get("message") or "routeros_api_fatal"
                errors.append(msg)
                return ApiResult(ok=False, rows=rows, errors=errors)

    def login(self, username: str, password: str) -> ApiResult:
        initial = self.call(["/login", f"=name={username}", f"=password={password}"])
        if initial.ok:
            return initial
        challenge = self.call(["/login"])
        if not challenge.rows:
            return initial
        token = challenge.rows[0].get("ret")
        if not token:
            return initial
        digest = hashlib.md5(b"\x00" + password.encode("utf-8") + bytes.fromhex(token)).hexdigest()
        return self.call(["/login", f"=name={username}", f"=response=00{digest}"])


def _collect_connections(client: RouterOsApiClient, limit: int) -> tuple[list[dict[str, Any]], int]:
    result = client.call(["/ip/firewall/connection/print"])
    rows = result.rows[:limit] if result.ok else []
    return rows, len(rows)


def _collect_dns_cache(client: RouterOsApiClient) -> tuple[list[dict[str, Any]], int]:
    result = client.call(["/ip/dns/cache/print"])
    rows = result.rows if result.ok else []
    return rows, len(rows)


def _collect_routeros_rows(client: RouterOsApiClient, command: str, limit: int | None = None) -> tuple[list[dict[str, Any]], int, list[str]]:
    result = client.call([command])
    rows = result.rows if result.ok else []
    if limit is not None:
        rows = rows[:limit]
    return rows, len(rows), result.errors


def _first_text(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return None


def _inventory_candidate(
    *,
    source_detail: str,
    evidence_type: str,
    row: dict[str, Any],
    ip: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    interface_name: str | None = None,
    interface_mac: str | None = None,
    vendor: str | None = None,
    device_type: str | None = None,
) -> dict[str, Any] | None:
    normalized_ip = normalize_ip(ip)
    normalized_mac = normalize_mac(mac)
    normalized_interface_mac = normalize_mac(interface_mac)
    if not any((normalized_ip, normalized_mac, hostname)):
        return None
    return {
        "source": "mikrotik",
        "source_detail": source_detail,
        "evidence_type": evidence_type,
        "ip": normalized_ip,
        "mac": normalized_mac,
        "hostname": hostname,
        "interface_name": interface_name,
        "interface_mac": normalized_interface_mac,
        "vendor": vendor,
        "device_type": device_type,
        "metadata": sanitize_raw_summary(row),
    }


def collect_mikrotik_host_inventory(limit: int | None = 500, dry_run: bool = False) -> dict[str, Any]:
    enabled = _env_bool("ROUTEBRAIN_MIKROTIK_ENABLED", False)
    host = os.environ["ROUTEBRAIN_MIKROTIK_HOST"]
    port = _env_int("ROUTEBRAIN_MIKROTIK_PORT", 8728)
    username = os.environ["ROUTEBRAIN_MIKROTIK_USERNAME"]
    password = os.getenv("ROUTEBRAIN_MIKROTIK_PASSWORD", "")
    timeout = _env_int("ROUTEBRAIN_MIKROTIK_TIMEOUT_SECONDS", 10)
    safe_limit = max(1, min(int(limit or 500), 2000))
    run = {
        "status": "disabled" if not enabled else "pending",
        "run_uid": None,
        "dry_run": dry_run,
        "source": "mikrotik",
        "raw_seen": 0,
        "candidates_seen": 0,
        "inserted": 0,
        "updated": 0,
        "skipped": 0,
        "errors": [],
        "preview": [],
        "sources": {},
    }
    if not enabled:
        return run
    if not password:
        run["status"] = "dependency_missing"
        run["errors"].append("missing ROUTEBRAIN_MIKROTIK_PASSWORD")
        return run

    run_uid = f"ihd_dry_{os.urandom(6).hex()}" if dry_run else None
    db_run = None
    if not dry_run:
        db_run = start_discovery_run("mikrotik", "collect", metadata={"limit": safe_limit})
        run_uid = db_run["run_uid"]
    run["run_uid"] = run_uid
    candidates: list[dict[str, Any]] = []
    errors: list[str] = []
    sources: dict[str, int] = {}

    try:
        with RouterOsApiClient(host, port, timeout) as client:
            auth = client.login(username, password)
            if not auth.ok:
                run["status"] = "auth_failed"
                run["errors"].extend(auth.errors)
                return run

            arp_rows, count, errs = _collect_routeros_rows(client, "/ip/arp/print", safe_limit)
            sources["arp"] = count
            errors.extend(errs)
            for row in arp_rows:
                item = _inventory_candidate(
                    source_detail="arp",
                    evidence_type="arp",
                    row=row,
                    ip=_first_text(row, "address"),
                    mac=_first_text(row, "mac-address"),
                    hostname=_first_text(row, "comment", "host-name"),
                    interface_name=_first_text(row, "interface"),
                )
                if item:
                    candidates.append(item)

            lease_rows, count, errs = _collect_routeros_rows(client, "/ip/dhcp-server/lease/print", safe_limit)
            sources["dhcp_lease"] = count
            errors.extend(errs)
            for row in lease_rows:
                item = _inventory_candidate(
                    source_detail="dhcp_lease",
                    evidence_type="dhcp_lease",
                    row=row,
                    ip=_first_text(row, "address", "active-address"),
                    mac=_first_text(row, "mac-address", "active-mac-address"),
                    hostname=_first_text(row, "host-name", "comment", "client-id"),
                    interface_name=_first_text(row, "server"),
                )
                if item:
                    candidates.append(item)

            dns_rows, count, errs = _collect_routeros_rows(client, "/ip/dns/cache/print", safe_limit)
            sources["dns_cache"] = count
            errors.extend(errs)
            for row in dns_rows:
                item = _inventory_candidate(
                    source_detail="dns_cache",
                    evidence_type="dns_cache",
                    row=row,
                    ip=_first_text(row, "address", "data"),
                    hostname=_first_text(row, "name"),
                )
                if item:
                    candidates.append(item)

            bridge_rows, count, errs = _collect_routeros_rows(client, "/interface/bridge/host/print", safe_limit)
            sources["bridge_host"] = count
            errors.extend(errs)
            for row in bridge_rows:
                item = _inventory_candidate(
                    source_detail="bridge_host",
                    evidence_type="bridge_host",
                    row=row,
                    mac=_first_text(row, "mac-address"),
                    interface_name=_first_text(row, "on-interface", "interface"),
                    hostname=_first_text(row, "comment"),
                )
                if item:
                    candidates.append(item)

            neighbor_rows, count, errs = _collect_routeros_rows(client, "/ip/neighbor/print", safe_limit)
            sources["neighbor"] = count
            errors.extend(errs)
            for row in neighbor_rows:
                item = _inventory_candidate(
                    source_detail="neighbor",
                    evidence_type="neighbor",
                    row=row,
                    ip=_first_text(row, "address"),
                    mac=_first_text(row, "mac-address"),
                    hostname=_first_text(row, "identity", "host-name"),
                    interface_name=_first_text(row, "interface"),
                    vendor=_first_text(row, "platform", "board"),
                    device_type=_first_text(row, "platform"),
                )
                if item:
                    candidates.append(item)

            interface_rows, count, errs = _collect_routeros_rows(client, "/interface/print", safe_limit)
            sources["interface"] = count
            errors.extend(errs)
            for row in interface_rows:
                item = _inventory_candidate(
                    source_detail="interface",
                    evidence_type="interface",
                    row=row,
                    mac=_first_text(row, "mac-address"),
                    hostname=_first_text(row, "comment"),
                    interface_name=_first_text(row, "name"),
                    interface_mac=_first_text(row, "mac-address"),
                    device_type=_first_text(row, "type"),
                )
                if item:
                    candidates.append(item)

        ingest = ingest_discovery_candidates(candidates, source="mikrotik", mode="dry_run" if dry_run else "collect", dry_run=dry_run, run_uid=run_uid)
        counters = ingest["counters"]
        run.update(counters)
        run["preview"] = ingest["preview"]
        run["sources"] = sources
        run["errors"] = errors
        run["status"] = "partial" if errors else "ok"
        if not dry_run and run_uid:
            finish_discovery_run(run_uid, run["status"], counters, metadata={"sources": sources, "dry_run": False})
    except Exception as exc:
        run["status"] = "error"
        run["errors"].append(f"{type(exc).__name__}: {exc}")
        if not dry_run and run_uid:
            finish_discovery_run(run_uid, "error", run, error_message=f"{type(exc).__name__}: {exc}")
    return run


def collect_mikrotik_observed_destinations(*, limit: int = 1000, dry_run: bool = False) -> dict[str, Any]:
    enabled = _env_bool("ROUTEBRAIN_MIKROTIK_ENABLED", False)
    observed_enabled = _env_bool("ROUTEBRAIN_OBSERVED_DESTINATIONS_ENABLED", False)
    host = os.environ["ROUTEBRAIN_MIKROTIK_HOST"]
    port = _env_int("ROUTEBRAIN_MIKROTIK_PORT", 8728)
    username = os.environ["ROUTEBRAIN_MIKROTIK_USERNAME"]
    password = os.getenv("ROUTEBRAIN_MIKROTIK_PASSWORD", "")
    timeout = _env_int("ROUTEBRAIN_MIKROTIK_TIMEOUT_SECONDS", 10)
    ignore_private = _env_bool("ROUTEBRAIN_OBSERVED_DESTINATIONS_IGNORE_PRIVATE", True)

    run = {
        "status": "disabled" if not enabled or not observed_enabled else "pending",
        "run_uid": None,
        "raw_seen": 0,
        "skipped_private": 0,
        "skipped_invalid": 0,
        "destinations_seen": 0,
        "destinations_inserted": 0,
        "destinations_updated": 0,
        "dns_entries_inserted": 0,
        "dns_entries_updated": 0,
        "errors": [],
        "top_destinations": [],
        "top_ports_protocols": [],
    }
    if not enabled or not observed_enabled:
        return run
    if not password:
        run["status"] = "dependency_missing"
        run["errors"].append("missing ROUTEBRAIN_MIKROTIK_PASSWORD")
        return run

    run_uid = f"odr_{os.urandom(8).hex()}"
    run["run_uid"] = run_uid
    if not dry_run:
        create_observed_destination_run("mikrotik_connection_tracking", "running", run_uid=run_uid)
    destinations_inserted = destinations_updated = 0
    dns_inserted = dns_updated = 0
    raw_seen = skipped_private = skipped_invalid = destinations_seen = 0
    errors: list[dict[str, Any]] = []
    destination_counter: Counter[str] = Counter()
    port_protocol_counter: Counter[str] = Counter()
    run_item_counter: Counter[tuple[str, int | None, str | None]] = Counter()

    try:
        with RouterOsApiClient(host, port, timeout) as client:
            auth = client.login(username, password)
            if not auth.ok:
                run["status"] = "auth_failed"
                errors.extend({"error": e} for e in auth.errors)
                return run

            rows, count = _collect_connections(client, limit)
            raw_seen = count
            for row in rows:
                dst = row.get("dst-address") or row.get("dst-address6") or row.get("dst-address-and-port")
                protocol = normalize_protocol(row.get("protocol"))
                port_value = normalize_port(row.get("dst-port") or row.get("dst-port-v6"))
                if not dst:
                    skipped_invalid += 1
                    continue
                addr_text = str(dst).split(":", 1)[0]
                try:
                    addr = ipaddress.ip_address(addr_text)
                except ValueError:
                    skipped_invalid += 1
                    continue
                if ignore_private and not is_public_destination(str(addr)):
                    skipped_private += 1
                    continue
                metadata = {
                    "protocol": protocol,
                    "destination_port": port_value,
                    "connection_seen": True,
                }
                inserted = upsert_observed_destination(
                    str(addr),
                    port_value,
                    protocol,
                    "mikrotik_connection_tracking",
                    run_uid,
                    metadata=metadata,
                )
                destinations_seen += 1
                destination_counter[str(addr)] += 1
                port_protocol_counter[f"{port_value or 'unknown'}/{protocol or 'unknown'}"] += 1
                run_item_counter[(str(addr), port_value, protocol)] += 1
                if inserted:
                    destinations_inserted += 1
                else:
                    destinations_updated += 1

            dns_rows, dns_count = _collect_dns_cache(client)
            for row in dns_rows:
                domain = row.get("name") or row.get("domain")
                address = row.get("address")
                if not domain or not address:
                    continue
                ttl = None
                ttl_raw = row.get("ttl")
                if ttl_raw not in (None, ""):
                    try:
                        ttl = int(ttl_raw)
                    except ValueError:
                        ttl = None
                inserted = upsert_observed_dns(
                    str(domain).strip(),
                    str(address).strip(),
                    ttl,
                    "mikrotik_dns_cache",
                    run_uid,
                    metadata={"source": "mikrotik_dns_cache"},
                )
                if inserted:
                    dns_inserted += 1
                else:
                    dns_updated += 1

            for (destination_ip, port_value, protocol), count in run_item_counter.items():
                upsert_observed_destination_run_item(
                    run_uid,
                    destination_ip,
                    port_value,
                    protocol,
                    observation_count=count,
                    metadata={
                        "source": "mikrotik_connection_tracking",
                        "connection_seen": True,
                        "run_uid": run_uid,
                    },
                )

        run["status"] = "ok"
    except Exception as exc:
        run["status"] = "error"
        errors.append({"error": f"{type(exc).__name__}: {exc}"})
    finally:
        summary = {
            "dns_entries_inserted": dns_inserted,
            "dns_entries_updated": dns_updated,
            "limit": limit,
            "dry_run": dry_run,
            "top_destinations": [
                {"destination_ip": ip, "observations": count}
                for ip, count in destination_counter.most_common(10)
            ],
            "top_ports_protocols": [
                {"port_protocol": value, "observations": count}
                for value, count in port_protocol_counter.most_common(10)
            ],
        }
        if not dry_run and run["status"] == "ok":
            finish_observed_destination_run(
                run_uid,
                run["status"],
                raw_seen=raw_seen,
                skipped_private=skipped_private,
                skipped_invalid=skipped_invalid,
                destinations_seen=destinations_seen,
                destinations_inserted=destinations_inserted,
                destinations_updated=destinations_updated,
                errors=errors,
                summary=summary,
            )
        elif not dry_run:
            finish_observed_destination_run(
                run_uid,
                run["status"],
                raw_seen=raw_seen,
                skipped_private=skipped_private,
                skipped_invalid=skipped_invalid,
                destinations_seen=destinations_seen,
                destinations_inserted=destinations_inserted,
                destinations_updated=destinations_updated,
                errors=errors,
                summary=summary,
            )
        run.update(
            {
                "raw_seen": raw_seen,
                "skipped_private": skipped_private,
                "skipped_invalid": skipped_invalid,
                "destinations_seen": destinations_seen,
                "destinations_inserted": destinations_inserted,
                "destinations_updated": destinations_updated,
                "dns_entries_inserted": dns_inserted,
                "dns_entries_updated": dns_updated,
                "errors": errors,
                "top_destinations": summary["top_destinations"],
                "top_ports_protocols": summary["top_ports_protocols"],
            }
        )
    return run
