from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.connection import get_connection
from app.services.pipeline_lock import try_advisory_lock
from scripts.bootstrap_worker_utils import ensure_project_manifest_layout, json_write, timestamp_slug

STAGING_TABLE = "bgp_bootstrap_staging"
PROMOTIONS_TABLE = "bgp_bootstrap_promotions"
PIPELINE_NAME = "routeviews_raw_to_current"
LOCK_NAME = "routebrain:bootstrap_promote_bgp"


@dataclass(frozen=True)
class DeepStats:
    staging_rows: int
    distinct_collectors: int
    distinct_peers: int
    distinct_prefixes: int
    distinct_origin_asns: int
    principal_duplicate_rows: int
    exact_duplicate_rows: int
    source_null_rows: int
    collector_null_rows: int
    collected_at_null_rows: int
    peer_ip_null_rows: int
    prefix_null_rows: int
    raw_record_null_rows: int
    collector_mismatch_rows: int
    source_mismatch_rows: int
    source_file: str
    source_key: str
    samples: list[dict[str, Any]]
    already_promoted: bool


def _normalize_source_file(source_file: str) -> tuple[str, int, int]:
    name = Path(source_file).name
    match = re.fullmatch(r"bgp_bootstrap_routeviews2_start(\d+)_limit(\d+)\.csv", name)
    if not match:
        raise SystemExit(
            "source-file inválido. Use o formato "
            "bgp_bootstrap_routeviews2_start<START>_limit<LIMIT>.csv"
        )
    start_record = int(match.group(1))
    limit_records = int(match.group(2))
    return name, start_record, limit_records


def _load_validation_json(report_stem: str) -> dict[str, Any]:
    path = PROJECT_ROOT / "data" / "processed" / "bootstrap_worker_reports" / f"{report_stem}_validation.json"
    if not path.exists():
        raise SystemExit(f"Validation JSON não encontrado: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_promotions_schema(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS bgp_bootstrap_promotions (
            id bigserial PRIMARY KEY,
            source_file text NOT NULL UNIQUE,
            source_key text NOT NULL UNIQUE,
            batch_id text NOT NULL,
            start_record integer NOT NULL,
            limit_records integer NOT NULL,
            staging_rows bigint NOT NULL,
            inserted_raw_rows bigint NOT NULL,
            raw_id_min bigint,
            raw_id_max bigint,
            raw_count_before bigint NOT NULL,
            raw_count_after bigint NOT NULL,
            raw_max_before bigint NOT NULL,
            raw_max_after bigint NOT NULL,
            cursor_before bigint NOT NULL,
            cursor_after bigint NOT NULL,
            promoted_at timestamptz NOT NULL DEFAULT now(),
            status text NOT NULL,
            report_json text,
            notes text
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_bgp_bootstrap_promotions_batch ON bgp_bootstrap_promotions (start_record, limit_records)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_bgp_bootstrap_promotions_status ON bgp_bootstrap_promotions (status)"
    )


def _pattern_for_source_file(source_file: str) -> str:
    return f"%/{source_file}::%"


def _find_staging_source_key(cur, source_file: str) -> str:
    pattern = _pattern_for_source_file(source_file)
    cur.execute(
        f"""
            select distinct source_file
              from {STAGING_TABLE}
             where source_file like %s
             order by source_file
        """,
        [pattern],
    )
    rows = [row[0] for row in cur.fetchall()]
    if not rows:
        raise SystemExit(f"Nenhuma staging encontrada para source_file={source_file}")
    if len(rows) > 1:
        raise SystemExit(f"Mais de uma staging encontrada para {source_file}: {rows}")
    return str(rows[0])


def _count_one(cur, sql: str, params: list[Any] | tuple[Any, ...] | None = None) -> int:
    cur.execute(sql, params or [])
    return int(cur.fetchone()[0])


def _fetch_sample_rows(cur, source_key: str) -> list[dict[str, Any]]:
    with cur.connection.cursor(row_factory=None) as sample_cur:
        sample_cur.execute(
            f"""
                select id, source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop,
                       as_path, origin_asn, origin_type, med, local_pref, communities
                  from {STAGING_TABLE}
                 where source_file = %s
                 order by id asc
                 limit 10
            """,
            [source_key],
        )
        rows = sample_cur.fetchall()
    return [
        {
            "id": row[0],
            "source": row[1],
            "collector": row[2],
            "collected_at": row[3].isoformat() if hasattr(row[3], "isoformat") else row[3],
            "peer_ip": row[4],
            "peer_asn": row[5],
            "prefix": row[6],
            "next_hop": row[7],
            "as_path": row[8],
            "origin_asn": row[9],
            "origin_type": row[10],
            "med": row[11],
            "local_pref": row[12],
            "communities": row[13],
        }
        for row in rows
    ]


def _deep_validation(cur, source_file: str, expected_start: int, expected_limit: int, validation_json: dict[str, Any]) -> DeepStats:
    source_key = _find_staging_source_key(cur, source_file)

    staging_rows = _count_one(cur, f"select count(*) from {STAGING_TABLE} where source_file = %s", [source_key])
    distinct_collectors = _count_one(
        cur,
        f"select count(distinct collector) from {STAGING_TABLE} where source_file = %s",
        [source_key],
    )
    distinct_peers = _count_one(cur, f"select count(distinct peer_ip) from {STAGING_TABLE} where source_file = %s", [source_key])
    distinct_prefixes = _count_one(
        cur,
        f"select count(distinct prefix) from {STAGING_TABLE} where source_file = %s",
        [source_key],
    )
    distinct_origin_asns = _count_one(
        cur,
        f"select count(distinct origin_asn) from {STAGING_TABLE} where source_file = %s",
        [source_key],
    )

    principal_duplicate_rows = _count_one(
        cur,
        f"""
            select coalesce(sum(dup_count - 1), 0)
              from (
                    select count(*) as dup_count
                      from {STAGING_TABLE}
                     where source_file = %s
                  group by collector, peer_ip, prefix
                    having count(*) > 1
              ) dupes
        """,
        [source_key],
    )
    exact_duplicate_rows = _count_one(
        cur,
        f"""
            select coalesce(sum(dup_count - 1), 0)
              from (
                    select count(*) as dup_count
                      from {STAGING_TABLE}
                     where source_file = %s
                  group by source, collector, collected_at, peer_ip, peer_asn, prefix, next_hop, as_path,
                           origin_asn, origin_type, med, local_pref, communities, raw_record
                    having count(*) > 1
              ) dupes
        """,
        [source_key],
    )

    source_null_rows = _count_one(cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and source is null", [source_key])
    collector_null_rows = _count_one(
        cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and collector is null", [source_key]
    )
    collected_at_null_rows = _count_one(
        cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and collected_at is null", [source_key]
    )
    peer_ip_null_rows = _count_one(cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and peer_ip is null", [source_key])
    prefix_null_rows = _count_one(cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and prefix is null", [source_key])
    raw_record_null_rows = _count_one(
        cur, f"select count(*) from {STAGING_TABLE} where source_file = %s and raw_record is null", [source_key]
    )
    collector_mismatch_rows = _count_one(
        cur,
        f"select count(*) from {STAGING_TABLE} where source_file = %s and collector <> 'route-views2'",
        [source_key],
    )
    source_mismatch_rows = _count_one(
        cur,
        f"select count(*) from {STAGING_TABLE} where source_file = %s and source <> 'routeviews'",
        [source_key],
    )

    already_promoted = _count_one(
        cur,
        f"select count(*) from {PROMOTIONS_TABLE} where source_file = %s",
        [source_file],
    ) > 0

    samples = _fetch_sample_rows(cur, source_key)

    return DeepStats(
        staging_rows=staging_rows,
        distinct_collectors=distinct_collectors,
        distinct_peers=distinct_peers,
        distinct_prefixes=distinct_prefixes,
        distinct_origin_asns=distinct_origin_asns,
        principal_duplicate_rows=principal_duplicate_rows,
        exact_duplicate_rows=exact_duplicate_rows,
        source_null_rows=source_null_rows,
        collector_null_rows=collector_null_rows,
        collected_at_null_rows=collected_at_null_rows,
        peer_ip_null_rows=peer_ip_null_rows,
        prefix_null_rows=prefix_null_rows,
        raw_record_null_rows=raw_record_null_rows,
        collector_mismatch_rows=collector_mismatch_rows,
        source_mismatch_rows=source_mismatch_rows,
        source_file=source_file,
        source_key=source_key,
        samples=samples,
        already_promoted=already_promoted,
    )


def _load_raw_counts(cur) -> tuple[int, int, int]:
    raw_count = _count_one(cur, "select count(*) from bgp_raw_routes")
    raw_max = _count_one(cur, "select coalesce(max(id), 0) from bgp_raw_routes")
    cursor = _count_one(
        cur,
        "select coalesce(last_raw_route_id, 0) from bgp_pipeline_state where pipeline_name = %s",
        [PIPELINE_NAME],
    )
    return raw_count, raw_max, cursor


def _build_report(
    *,
    mode: str,
    source_file: str,
    batch_id: str,
    start_record: int,
    limit_records: int,
    deep: DeepStats,
    validation_json: dict[str, Any],
    comparison: dict[str, Any],
    raw_before: dict[str, int] | None = None,
    raw_after: dict[str, int] | None = None,
    promotion: dict[str, Any] | None = None,
    allow_duplicates: bool = False,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "mode": mode,
        "source_file": source_file,
        "source_key": deep.source_key,
        "batch_id": batch_id,
        "start_record": start_record,
        "limit_records": limit_records,
        "allow_duplicates": allow_duplicates,
        "staging": {
            "staging_rows": deep.staging_rows,
            "distinct_collectors": deep.distinct_collectors,
            "distinct_peers": deep.distinct_peers,
            "distinct_prefixes": deep.distinct_prefixes,
            "distinct_origin_asns": deep.distinct_origin_asns,
            "principal_duplicate_rows": deep.principal_duplicate_rows,
            "exact_duplicate_rows": deep.exact_duplicate_rows,
            "nulls": {
                "source": deep.source_null_rows,
                "collector": deep.collector_null_rows,
                "collected_at": deep.collected_at_null_rows,
                "peer_ip": deep.peer_ip_null_rows,
                "prefix": deep.prefix_null_rows,
                "raw_record": deep.raw_record_null_rows,
            },
            "collector_mismatch_rows": deep.collector_mismatch_rows,
            "source_mismatch_rows": deep.source_mismatch_rows,
            "samples": deep.samples,
            "already_promoted": deep.already_promoted,
        },
        "validation": validation_json,
        "comparison": comparison,
        "raw": {
            "before": raw_before or {},
            "after": raw_after or {},
        },
        "promotion": promotion or {},
        "status": "DRY_RUN_READY" if mode == "DRY_RUN" else "PROMOTED",
    }
    return report


def _report_text(report: dict[str, Any]) -> str:
    lines = [
        f"mode={report['mode']}",
        f"source_file={report['source_file']}",
        f"source_key={report['source_key']}",
        f"batch_id={report['batch_id']}",
        f"start_record={report['start_record']}",
        f"limit_records={report['limit_records']}",
        f"staging_rows={report['staging']['staging_rows']}",
        f"distinct_collectors={report['staging']['distinct_collectors']}",
        f"distinct_peers={report['staging']['distinct_peers']}",
        f"distinct_prefixes={report['staging']['distinct_prefixes']}",
        f"distinct_origin_asns={report['staging']['distinct_origin_asns']}",
        f"principal_duplicate_rows={report['staging']['principal_duplicate_rows']}",
        f"exact_duplicate_rows={report['staging']['exact_duplicate_rows']}",
        f"collector_mismatch_rows={report['staging']['collector_mismatch_rows']}",
        f"source_mismatch_rows={report['staging']['source_mismatch_rows']}",
        f"already_promoted={report['staging']['already_promoted']}",
        f"comparison_all_match={report['comparison']['all_match']}",
        f"raw_before={report['raw'].get('before')}",
        f"raw_after={report['raw'].get('after')}",
        f"promotion_status={report['promotion'].get('status')}",
        f"status={report['status']}",
        "",
    ]
    return "\n".join(lines)


def _promoted_rows_count(cur, source_file: str) -> int:
    return _count_one(
        cur,
        f"select count(*) from {PROMOTIONS_TABLE} where source_file = %s",
        [source_file],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validação profunda e promoção controlada de staging BGP para bgp_raw_routes.")
    parser.add_argument("--source-file", required=True, help="Nome lógico do CSV importado na staging.")
    parser.add_argument("--start-record", required=True, type=int, help="start-record esperado.")
    parser.add_argument("--limit-records", required=True, type=int, help="limit esperado.")
    parser.add_argument("--expected-cursor", required=True, type=int, help="Cursor esperado em bgp_pipeline_state e max(id) em raw.")
    parser.add_argument("--dry-run", action="store_true", help="Somente valida e relata; não promove.")
    parser.add_argument(
        "--allow-duplicates",
        action="store_true",
        help="Permite duplicados exatos na staging. Por padrão, isso falha se forem encontrados.",
    )
    parser.add_argument("--report-json", type=Path, default=None, help="Caminho do relatório JSON.")
    parser.add_argument("--report-text", type=Path, default=None, help="Caminho do relatório TXT.")
    args = parser.parse_args()

    source_file, parsed_start, parsed_limit = _normalize_source_file(args.source_file)
    if parsed_start != args.start_record or parsed_limit != args.limit_records:
        raise SystemExit(
            f"start/limit no nome do arquivo não batem com os argumentos: "
            f"arquivo=({parsed_start}, {parsed_limit}) args=({args.start_record}, {args.limit_records})"
        )

    batch_id = Path(source_file).stem
    validation_json = _load_validation_json(batch_id)

    report_json = args.report_json or (
        PROJECT_ROOT
        / "data"
        / "processed"
        / "bootstrap_worker_reports"
        / (
            f"{batch_id}_staging_deep_validation.json"
            if args.dry_run
            else f"{batch_id}_promotion.json"
        )
    )
    report_text = args.report_text or report_json.with_suffix(".txt")

    with get_connection() as conn:
        with conn.cursor() as cur:
            _ensure_promotions_schema(cur)
            deep = _deep_validation(cur, source_file, args.start_record, args.limit_records, validation_json)
            comparison = {
                "total_rows_match": deep.staging_rows == int(validation_json.get("total_rows", -1) or -1),
                "distinct_collectors_match": deep.distinct_collectors
                == int(validation_json.get("distinct_collectors", -1) or -1),
                "distinct_peers_match": deep.distinct_peers == int(validation_json.get("distinct_peers", -1) or -1),
                "distinct_prefixes_match": deep.distinct_prefixes
                == int(validation_json.get("distinct_prefixes", -1) or -1),
                "distinct_origin_asns_match": deep.distinct_origin_asns
                == int(validation_json.get("distinct_origin_asns", -1) or -1),
                "principal_duplicate_rows_match": deep.principal_duplicate_rows
                == int(validation_json.get("duplicate_rows", -1) or -1),
            }
            comparison["all_match"] = all(comparison.values())

            raw_before_count = raw_before_max = cursor_before = None
            raw_after_count = raw_after_max = cursor_after = None
            promotion_info: dict[str, Any] = {}

            if args.dry_run:
                raw_count, raw_max, cursor = _load_raw_counts(cur)
                raw_before_count = raw_count
                raw_before_max = raw_max
                cursor_before = cursor
                if cursor != args.expected_cursor or raw_max != args.expected_cursor:
                    comparison["cursor_match"] = False
                else:
                    comparison["cursor_match"] = True
                promotion_info = {
                    "would_insert_rows": deep.staging_rows,
                    "expected_next_raw_id_min": raw_max + 1,
                    "expected_next_raw_id_max": raw_max + deep.staging_rows,
                    "would_promote": not deep.already_promoted and (deep.exact_duplicate_rows == 0 or args.allow_duplicates),
                }
                report = _build_report(
                    mode="DRY_RUN",
                    source_file=source_file,
                    batch_id=batch_id,
                    start_record=args.start_record,
                    limit_records=args.limit_records,
                    deep=deep,
                    validation_json=validation_json,
                    comparison=comparison,
                    raw_before={"count": raw_before_count or 0, "max_id": raw_before_max or 0, "cursor": cursor_before or 0},
                    promotion=promotion_info,
                    allow_duplicates=args.allow_duplicates,
                )
                json_write(report_json, report)
                report_text.write_text(_report_text(report), encoding="utf-8")
                print(json.dumps(report, indent=2, ensure_ascii=False))
                return

            lock_conn = conn
            if not try_advisory_lock(lock_conn, LOCK_NAME):
                raise SystemExit("Outro processo de promoção já está em execução.")

            raw_count_before, raw_max_before, cursor_before = _load_raw_counts(cur)
            if cursor_before != args.expected_cursor:
                raise SystemExit(
                    f"Cursor inesperado. esperado={args.expected_cursor} atual={cursor_before}"
                )
            if raw_max_before != args.expected_cursor:
                raise SystemExit(
                    f"max(id) inesperado em bgp_raw_routes. esperado={args.expected_cursor} atual={raw_max_before}"
                )
            if deep.already_promoted or _promoted_rows_count(cur, source_file) > 0:
                raise SystemExit(f"source_file já promovido: {source_file}")
            if deep.exact_duplicate_rows > 0 and not args.allow_duplicates:
                raise SystemExit(
                    f"Duplicados exatos encontrados na staging ({deep.exact_duplicate_rows}). "
                    "Reexecute com --allow-duplicates se quiser seguir."
                )

            with conn.transaction():
                raw_count_before, raw_max_before, cursor_before = _load_raw_counts(cur)
                if cursor_before != args.expected_cursor or raw_max_before != args.expected_cursor:
                    raise SystemExit(
                        f"Estado mudou antes do INSERT. cursor={cursor_before} max_id={raw_max_before}"
                    )
                cur.execute(
                    f"""
                        INSERT INTO bgp_raw_routes (
                            source, collector, collected_at, peer_ip, peer_asn, prefix,
                            next_hop, as_path, origin_asn, origin_type, med, local_pref,
                            communities, raw_record
                        )
                        SELECT
                            source,
                            collector,
                            collected_at,
                            peer_ip::inet,
                            peer_asn::bigint,
                            prefix::cidr,
                            next_hop::inet,
                            as_path,
                            origin_asn::bigint,
                            origin_type,
                            med::bigint,
                            local_pref::bigint,
                            communities,
                            raw_record
                          FROM {STAGING_TABLE}
                         WHERE source_file = %s
                         ORDER BY id
                        RETURNING id
                    """,
                    [deep.source_key],
                )
                inserted_ids = [int(row[0]) for row in cur.fetchall()]
                inserted_raw_rows = len(inserted_ids)
                if inserted_raw_rows != deep.staging_rows:
                    raise SystemExit(
                        f"Quantidade inserida diferente da staging. inserted={inserted_raw_rows} staging={deep.staging_rows}"
                    )

                raw_id_min = min(inserted_ids) if inserted_ids else None
                raw_id_max = max(inserted_ids) if inserted_ids else None
                raw_after_count = raw_count_before + inserted_raw_rows
                raw_after_max = raw_id_max if raw_id_max is not None else raw_max_before
                cursor_after = cursor_before

                cur.execute(
                    f"""
                        INSERT INTO {PROMOTIONS_TABLE} (
                            source_file, source_key, batch_id, start_record, limit_records,
                            staging_rows, inserted_raw_rows, raw_id_min, raw_id_max,
                            raw_count_before, raw_count_after, raw_max_before, raw_max_after,
                            cursor_before, cursor_after, status, report_json, notes
                        ) VALUES (
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s, %s, %s
                        )
                    """,
                    [
                        source_file,
                        deep.source_key,
                        batch_id,
                        args.start_record,
                        args.limit_records,
                        deep.staging_rows,
                        inserted_raw_rows,
                        raw_id_min,
                        raw_id_max,
                        raw_count_before,
                        raw_after_count,
                        raw_max_before,
                        raw_after_max,
                        cursor_before,
                        cursor_after,
                        "PROMOTED",
                        str(report_json),
                        "promotion controlled from staging",
                    ],
                )

                raw_after_count_db, raw_after_max_db, cursor_after_db = _load_raw_counts(cur)
                promotion_info = {
                    "inserted_raw_rows": inserted_raw_rows,
                    "raw_id_min": raw_id_min,
                    "raw_id_max": raw_id_max,
                    "raw_count_before": raw_count_before,
                    "raw_count_after": raw_after_count_db,
                    "raw_max_before": raw_max_before,
                    "raw_max_after": raw_after_max_db,
                    "cursor_before": cursor_before,
                    "cursor_after": cursor_after_db,
                    "cursor_match": cursor_after_db == args.expected_cursor,
                    "promotions_rows": 1,
                }

            report = _build_report(
                mode="APPLY",
                source_file=source_file,
                batch_id=batch_id,
                start_record=args.start_record,
                limit_records=args.limit_records,
                deep=deep,
                validation_json=validation_json,
                comparison=comparison,
                raw_before={
                    "count": raw_count_before,
                    "max_id": raw_max_before,
                    "cursor": cursor_before,
                },
                raw_after={
                    "count": promotion_info["raw_count_after"],
                    "max_id": promotion_info["raw_max_after"],
                    "cursor": promotion_info["cursor_after"],
                },
                promotion=promotion_info,
                allow_duplicates=args.allow_duplicates,
            )
            json_write(report_json, report)
            report_text.write_text(_report_text(report), encoding="utf-8")
            print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
