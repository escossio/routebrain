# CIDR /32 incident: preserving evidence enabled recovery

## Failure

The decoded MRT record carried a network address and its length separately. The early parser projected only the address into the normalized `prefix` column. The importer passed that string to PostgreSQL's `cidr` type, which interpreted a bare IPv4 address as a host `/32`.

Different networks sharing the same base address then collided under the current-route key. Attribute differences between those different prefixes appeared as route changes.

## Recovery

The original JSONB `raw_record` retained `prefix` and `length`. Their combination allowed a controlled reconstruction of the CIDR column. The historical process used isolated rebuild tables, validation and a promotion designed to preserve dependent views.

The read-only audit performed on 2026-09-15 verified:

| Table | Before: rows | After: rows | Before: /32 rows | After: /32 rows |
|---|---:|---:|---:|---:|
| raw | 1,061,466 | 1,061,466 | 1,061,466 | 84 |
| current | 1,041,877 | 1,061,196 | 1,041,877 | 84 |

Current has approximately 1,061,192 distinct prefixes. The complete raw-table comparison against preserved prefix + length found **zero mismatches**. The remaining 84 `/32` rows are legitimate in that dataset; deleting all `/32` records would be another error.

These private-dataset measurements are published as aggregate historical evidence. The dataset and private audit files are not distributed here.

## What was not recovered end to end

The historical `bgp_route_changes` table still contains 1,052,202 records:

- 1,040,932 `NEW_ROUTE` records mean initial materialization of absent keys.
- 10,972 `AS_PATH_CHANGED` and 298 `ORIGIN_TYPE_CHANGED` comparisons involved the same base address and MRT timestamp but different masks.

They do **not** prove a million temporal BGP changes. Replacing only the prefix field in those events would not make the original comparisons valid.

The audit also found stale current summaries, contaminated changes summaries, old BGP evidence/caches, ASN snapshots and semantic documents derived from previous counts. Some BGP caches did not expire. Correcting a reference table is not equivalent to reconciling every derived representation.

## Remaining code debt

The current normalizer validates prefix length, but parser callers can fall back to a bare address on a normalization error. Writers and staging inputs still require an end-to-end validation policy. The public export does not claim this incident has been fully repaired.

The operational rebuild script and private promotion/rollback artifacts are deliberately not included as a ready-to-run public repair tool. Historical schema files and event processors remain experimental and must not be blindly replayed.

## Lessons and future work

1. Preserve source records alongside normalized projections.
2. Treat a prefix as address **and** length at every boundary.
3. Distinguish a baseline import from a temporal event.
4. Version datasets and their derivatives; TTL alone cannot represent semantic validity.
5. Keep invalid historical evidence traceable without presenting it as current operational truth.
6. Rebuild derived stores in dependency order and validate consumers before promotion.

Future remediation belongs in an isolated, reversible workflow. No remediation of the private deployment was performed to create this release.
