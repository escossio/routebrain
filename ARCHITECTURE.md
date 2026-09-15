# Architecture

## Two layers with different costs

The **reference layer** ingests global BGP data and supports queries by prefix, ASN and peer. The **deep materialization layer** is intended to focus on an operator's working set: destinations observed in traffic and selected for further investigation.

The pivot concerns the scope of semantic work, not a claim that global BGP ingestion is impossible. A million-record RIB can be ingested without building complete contextual histories for every route and every network element.

## From observations to operator questions

Demand-driven materialization selects what deserves deeper investigation; contextual identity relates observations without treating an address as definitive identity; temporal memory preserves when and where evidence was observed. Together, these are intended to support questions about prior paths, recurring elements, changes and the evidence relevant to an operator's next action.

Implemented building blocks and experimental memory supply parts of these answers. Historical comparisons require accumulated, comparable observations. Cross-context identity resolution and policy/action reasoning remain architectural direction; before/after correlation alone does not establish causality. See [Questions RouteBrain Is Designed to Answer](docs/OPERATOR_QUESTIONS.md) for the questions and their evidence requirements.

## Components and boundaries

| Component | Source | State / responsibility |
|---|---|---|
| MRT projection | `app/parsers/routeviews_mrt_parser.py` | Implemented; normalizes prefix/length and selects the first RIB entry |
| CIDR normalization | `app/services/bgp_prefix_normalizer.py` | Implemented helper; caller fallback on invalid input remains debt |
| Raw/current persistence | `app/services/bgp_raw_ingest.py`, `bgp_current_builder.py` | Implemented; PostgreSQL CIDR/INET/JSONB |
| BGP queries | `app/services/bgp_operational_queries.py` | LPM, prefix/ASN/peer context; some paths prefer persisted summaries |
| Traffic-derived candidates | `app/services/mikrotik_observer.py`, `observed_destinations.py` | Connection-tracking destinations, runs and enrichment; actual device configuration must be supplied |
| Baselines | `app/services/observed_destinations.py` | Explicit promotion/refresh and suggested actions; not automatic promotion of every destination |
| Active observations | Services under `app/services/` and measurement scripts | Ping/traceroute persistence and parsing; requires deliberate execution |
| Enrichment | `app/services/external_enrichment.py` | RDAP/PeeringDB and cache-backed context; external attribution is distinct from BGP confirmation |
| Route memory | `app/services/route_memory.py`, `route_memory_persistence.py` | Experimental observations, segment matching, hop facts and graph snapshots |
| Graph contracts | `app/services/route_graph_builder.py`, `app/adapters/` | Reports and adapters; observed path adjacency is not proof of physical adjacency |
| Semantic retrieval | `app/services/semantic_memory.py`, `embedding_provider.py` | Documents, embeddings and hybrid retrieval; model training is not implemented here |
| Operator interfaces | `app/api/`, `app/cli.py`, `app/static/` | FastAPI, CLI and experimental browser views; both query and action interfaces |
| Visualization | `deploy/grafana/dashboards/`, `grafana/` | Dashboard/query definitions; no real datasource configuration |
| Bootstrap worker | `scripts/bootstrap_parse_bgp_snapshot.py`, `bootstrap_worker_utils.py` | Offline chunk artifacts and manifests; no HA cluster or distributed scheduler claim |

## Existing flow versus intended composition

Observed destinations have dedicated collection, enrichment, baseline and suggested-action operations. Promotion requires confirmation. Measurements have their own execution paths. Route memory and semantic retrieval have separate builders/persistence. They demonstrate parts of demand-driven materialization, but no verified single controller closes the entire loop automatically.

The public tree does not include historical operator-specific active-target lists, deployment configs or complete original lab outputs. See the export inventory and boundaries document.

## Contextual identity

The intended entity model combines address evidence with vantage point, predecessor/successor, path position, ASN, recurrence and observation time. Segment fingerprints and matching provide an experimental foundation. IP-independent entity resolution, merge/split policy and temporal identity reconciliation are not complete.

Private/CGNAT nodes should not receive a public ASN merely because a nearby public hop has one. A hop can have contextual association without direct BGP attribution. Silent hops are observations of missing responses, not identified devices.

The graph exporter now validates a present hop IP before exposing a direct ASN or generating an AS-number label. Invalid/non-global addresses lose direct attribution even if a preferred fact is tagged public. Raw evidence, contextual segment ASN and existing snapshots remain unchanged; absent-IP behavior is preserved. This bounded fix is not complete entity resolution or independent BGP verification. See [validation findings](docs/VALIDATION.md).

## Time and provenance

Distinguish MRT record time, ingestion time, active measurement time and knowledge materialization time. Recomputing context from a corrected RIB must not be represented as a new network measurement.

The archived dataset primarily represents one RIB. A sequence of ingestion batches is not a time series of routing updates. The historical change table lacks sufficient event provenance and has invalid comparisons; its code is included as experimental legacy, not a trusted incident stream.

## Engineering controls and limits

- PostgreSQL advisory locks and a raw-ID cursor exist in pipeline scripts. Lock names differ across workflows; they are not global exclusion by default.
- Staging and manifests separate offline parsing from server-side persistence.
- Raw records preserve recovery evidence; normalization must not destroy source information.
- Deduplication exists at selected stages, not as a universal exactly-once guarantee.
- Semantic document hashes avoid some unnecessary re-embedding, but generation-aware invalidation across all derived stores remains work.
- Some historical BGP caches have no expiration. A corrected reference table does not automatically correct derived knowledge.

No complete Internet model, real-time BGP monitor, production SLA or high-availability architecture is claimed.
