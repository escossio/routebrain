# Public-tree validation

Date: 2026-09-15. Scope: public export only. The owner has authorized a new public root commit and publication, conditional on all final gates passing. Publication restrictions in the historical sections below describe earlier stages.

**Previous preparation result:** all seven source fixture failures are PREEXISTING_CONFIRMED and causally independent. Their public counterparts passed before propagation. The four approved deltas are now propagated: **79 public tests passed, zero failed**, with operational/secret checks passing. Source baseline remains 72/79 with seven known failures, unchanged. Ready for final human review only; no Git, commit or push. See “Seven-failure independence and conditional public propagation” below. Earlier stage results are retained as history.

## Final publication review — 2026-09-15

The owner authorized publication of this curated tree with a new Git history, conditional on all gates passing. This section supersedes preparation-stage publication restrictions; the earlier diagnoses remain historical evidence.

- Editorial and claims review: PASS. The architecture distinguishes implemented components, experiments and architectural direction. IP is evidence; contextual identity remains unfinished. Million-record figures describe an audited historical RIB, not a million genuine BGP changes. Raw/current CIDR recovery and unresolved derived-data debt remain explicit.
- Fresh complete public suite: **79 total, 79 passed, 0 failed, 0 skipped**, exit 0 (0.36s).
- Python syntax/in-memory compilation and API import: PASS. Shell syntax, JavaScript syntax and JSON parsing: PASS.
- Tests used a disposable virtual environment prepared from the public requirements, then an empty inherited environment, disabled bytecode/plugin autoload/cache, Linux network-namespace isolation and the existing network/subprocess/database guards. The environment was removed before the final artifact scan.
- Final public-only secret scan: PASS, zero real secrets detected. Checks cover provider tokens, private keys, credential URLs, literal Basic/Bearer credentials, JWTs and Python literal credential assignments/dictionary entries. No source environment or source Git was accessed in this publication session; the earlier exact private-value comparisons remain historical evidence, not a freshly repeated check.
- Operational-reference scan: PASS. All candidate files checked for private deployment paths; IP, URL-host and domain literals reviewed against the documented sanitized examples, public service references and reserved-range security policies. No private operational reference was identified. Detection remains bounded by these patterns and contextual review.
- Artifact scan: PASS. 217 candidate files, largest 203,313 bytes; none over 1 MB. No copied Git, environment files, datasets, dumps, HARs, operational logs, archives, keys, symlinks, hardlinks, virtual environments or generated caches in the candidate.
- Internal Markdown links and README instructions' referenced files: PASS. Historical prose references to omitted source documents are provenance notes, not public navigation links. Environment files mentioned as excluded are intentionally absent.
- License remains **LICENSE_DECISION=PENDING**; no LICENSE created.
- Only README, this report, public STATUS, file inventory and .gitignore changed in the final review. No application, test, database, runtime, operational data or original source changes.

Git creation and publication follow these checks. The root commit cannot contain its own SHA or attest to a future push; commit identity and remote verification are reported separately after publication. No post-push content changes are authorized.

## Historical result — initial remediation stage

**PUBLICATION_REMEDIATION_STATUS=BLOCKED — tests and contract decisions remain.**

- Operational-reference/credential scan: PASS within the checks below; one operational reference fixed, zero real secrets detected.
- Python syntax and FastAPI application import: PASS.
- Isolated tests: **59 total, 55 passed, 4 failed, 0 skipped**. Exit code 1.
- Original source and Git: untouched; content fingerprint matches the pre-remediation baseline.
- Application-code change: only one example address in an error message; no processing logic repaired.
- **SOURCE_FIX_REQUIRED=YES** for private-hop attribution validation.
- **PUBLIC_TREE_READY_FOR_FINAL_REVIEW=NO** for release approval. Findings are available for human review, but publication remains blocked.

## Original blockers and reproduction

The prior scan reported FAIL_OPERATIONAL_REFERENCE_REMAINS. The test baseline was reproduced as **44 passed / 15 failed**, with syntax and API import passing. Dependency/fixture corrections yielded 54/5; adding the missing explicit synthetic observation evidence yielded 55/4.

The existing offline harness used installed dependencies read-only, an empty inherited environment, disabled bytecode and a separate network namespace. Its audit hook rejects connections, DNS, socket binding and subprocess execution; Psycopg connections are explicitly denied. Plugin autoload and pytest cache generation are disabled. No services, migrations, database writes, measurements, browser sessions, model downloads or installations were performed.

Portable reproduction after separately preparing dependencies:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -B scripts/offline_check.py
```

The actual run additionally used Linux network-namespace isolation. These results do not certify live integrations.

## Operational-reference findings

All occurrences reproducing the previous failing operational scan: **one**.

| Location | Classification | Cause / disposition |
|---|---|---|
| app/services/questions.py:2336 | REAL_OPERATIONAL_INFRA | Original public operational address in a target-override example. The previous replacement boundary rejected sentence-final punctuation. Replaced only this occurrence with 203.0.113.42; original value not reproduced. |

Additional contextual review, not additional failing findings:

| Location / family | Classification | Disposition |
|---|---|---|
| synthetic_target_policy.py, config/synthetic_targets*.yml, traceroute classification SQL | FALSE_POSITIVE | RFC1918, CGNAT, loopback/link-local ranges and blocked private-domain suffixes implement safety/classification. Preserved. |
| Synthetic hop fixtures in tests; example addresses in route_graph.py, route_learning_builder.py and traceroute_visual.py | SAFE_DOCUMENTATION_EXAMPLE | Already-sanitized private examples retain private-hop semantics. No blanket replacement. Address-specific heuristics remain experimental, not general identity resolution. |
| external_route_inventory.py, sql/034_external_route_hop_inventory.sql and question examples | SAFE_DOCUMENTATION_EXAMPLE | Public service catalog and domain examples, not private operator infrastructure. No targets contacted. |
| BGP/parser/route-memory tests | SAFE_DOCUMENTATION_EXAMPLE | Synthetic inputs include public-address literals for public/private classification; documentation ranges are not interchangeable with globally routable addresses in Python. Not captured traffic or ownership evidence. |
| docs/contracts/routebrain_topology_view_v0_1.schema.json | FALSE_POSITIVE | Local-looking schema identifier, not deployment hostname or runtime connection. |
| Credential names in auth.py, cli.py, llm_assistant.py and mikrotik_observer.py | FALSE_POSITIVE | Environment reads, empty checks and authentication/protocol logic, not embedded credentials. |
| Loopback API/TTS defaults, public enrichment/CDN endpoints | FALSE_POSITIVE | Explicit local/public-service dependencies, not original private infrastructure. Live use still needs separate configuration. |

No additional REAL_SECRET, PERSONAL_DOMAIN, PRIVATE_HOSTNAME, PRIVATE_IP or USERNAME_OR_PATH finding was confirmed in the candidate. This says nothing about the original private history.

Coverage: every candidate file; known operational identifiers/addresses and deployment paths; common provider-token formats, private keys, credential-bearing URLs, literal Basic/Bearer values; exact matching against nontrivial secret values read privately from original environment files; AST inspection of literal credential assignments; contextual review of IPs, URL hosts, domains, paths and authentication keywords. Private values were neither printed nor copied. Empty values, variable names and the project name were not treated as secrets. This is not a mathematical guarantee against unknown secret formats.

## Individual classification of all 15 original failures

File abbreviations: **RG** = tests/test_route_graph_contract.py; **RM** = tests/test_route_memory.py; **GE** = tests/test_route_memory_graph_export.py.

Legend: A REGRESSION_REAL; B PRIVATE_ENV_DEPENDENCY; C SANITIZATION_BROKE_FIXTURE; D MISSING_PUBLIC_TEST_FIXTURE; E OPTIONAL_INTEGRATION_TEST; F OUTDATED_TEST; G OTHER.

Final primary classifications of the original 15: **D=8, F=6, G=1**. Secondary findings uncovered after mock corrections are included. No export-introduced functional regression was established.

| TEST | FAILURE | CLASSIFICATION | ROOT_CAUSE | PUBLIC_FIX_REQUIRED | SOURCE_FIX_REQUIRED |
|---|---|---|---|---|---|
| RG::test_simple_three_hop_route | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_silent_hop_is_explicit | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_private_and_public_ip_flags | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_validator_rejects_missing_node_for_edge | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_missing_fields_remain_null | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_cytoscape_adapter_returns_expected_shape | Offline DB guard | D | Missing isolated BGP lookup | YES, done; PASS | NO |
| RG::test_diagnostics_summary_counts_missing_fields | DB guard, then evidence missing 2 versus 1 | D | Fixture lacked both isolated BGP and its expected evidence-bearing observation | YES, done; PASS | NO |
| RG::test_route_graph_source_falls_back_to_traceroute_visual_payload | AttributeError | F | Current API imports traceroute helper locally and falls back to external inventory, not visual payload | Contract decision; unchanged FAIL | NO for current behavior; YES if old fallback must return |
| RM::test_on_net_destination_edge_short_route | Unexpected measurement_id | F | Observation mock signature outdated | YES, done; PASS | NO |
| RM::test_private_branch_variation_between_similar_on_net_routes | Unexpected measurement_id | F | Signature drift; related-run persistence also needed isolation | YES, done; PASS | NO |
| RM::test_operational_divergence_with_destination_asn_change | Signature drift, then structural versus operational divergence | F | Expects single report to contain cross-report comparison result | Mock fixed; assertion retained; FAIL | NO for current pure comparison; YES if report semantics must change |
| RM::test_private_hops_do_not_receive_public_asn_directly | Unexpected measurement_id | F | Signature drift and incomplete related-run isolation | YES, done; PASS | NO |
| GE::test_graph_payload_projects_shared_nodes_and_remaps_shared_edges | Missing key, then one shared edge versus two | F; secondary D fixed | Unrelated default facts masked custom route; only one adjacent pair is shared | Fixture fixed; count assertion retained; FAIL | NO for current edge model; YES if new edge type required |
| GE::test_graph_payload_keeps_divergent_final_edges_separate | No final edges | D | Unrelated default hop facts overrode custom three-hop route | YES, matching facts supplied; PASS | NO |
| GE::test_graph_payload_does_not_attribute_private_ip_to_public_asn | ASN 64510 instead of null | G | Preexisting validation gap and contradictory test contract; regression timing not established | Reviewed source-level decision required; FAIL | YES |

## Four unresolved contracts

1. **Fallback:** app/api/route_graph.py::_source_payload_for_run calls the traceroute service and then get_external_route_trace_graph. The test patches obsolete module-level symbols and expects visual-payload normalization. Using raising=False or testing a different fallback would conceal the mismatch. Choose the intended API contract before updating this test or restoring functionality.
2. **Divergence:** route_memory.py::_match_segments compares one observed destination against that report's BGP context. A successful ASN match produces structural_divergence. compare_route_memory_reports separately detects differing destination ASNs and already satisfies the test's comparison assertions. It does not mutate the input report. The final assertion asks an input report to contain that cross-report result; it remains unchanged.
3. **Shared edges:** corrected fixtures have two common nodes followed by distinct destinations: one common adjacent pair, not two. Earlier node assertions now pass. No extra edge was invented and the count assertion was not reduced. Decide whether this test is outdated or a source-to-route/segment edge is required by the intended contract.
4. **Private ASN:** route_memory_persistence.py::resolve_best_hop_facts selects a higher-weight fact tagged public despite its private IP. route_memory_graph_export.py copies origin_asn into asn without independently validating address scope. The same _report input is used by test_graph_payload_prefers_resolved_hop_fact, which requires ASN 64510, while the failing private-IP test requires null. These expectations are incompatible. Decide validation at ingestion/resolution/export and separate valid-public precedence from adversarial-private rejection in future tests. No assertion or production logic was altered to hide this gap.

The relevant implementation files app/api/route_graph.py, app/services/route_memory.py and app/services/route_memory_graph_export.py are byte-identical to the original source. These discrepancies were not introduced by this sanitization.

## Changes performed

- app/services/questions.py: one error-message example sanitized.
- tests/test_route_graph_contract.py: empty-reference BGP fixture; existing evidence-specific tests still override it. Explicit synthetic observation evidence added for diagnostics; all assertions preserved.
- tests/test_route_memory.py: observation mocks accept measurement_id; related-run lookup returns an empty synthetic collection. Segmentation/matching/comparison functions run unchanged.
- tests/test_route_memory_graph_export.py: custom route pairs receive matching facts instead of unrelated defaults. Adversarial private-ASN fixture and assertions preserved.
- README.md, ARCHITECTURE.md, STATUS.md, this report and docs/FILE_INVENTORY.md: updated results, limitations and sizes.

No tests deleted, assertions relaxed/commented, skips/xfails added, source files recopied or integrations fabricated. No configuration files or dependency declarations changed in this stage.

## Final validation and limitations

- 217 candidate files; none over 1 MB. Largest: 203,313 bytes. See [inventory](FILE_INVENTORY.md) for current individual sizes.
- No Git directory, environment files, dumps, HARs, logs, RIB/MRT/CSV datasets, archives, bytecode/cache directories, virtual environments or symlinks found.
- README local Markdown links resolve. ARCHITECTURE code pointers reviewed; abbreviated sibling filenames refer to the stated service directory. No private-deployment link is required.
- Parser/CIDR and independent topology tests are included in the 55 passes; not a replay of the historical million-record dataset.
- Database/schema/live BGP, enrichment, MikroTik, active measurements, semantic-provider and browser/Grafana integrations remain unexecuted. They need isolated databases, explicit service configuration and authorized targets. They are not represented as passing unit tests or hidden skips.
- Credential review passed for this candidate; functional gate did not. This report does not authorize publication.

## Next decision

Review the four contracts, prioritizing private-IP attribution and contradictory precedence expectations. Semantic repairs require a separately authorized source change followed by a reviewed export update. Updating obsolete expectations also requires a contract decision; none were weakened here. Then repeat all checks. **Do not initialize Git, commit, create a remote or push at this stage, even after a future green run.**

## Remaining 4 test failures — root cause and proposed remediation

### Diagnostic scope and verdict

This section supersedes the provisional F=3/G=1 classification above. Investigation only; no proposed patch was applied. Only this document is changed in this session. STATUS.md and the size inventory deliberately remain untouched under the document-only authorization; their earlier classification/size entries are therefore historical.

All four selected tests were reproduced offline: **4 failed in 0.17s**; syntax and API import passed. The existing harness was invoked with an in-memory pytest selection of these four node IDs, with bytecode/cache disabled, network-namespace isolation and the original database/subprocess guards. No test files were edited. The whole 59-test suite was not rerun in this session; its last result remains 55/4.

Final diagnosis: **three test-contract mismatches (F), one confirmed preexisting functional regression (A)**. No remaining failure originated in public sanitization. “Outdated” here means incompatible with the supported contract; for two tests the inconsistency was present from their first reachable revision, not evidence they once passed.

The prior OTHER classification is resolved: **hop-fact precedence introduced an unvalidated private-address ASN attribution path**. This is a source bug, not an integration requirement.

### 1. Source/public comparison and historical evidence

Only relevant code/test files were compared. Four implementation files are byte-identical between SOURCE and PUBLIC:

- app/api/route_graph.py
- app/services/route_memory.py
- app/services/route_memory_graph_export.py
- app/services/route_memory_persistence.py

The three relevant test files differ by previously reviewed synthetic address/source-label substitutions and public offline fixtures. AST comparison confirms that **all assertions in each of the four failing test functions are unchanged** from SOURCE.

Public changes that exposed rather than created failures:

- Observation mocks now accept measurement_id and isolate related graph runs; in SOURCE the stale signature can mask the later divergence assertion.
- Explicit graph-route fixtures now provide matching hop_facts; in SOURCE unrelated default facts can mask the later edge-count assertion.
- These corrections did not alter route relationships, destination-ASN differences or the adversarial private-IP fact.

Reachable Git evidence, inspected without checkout or changes:

| Revision | Date | Relevant evidence |
|---|---|---|
| fab6d82 | 2026-06-21 | Introduces the visual-fallback test against module-level helpers. |
| 5a902ff | 2026-06-21 | First reachable app/api/route_graph.py already uses local traceroute import and external-inventory fallback. Its current implementation is unchanged. No earlier supported visual fallback in this file was found. |
| c67c47a | 2026-06-23 | Introduces both single-report segment matching and pure two-report comparison, together with the inconsistent final test assertion. |
| 836ca6c | 2026-06-23 | Graph export consumes report.hops; private-ASN protection test exists. |
| 784008b | 2026-06-23 | Export starts preferring report.hop_facts and resolving them by completeness; fixture adds a private IP tagged public with origin_asn, plus a conflicting precedence assertion. |
| 2bee20f | 2026-06-24 | Introduces shared-edge consolidation by logical endpoints and edge type. |
| 53bb219 | 2026-06-24 | Canonical-node test expects two shared edges for diverging final hops; refactored fixture also stops explicitly supplying the matching facts. Both issues predate the export. |

Historical pure-function experiment: the same small synthetic report, with a private hop lacking an ASN in hops and a conflicting public-tagged fact in hop_facts, was supplied to extracted graph-export functions from 836ca6c and 784008b. Result: **private-hop ASN [None] → [64510]**. Only function definitions were evaluated in memory; no application entry point, database, migration or historical script was executed. Git objects were read before installing the diagnostic subprocess guard. This demonstrates a behavior regression when the new fact path is present; it does not prove old code rejected every possible invalid input or establish how many stored observations were affected.

### 2. Failure-by-failure diagnosis

#### R1 — fallback contract

- **Path/name:** tests/test_route_graph_contract.py::test_route_graph_source_falls_back_to_traceroute_visual_payload
- **Failure:** AttributeError: app.api.route_graph has no attribute get_traceroute_graph_by_run.
- **Relevant stack:** test line 157 → monkeypatch.setattr. The production function is not reached by this failing test.
- **Expected:** unavailable traceroute result → build_traceroute_visual_payload → normalized target, requested run UID and two hops.
- **Actual:** app/api/route_graph.py:33–53 imports get_traceroute_graph_by_run inside the numeric-ID branch; on unavailable results it calls get_external_route_trace_graph(run_uid), otherwise returns 404. It copies the selected graph's target/nodes. It does not call the visual helper or _normalize_target_text.
- **Classification:** F confirmed as unsupported/stale test contract; no demonstrated code regression and no sanitization-induced premise change.
- **Authority:** preserve the run-specific traceroute/external-inventory lookup. It is the only reachable implementation of this endpoint and preserves association with the requested run. The test's parameterless visual fallback is not evidence sufficient to add a new retrieval path. The unused normalization helper alone does not establish a supported fallback contract.
- **Origin:** original repository mismatch. The test predates the first reachable version of the API file on the same date. It is inaccurate to claim that this investigation found a previously working fallback later removed.

#### R2 — report versus comparison

- **Path/name:** tests/test_route_memory.py::test_operational_divergence_with_destination_asn_change
- **Failure:** AssertionError: structural_divergence != operational_divergence.
- **Relevant stack:** test line 158, final assertion on report_c.segment_matches[-1]. Before that, build_route_memory_report (line 367 onward) → _match_segments (322–364); compare_route_memory_reports (509–559) returns a separate comparison object.
- **Expected:** changing destination ASN between reports makes report_c's own last segment match operational_divergence.
- **Actual:** each report matches its destination against its own supplied BGP context and gets destination_asn_match/structural_divergence. Comparing the two reports correctly yields operational_divergence=True and destination_asn_match=False; the comparator does not mutate either report.
- **Classification:** F confirmed as incorrect assertion scope, already inconsistent in c67c47a. No historical transition from a working mutating comparator was found.
- **Authority:** preserve distinction between a single observation's context and a comparison between observations. Both the implementation and this test's preceding comparison assertions establish that contract. A report cannot infer another report's ASN that was never supplied to it; making the last assertion pass in production would introduce hidden state or unexpected mutation.
- **Origin:** source test debt, exposed after the public mock-signature correction. Private-address substitutions preserve the private branch and the two distinct synthetic destination ASNs.

#### R3 — shared-node versus shared-edge count

- **Path/name:** tests/test_route_memory_graph_export.py::test_graph_payload_projects_shared_nodes_and_remaps_shared_edges
- **Failure:** AssertionError: len(shared_edges) is 1, expected 2.
- **Relevant stack:** test line 122 → assertion after _route_pair_payload → build_route_memory_graph_payload (198–368) → _merge_edge_record (154–185), then canonical-node/edge-ID projection.
- **Expected:** two shared edges for two shared nodes followed by different destinations.
- **Actual:** paths are A→B→C and A→B→D: shared nodes A/B, one shared edge A→B, two separate final edges. The corrected fixture yields the requested canonical nodes and remapped identifiers; the count assertion is the remaining failure.
- **Classification:** F confirmed, with prior source-fixture debt already corrected only in PUBLIC.
- **Authority:** preserve logical-edge identity, not the erroneous count. Original docs/sdk/route_memory_graph_v1.md:68–86 define edges as logical transitions and shared=true as the same edge occurring in more than one route. Code keys edges by (source_key, target_key, edge_type). The test separately asserts that divergent final edges stay separate. There is no source-node edge in this fixture to account for an extra shared edge.
- **Origin:** source test/fixture inconsistency introduced by the canonical-node test revision, not public sanitization. This does not require inventing another edge or removing canonicalization.

#### R4 — private hop gains direct ASN from preferred fact

- **Path/name:** tests/test_route_memory_graph_export.py::test_graph_payload_does_not_attribute_private_ip_to_public_asn
- **Failure:** AssertionError: 64510 is not None.
- **Relevant stack:** test line 182 → assertion after build_route_memory_graph_payload → hop_source selection at export line 289 → resolve_best_hop_facts at persistence line 107 → raw hop node assignment at export line 300 → canonical projection retains raw_node.asn.
- **Expected:** a private IP must not receive direct public BGP ASN attribution.
- **Actual:** _hop_fact_weight prefers a record with IP/type/BGP context/evidence over the incomplete record. The selected record has a private IP but hop_type=public and origin_asn=64510. Selection does not validate scope. Export trusts origin_asn, and canonical projection retains it.
- **Definitive classification:** A — REAL_REGRESSION, preexisting in SOURCE; introduced for the hop_facts path by 784008b. A latent lack of exporter validation existed earlier, but the new precedence path changes the demonstrated result from null to ASN.
- **Authority:** preserve the no-direct-private-ASN invariant. Original docs/ROUTE_LEARNING_ENGINE.md:100–111 and docs/ROUTE_LEARNING_PAYLOADS.md:690 distinguish private-hop observation from public ASN attribution; route_memory.py::_normalize_hop_fact also gates direct attribution by address scope. The older protection test agrees. The later precedence test's private-IP/public-ASN fixture contradicts this independent invariant and must be split, not allowed to overrule it.
- **Origin:** source behavior regression plus conflicting test fixture. Both exist unchanged in the public exporter. No actual private infrastructure is needed to reproduce it.

### 3. Minimal patch proposals — NOT APPLIED

TARGET=BOTH means independently reviewed changes in SOURCE and PUBLIC, retaining sanitized public fixtures; never copying original operational examples wholesale. SOURCE_REQUIRED includes source-test maintenance; only R4 requires production-code modification. No branch/commit/publication action is part of these proposals.

| Proposal | TARGET | FILES | CHANGE_TYPE | RATIONALE | REGRESSION_RISK | PUBLICATION_REQUIRED | SOURCE_REQUIRED |
|---|---|---|---|---|---|---|---|
| P1 | BOTH | tests/test_route_graph_contract.py | TEST_FIX + FIXTURE_FIX | Test the supported run-specific external fallback, not nonexistent helpers | LOW | YES | YES, tests only |
| P2 | BOTH | tests/test_route_memory.py | TEST_FIX + FIXTURE_FIX in SOURCE | Assert cross-report divergence on the comparison result; retain single-report semantics | LOW | YES | YES, tests only |
| P3 | BOTH | tests/test_route_memory_graph_export.py | TEST_FIX + FIXTURE_FIX in SOURCE | Verify one shared logical edge and two distinct final edges for A/B/C versus A/B/D | LOW | YES | YES, tests only |
| P4 | BOTH | app/services/route_memory_graph_export.py; tests/test_route_memory_graph_export.py | CODE_FIX + TEST_FIX + FIXTURE_FIX | Validate direct ASN at export boundary and separate positive public-fact precedence from adversarial private facts | MEDIUM | YES | YES, code and tests |

**P1 exact intended edit:** rename the case to test_route_graph_source_falls_back_to_external_inventory. Patch app.services.traceroute_graph.get_traceroute_graph_by_run, the actual defining module used by the local import, and route_graph_api.get_external_route_trace_graph. Supply an explicit available external graph with target/nodes matching the current graph interface. Retain run UID/target/hop assertions and additionally record calls to prove the requested ID reaches both lookups. Use a normalized target in that fixture; do not claim this tests CIDR normalization. Add small cases for preferred local data and both sources unavailable → HTTPException 404. Do not restore the old parameterless visual fallback or add raising=False.

**P2 exact intended edit:** change the final assertion's subject from report_c["segment_matches"][-1] to comparison["segment_comparisons"][-1], retaining the required value "operational_divergence". Add an explicit assertion that report_c's single-report match stays "structural_divergence"; optionally compare input snapshots to prove non-mutation. SOURCE also needs the already-public measurement_id-compatible mocks and empty synthetic related-run fixture, otherwise that suite stops before the semantic assertion. No change to either production function.

**P3 exact intended edit:** replace the count-only expectation of two shared edges with an exact expected shared-edge key set containing only A→B of type route_hop. Retain canonical node-ID remapping assertions and verify the two final edge keys are unshared; the existing divergent-final-edge test supplies complementary coverage. SOURCE needs its custom route pair facts bound to its custom hop lists as already done publicly. This strengthens the definition under test instead of merely accepting a smaller number.

**P4 exact intended edit:** in the exporter, derive a separate direct_asn value from the selected hop. For a present IP, parse it using the standard-library ipaddress module; non-global or invalid addresses yield direct_asn=None. Only a globally scoped IP may retain the supplied direct ASN. This excludes RFC1918, CGNAT, loopback, link-local, ULA and documentation addresses without relying on the untrusted hop_type label. Use this value both for the hop node's numeric asn and for any generated AS-number label fallback. Preserve the input object, raw evidence, IP-based canonical key, node/edge identifiers, segmentation, fact precedence and explicit contextual ASN on segment nodes. For absent IP, leave existing contextual/no-IP behavior unchanged in this bounded patch; it is not a complete identity/attribution policy.

Keep the adversarial private-ASN test. Change only the positive precedence case to provide explicit globally scoped synthetic test input and matching facts (for example a public resolver address with a fabricated test ASN and no network lookup). Do not globally replace the shared _report defaults, which would erase the negative case. Add parameterized private/CGNAT/loopback/link-local/ULA/documentation cases, a valid public-IP positive case, no-input-mutation check and multi-route merge check. A public-address literal here is only an offline classification input, not permission to measure that endpoint.

P4 intentionally does not change resolve_best_hop_facts globally: that would affect persistence and every caller's evidence selection, a materially larger patch. Raw contradictory evidence remains preserved. The bounded exporter patch prevents it being presented as direct attribution in newly built graphs. Stored historical snapshots and raw facts are not repaired by this proposal; any reconciliation is a separate task.

### 4. Impact, compatibility and validation plan

| Patch | Imports and interfaces | Contracts / regression tests | Operational effect and compatibility |
|---|---|---|---|
| P1 | Test imports the traceroute service module; API implementation/imports unchanged. Covers GET /route-graph/runs/{run_uid} source selection. | Fallback, local preference and 404; RouteGraph/Cytoscape contracts remain intact. | None in operation. No new fallback or target normalization behavior. |
| P2 | No production import/API changes. Mock signature mirrors measurement_id. | Single report, two-report comparison, same-ASN branch variation and input immutability. | None. Reports remain independent; comparison remains pure. |
| P3 | No production import/API changes. | Shared-edge identity, canonical remapping, divergent edges, unknown-only nodes, graph validator/SDK. | None. Existing route_memory_graph.v1 shape and identifiers unchanged. |
| P4 | Add ipaddress import/local pure helper or equivalent bounded logic only in graph exporter; avoid importing the report builder or causing dependency cycles. | Private negative case, corrected public positive precedence, graph merge, validator, SDK, persistence tests. | Newly generated graphs stop publishing direct ASN for invalid/non-global hop IPs. Numeric fields remain nullable under the existing graph schema; some incorrect AS labels disappear. Existing stored snapshots returned by graph/Grafana APIs remain unchanged. |

Direct producer: scripts/register_route_memory_observation.py calls the exporter and can later persist the resulting graph when explicitly requested. Readers include route_memory_sdk and graph/Grafana API endpoints under /route-memory; they consume snapshots, not automatically rebuilt data. A future exporter patch therefore must not be described as repairing every existing dashboard or saved graph. No producer or snapshot reader was executed against a database in this session.

Future validation order, after human authorization:

1. Apply each reviewed test-only change separately with a local failing/passing check; keep all assertions justified by the documented contract.
2. For P4, retain the current red private-IP test, then implement only the export boundary; use the independent positive/negative fixtures.
3. Run offline graph contract, report comparison, graph export, persistence, validator and SDK tests; then the whole offline suite and syntax/import checks.
4. Recheck sanitization on changed public files. Do not import SOURCE fixture secrets or operational identities.
5. Review the diff and update status/inventory only under the next authorization. A successful patch still grants no permission for GitHub creation or push.

### 5. Readiness and limitations

**SAFE_TO_PATCH_NEXT=YES**, meaning the four bounded patches are technically specified for review, not authorized or already validated. P4's non-global-address policy and its deliberate limit to newly exported graphs must be included in that review. Regression risk is MEDIUM because it changes displayed attribution, even though it leaves the schema and persistent data untouched.

**OUTDATED_TEST_CONFIRMED=3; REAL_REGRESSIONS_FOUND=1; PUBLIC_EXPORT_ISSUES_FOUND=0; SOURCE_BUGS_FOUND=1; OTHER_ROOT_CAUSE=RESOLVED_HOP_FACT_SCOPE_VALIDATION_GAP; PATCHES_PROPOSED=4.**

SOURCE_BUGS_FOUND counts the production attribution bug, not the three additional source-test defects. PUBLIC_EXPORT_ISSUES_FOUND counts causes of these four remaining failures only, not a new whole-project audit. The historical reproduction establishes a bounded behavior change, not operational contamination counts. No database, remote service or original runtime was queried.

**SOURCE_CHANGE_REQUIRED=YES; PUBLIC_CHANGE_REQUIRED=YES; PATCH_EXECUTED=NO.**

## Approved four-patch execution — stopped at source gate

Date: 2026-09-15. The owner authorized the four patches above, source first, with a mandatory stop if the full source gate failed. This section supersedes the earlier NOT APPLIED/PATCH_EXECUTED=NO descriptions for SOURCE only.

### Before editing: scope and Git state

All four planned source files were tracked and clean relative to the existing Git index/HEAD. Their contents were retained in memory before editing; all other tracked/untracked source content and original Git files were fingerprinted for preservation verification.

| Source file | Reason | Initial Git state |
|---|---|---|
| app/services/route_memory_graph_export.py | P4: validate selected hop fact address before direct ASN export | Clean |
| tests/test_route_graph_contract.py | P1: supported external-inventory fallback, local preference and 404 cases | Clean |
| tests/test_route_memory.py | P2: comparison assertion scope and already-diagnosed mock prerequisites | Clean |
| tests/test_route_memory_graph_export.py | P3/P4: exact shared-edge contract, matching route facts, scope regression coverage | Clean |

Preexisting changes in source STATUS.md, the topology design document and untracked topology contract/example/test files were preserved. No Git index, branch, commit, remote or history operation was performed. STATUS.md was deliberately not edited because this execution explicitly limited source edits to the diagnosed files.

### Four patches applied in SOURCE

1. **P1:** replaced the obsolete visual-fallback test with the supported run-specific external-inventory case, retaining payload assertions and checking requested lookup IDs. Added local-data preference and missing-run 404 cases. API implementation unchanged.
2. **P2:** moved the operational-divergence assertion to comparison.segment_comparisons and explicitly preserved structural_divergence in the individual report. Observation mocks now accept measurement_id and isolate related-run persistence as specified in the proposal.
3. **P3:** bound explicit route fixtures to matching facts and replaced the incorrect two-edge count with the exact singleton shared-edge key set. Canonical node/remapping assertions and the separate divergent-final-edge test remain.
4. **P4:** introduced a local direct_asn variable in the exporter. A present invalid/non-global IP clears direct numeric ASN and generated AS-label fallback, independent of hop_type. Input facts, evidence and contextual segment ASN remain unchanged. The positive fact-precedence test now uses a globally scoped synthetic input rather than contradicting the private-IP protection test. Added 17 parameterized scope cases and a shared-private-hop merge case.

No other production module, API, schema, persistence resolver, configuration or dependency file was changed. There was no opportunistic refactoring or historical-data repair.

### Real bug: invariant and bounded effect

Incorrect behavior: a preferred fact tagged public could give a private hop origin_asn=64510; graph export trusted that fact and published the ASN directly. This violated the distinction between contextual evidence and direct public BGP attribution.

The exporter now uses standard-library ipaddress.is_global for a present IP, catching invalid input. Tests cover RFC1918 ranges, CGNAT, loopback, link-local, ULA, IPv4/IPv6 documentation addresses, invalid/empty input, valid public IPv4/IPv6, and absent IP. Globally scoped inputs retain the supplied ASN; they are not independently verified against BGP by this patch. Absent-IP contextual behavior is deliberately preserved. Existing observed host labels and raw evidence are not rewritten. This is not a complete entity-resolution or attribution policy.

The negative private-IP test was observed failing on SOURCE before the code patch (64510 instead of null), then passing after it. Contextual ASN on segment nodes remains allowed. The new scope tests verify no input mutation, evidence retention and correct generated labels; the merge case verifies shared nodes retain null direct ASN.

Effect is limited to newly built graph payloads. Route-memory rows, stored hop facts, graph snapshots, caches and Grafana historical data are untouched. No regeneration, migration or service restart was attempted. The persistence fact-selection function was not changed.

### Source validation results

| Check | Result |
|---|---|
| Original private-hop regression before fix | 1 failed, expected red |
| Four previously failing targets, using renamed P1 test | 4 passed |
| Graph export, persistence, graph validator and SDK modules | 40 passed |
| Equivalent complete suite | 79 total: 72 passed, 7 failed; exit 1 |
| Source Python syntax/in-memory compile | PASS |
| Source FastAPI import without starting service | PASS |
| Git diff whitespace check | PASS |

The equivalent suite selected SOURCE test files whose filenames exist in the public suite. It did not substitute public test implementations. The previous equivalent count of 59 increased by 20: two P1 branch tests, 17 parameterized scope cases and one merge case. Operator-specific tests absent from the public allowlist were not included; no skipped tests were introduced to obtain a pass.

Checks ran with an empty inherited environment, disabled bytecode and pytest cache/plugin autoload, a separate network namespace, an invalid test database URL, denied Psycopg connections and network/subprocess audit guards. Source modules, not public modules, were imported. Compilation was in memory, without pyc output. No operational database or service was accessed and no installation performed.

### Stop condition: seven other source fixture failures

All failures are in tests/test_route_graph_contract.py:

- test_simple_three_hop_route
- test_silent_hop_is_explicit
- test_private_and_public_ip_flags
- test_validator_rejects_missing_node_for_edge
- test_missing_fields_remain_null
- test_cytoscape_adapter_returns_expected_shape
- test_diagnostics_summary_counts_missing_fields

Observed stack: test → _graph → build_route_graph_v1 → _bgp_evidence_for_public_ip → lookup_bgp_by_ip → _fetch_one → get_connection → denied psycopg.connect. Failure: **RuntimeError: Database access forbidden**.

These are preexisting source fixture/isolation defects, not failures in the modified graph exporter. Their public counterparts received empty-reference BGP/evidence fixtures in an earlier remediation. Those additional test edits were not part of the four-patch authorization here. In particular, the diagnostics case also previously required explicit observation evidence after lookup isolation; no assumption is made that adding a database mock alone will clear every source failure.

No attempt was made to bypass the guard, query production, skip tests, import the extra public fixtures into SOURCE, or expand this patch. Consistent with the source-first gate, **public propagation and public test execution stopped**. The next decision is whether to authorize the separately identified source fixture-parity changes before rerunning the source gate. This report does not apply or authorize them.

### Public state, scans and exact changed files

Public code and tests have not changed in this execution. Their last measured result remains 59 total / 55 passed / 4 failed; those are prior results, not a post-patch public run. Post-propagation operational/secret/size/artifact scans were not run because propagation was prohibited by the failed source gate. Previous PASS/zero-secret findings are historical and are not recertified here.

Exactly four SOURCE files changed: the four files in the scope table above. Exactly one PUBLIC file changed: docs/VALIDATION.md. No original STATUS.md, public STATUS.md, README, architecture document, inventory, environment file or dataset was changed. The inventory's stored size for this report is therefore stale and must be refreshed in a later authorized documentation pass.

Final review verified the source diff and content fingerprints: all source content outside the four target files, including original Git and preexisting changes, remained identical. All public content except this report remained identical. No public Git repository was created.

**Source gate: FAIL; bounded bug fix: PASS; outdated tests updated: 3/3; public propagation: NOT PERFORMED; release-review readiness: NO.**

No commits, branches, GitHub repository creation or push were performed. The four source patches remain uncommitted for review.

## Seven-failure independence and conditional public propagation

### Current result — supersedes earlier stage statuses

**SEVEN_FAILURES_ANALYSIS_STATUS=PASS; SEVEN_FAILURES_PREEXISTING=7; SEVEN_FAILURES_PATCH_RELATED=0; SOURCE_PATCH_SCOPE_VALIDATED=YES.**

**SOURCE_BASELINE_TESTS_TOTAL=79; SOURCE_BASELINE_KNOWN_FAILURES=7.** Here 79 denotes the current equivalent source suite after the approved additions, not an assertion that 79 tests existed before the patches. The previously recorded 72/79 source result remains visible and is not reclassified as a globally green source suite.

**PUBLIC_PATCH_PROPAGATED=YES; PUBLIC_TESTS_TOTAL=79; PUBLIC_TESTS_PASSED=79; PUBLIC_TESTS_FAILED=0.** No tests skipped or removed. The increase from 59 is exactly the 20 approved additional cases: two source-selection cases, 17 parameterized scope cases and one merge case.

### 1. Baseline reconstructed without modifying SOURCE

Read HEAD:tests/test_route_graph_contract.py through Git, with no checkout/reset/revert. The prior execution recorded this file clean before the patches, so HEAD supplies its actual pre-patch test version. AST comparisons (excluding line-location metadata) prove that all seven failing test functions and their _graph helper are identical before and after the four patches.

The relevant production dependency slice was also checked against HEAD using a read-only Git diff: route_graph_builder.py, bgp_operational_queries.py, external_route_inventory.py and app/db/connection.py have no changes. The test harness uses the same installed dependencies and offline guard in both comparisons.

Executed the prior and current test-module text in separate in-memory namespaces inside an isolated network namespace, with bytecode disabled, an invalid database URL, denied Psycopg connections and network/subprocess guards. All seven functions in both versions raise the same **RuntimeError: Database access forbidden**. No temporary project checkout or on-disk test copy was required. No fixture or assertion was modified for this comparison.

Runtime call profiling confirms the failing path does not execute app/services/route_memory_graph_export.py. The failures do not execute either modified route-memory test module. This is a controlled reproduction of the relevant dependency slice, not an attempt to reconstruct every historical package, running service or database state.

### 2. Individual findings

All TEST entries below are functions in **tests/test_route_graph_contract.py**. FAILURE for each is **RuntimeError: Database access forbidden**.

FILES_INVOLVED common path **BGP_PATH**:

1. tests/test_route_graph_contract.py: test and _graph;
2. app/services/route_graph_builder.py: build_route_graph_v1 and _bgp_evidence_for_public_ip;
3. app/services/bgp_operational_queries.py: lookup_bgp_by_ip and _fetch_one;
4. app/db/connection.py: get_connection;
5. diagnostic Psycopg guard.

The first case also visits app/services/external_route_inventory.py for external hop context; its prior/current call path is the same. This does not enter the patched route-memory exporter.

| TEST | FAILURE | ROOT_CAUSE | FILES_INVOLVED | TOUCHES_CURRENT_PATCH_FILES | CAUSALLY_RELATED_TO_CURRENT_PATCH | BASELINE_CLASSIFICATION |
|---|---|---|---|---|---|---|
| test_simple_three_hop_route | Database access forbidden | Original contract fixture leaves public-hop BGP lookup live | BGP_PATH plus external_route_inventory.py | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_silent_hop_is_explicit | Database access forbidden | Public destination lookup lacks isolated reference fixture | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_private_and_public_ip_flags | Database access forbidden | Public-hop lookup reaches real persistence boundary | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_validator_rejects_missing_node_for_edge | Database access forbidden | Graph construction consults BGP before validator assertions | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_missing_fields_remain_null | Database access forbidden | Missing-context test has no explicit empty BGP reference | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_cytoscape_adapter_returns_expected_shape | Database access forbidden | Graph construction consults BGP before adapter assertions | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |
| test_diagnostics_summary_counts_missing_fields | Database access forbidden | Graph construction consults BGP before diagnostics; original fixture also lacks the explicit observation evidence previously supplied publicly | BGP_PATH | YES, containing test file only | NO | PREEXISTING_CONFIRMED |

Shared file location is not shared causality: P1 modifies another test and imports its local dependency, not these seven functions or _graph. Running the old module without the new imports produces the same seven failures. P4 modifies a different graph implementation, route_memory_graph_export, not route_graph_builder.

### 3. Public-component boundary

The RouteGraph component itself IS included in the public tree; it would be inaccurate to claim it is excluded or that these tests concern unrelated product functionality. The defect established here is **source test-fixture isolation**, not a demonstrated production BGP regression.

Before propagating anything, all seven existing public counterparts were run under the existing offline harness: **7 passed**. Their already-reviewed public empty-BGP fixture and explicit diagnostic evidence isolate the required dependencies. Those fixtures were retained unchanged. Thus the specific seven source-baseline failures are absent from the intended public test surface; no production BGP integration claim follows from these unit results.

This satisfies the conditional propagation boundary: preexistence and causal independence are demonstrated, and the public counterparts pass before and after propagation. The source's seven failures remain a separate maintenance task. No source test, fixture or code was edited in this session, and none of the failures was hidden, deleted or marked skipped.

### 4. Publication patch, real bug and updated tests

Only the approved functional deltas were merged into the four corresponding public files:

- app/services/route_memory_graph_export.py: selected-fact IP scope validation for direct ASN and generated AS-label fallback.
- tests/test_route_graph_contract.py: supported external-inventory fallback, local preference and 404; retained the existing public BGP/evidence fixtures.
- tests/test_route_memory.py: assert operational divergence on the comparison result and preserve the individual report's structural result; retained sanitized observation fixtures.
- tests/test_route_memory_graph_export.py: exact shared-edge identity; separate valid-public precedence from private fact rejection; 17 scope cases and shared-node regression check.

No source directories, original Git, environment files, operator configuration, STATUS.md or data were copied. Merge was by reviewed code/test deltas; operational names and addresses already generalized publicly were preserved.

The real bug fix is limited to newly built route-memory graphs. Present invalid/non-global addresses cannot gain direct ASN merely from a preferred public-tagged fact. Raw evidence, existing facts, stored snapshots, contextual segment ASN and absent-IP behavior remain unchanged. Globally scoped input still is not proof that the supplied ASN is accurate. No migration, rebuild, external measurement or historical-data repair was performed.

### 5. Public validation and scans

- Full existing public offline harness: **79 passed in 0.30s**, exit 0, zero skips/failures.
- Python syntax and FastAPI application import without service startup: PASS.
- Operational-reference and secret scans: PASS; zero detected real secrets. Every candidate file checked against the previously reviewed operational identifiers/addresses, private paths, common provider-token/private-key patterns, credential-bearing URLs, Basic/Bearer literals and nontrivial private environment secret values. Private values were neither printed nor copied.
- Existing private-range security rules, synthetic fixtures and public-service endpoints retain their contextual classifications; no blanket private-IP replacement.
- Files over 1 MB: none; largest file 203,313 bytes. Candidate count remains 217.
- No original/public .git, environment files, dumps, HARs, logs, RIB/MRT/CSV datasets, archives, symlinks, virtual environments or generated Python/cache artifacts found.
- No live database, BGP feed, device, browser, LLM or Grafana integration test was executed. Existing installed dependencies used without installation.
- README/architecture validation notices and public STATUS updated to reflect this result; historical diagnosis sections retained. Inventory sizes refreshed.

Secret scanning remains bounded by the documented patterns and known-value checks, not a universal proof against unknown secret formats. This is final-review readiness, not publication authorization.

### 6. Exact session changes and preservation

SOURCE: **no changes**. Aggregate content verification covers tracked/untracked files and original Git contents, preserving the previous four uncommitted patches and all earlier user changes.

PUBLIC functional files: the four listed above. PUBLIC documentation/status files: docs/VALIDATION.md, README.md, ARCHITECTURE.md, STATUS.md and docs/FILE_INVENTORY.md. These documentation changes only reconcile validation results, bounded attribution behavior and sizes; they add no new feature claim.

**PUBLIC_TREE_READY_FOR_FINAL_REVIEW=YES. GIT_CREATED=NO; COMMIT_CREATED=NO; PUSH_PERFORMED=NO.** The seven source failures remain an explicit separate maintenance boundary. License decision and live integration validation remain outside this session.
