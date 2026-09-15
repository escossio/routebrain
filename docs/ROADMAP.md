# Roadmap and implementation boundary

## Existing foundations

- Global RIB ingestion and preserved MRT source records.
- CIDR normalization, PostgreSQL route storage and longest-prefix matching.
- Traffic-derived destination inventory, enrichment and explicit baseline promotion.
- Ping/traceroute storage, hop handling and graph contracts.
- Experimental route memory, semantic documents and hybrid retrieval.
- API, CLI and Grafana query definitions.

## First engineering priority: reconcile the CIDR incident

The main private raw/current tables were recovered. Do not repeat that work without evidence. The remaining boundary is event semantics, persisted summaries, caches, historical evidence and derived semantic context.

Before any repair: preserve state, validate source integrity, decide baseline/event semantics, isolate invalid legacy data, build corrected derivatives separately, validate and promote with a tested rollback. Cleanup comes only after retention decisions.

## Experimental integration work

- Make selection, consent, measurement and materialization transitions explicit and observable.
- Track dataset generation through summaries, evidence, cache, documents and embeddings.
- Distinguish acquisition failure from absence of a BGP match.
- Improve reproducible isolated integration tests and schema setup.
- Make measurement vantage point and observation time first-class query constraints.

## Architectural direction

- An automatic working-set controller driven by real observed destinations and operator priorities.
- Contextual entity identities using adjacency, path position, ASN, time and recurrence.
- Temporal route/graph comparison with uncertainty and provenance.
- Selective enrichment budgets and cache policies that avoid unnecessary processing.

These are directions, not completed features. Full Internet materialization, real-time BGP monitoring, autonomous remediation and high availability are not promises of this release.

## Publication decisions

- Project license remains pending owner selection.
- Third-party assets, datasets and model weights remain outside the repository.
- Production deployment and performance claims require separate validation.
