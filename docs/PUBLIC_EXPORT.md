# Public export boundaries

This is a curated source export with a new Git history. The operational project and its Git were not used as the public repository.

## Included

- Application Python and selected experimental browser interfaces.
- Unit/contract tests and selected pipeline/measurement/query scripts.
- Historical SQL schemas and queries, graph contracts and dashboard definitions.
- Newly written public architecture, history, roadmap and postmortem.

## Deliberately omitted

- Original Git, operational STATUS and private reports.
- All environment files, including the unsafe original `.env.example`.
- Device/SSH/deployment configuration and operator-specific active-target baseline scripts/tests.
- RIBs, UPDATE datasets, bootstrap CSVs, HARs, dumps, logs and Grafana backups.
- Virtual environments, generated caches and temporary artifacts.
- Third-party icon assets and the icon gallery. Interfaces referencing those optional assets may show missing icons; the public export is not a polished UI distribution.
- Operational CIDR rebuild/promotion scripts and private rollback artifacts.

## Sanitized examples

Operational addresses and worker names in fixtures were replaced with illustrative values. Documentation networks are used for public-address examples. Private-only topology fixtures retain synthetic RFC1918 values so private/public classification tests keep their purpose. Reserved-range safety policies are preserved; they were not blindly replaced.

Public DNS addresses used by existing unit examples are reference values, not authorization to measure a third party. No measurement is made by the offline check. Existing laboratory views contain illustrative payloads; they are not production observations shipped with this export.

The MikroTik host must be explicitly configured. The convenience API launcher resolves its location relative to the export and defaults to loopback. These are public-export safety/configuration changes, not fixes applied to the private deployment.

## Configuration

No credentials or default working connection URL are supplied. Database-backed operation requires an isolated PostgreSQL database and an explicitly supplied `DATABASE_URL`. Never reuse a production database for public-source tests.

Relevant names include `ROUTEBRAIN_AUTH_ADMIN_USERNAME`, `ROUTEBRAIN_AUTH_ADMIN_PASSWORD`, viewer equivalents, and `ROUTEBRAIN_MIKROTIK_HOST`, `ROUTEBRAIN_MIKROTIK_USERNAME`, `ROUTEBRAIN_MIKROTIK_PASSWORD`. Names are configuration interfaces, not embedded secrets. Set device credentials only for a device you administer.

LLM assistance optionally uses `OPENAI_API_KEY`. Embeddings may use FlagEmbedding, PyTorch and model weights; these are not installed or loaded by the offline check. Playwright browser binaries are a separate optional installation. Do not assume the minimal Python requirements reproduce the original embedding runtime.

The source contains write-capable actions. SQL files have experimental ordering and naming history, including repeated numeric prefixes; review dependencies rather than treating filename order as a migration runner.

## Test boundary

`scripts/offline_check.py` runs syntax, API import and selected existing unit/contract tests. It blocks network/database access and subprocess execution. Fake persistence tests validate contracts, not PostgreSQL behavior. It does not certify real database migrations, live ingestion, browser execution, embeddings, Grafana datasource access or an end-to-end materialization loop.

## Third-party material and license

RouteViews, IX.br, RDAP, PeeringDB and IANA supply external reference data. BGE-M3 supplies optional model weights. Browser views may load libraries from public CDNs; review their licenses and availability before distribution or deployment. No dataset redistribution permission or project license is implied.

LICENSE_DECISION=PENDING
