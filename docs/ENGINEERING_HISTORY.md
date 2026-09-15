# Engineering history

## 1. Global ingestion

The initial experiment used a real RouteViews RIB. The pipeline processed over one million normalized records and explored PostgreSQL raw/current storage, incremental processing, chunked bootstrap and offline worker assistance.

This established that ingestion could work at that scale. It did not establish that every prefix could be enriched into a deep, continuously maintained semantic model on the available hardware.

## 2. Scope became an architectural constraint

The project owner's recovered architectural account identifies the practical cost of global contextualization as the motivation for the pivot. Ingestion throughput and the cost of maintaining identities, histories, observations and semantic documents are different concerns. No universal scaling benchmark or precise hardware threshold is claimed.

## 3. Selective materialization

Observed traffic supplies an operational working set. A destination becomes a candidate for LPM, ASN context, enrichment and, when warranted, an active observation. Baseline promotion and measurements remain explicit operations.

Code for observed destinations and their associated runs, enrichment and baselines demonstrates this direction. It does not prove an autonomous end-to-end loop or production deployment.

## 4. Contextual and temporal memory

Route observations, hop facts, segment matching and graph snapshots expand the unit of knowledge from an IP address to an observation with context. The intended result is the Internet relevant to an operator, seen from that operator's vantage point.

Temporal persistence exists experimentally. Complete contextual entity resolution and general historical question answering remain open architecture work.

## 5. Recovery as an engineering lesson

An early projection lost CIDR lengths. Preserving source JSON made reconstruction possible without inventing network masks. The main tables were corrected, while downstream events, summaries and caches remained inconsistent. The [postmortem](CIDR32_POSTMORTEM.md) documents this boundary honestly.

## Public release boundary

This repository begins with a new public history. The private development Git and operational records are not imported. Publication sanitizes examples and removes private deployment material; it does not retroactively repair or rewrite the operational experiment.
