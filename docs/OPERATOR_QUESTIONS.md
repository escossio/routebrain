# Questions RouteBrain Is Designed to Answer

RouteBrain aims to turn network observations into a contextual, temporal representation that helps an operator reason about the network's experience of the Internet. Storing BGP provides a reference layer for that purpose.

The central question is broader than where a route is now: **what it was, where it passed, in what context it was observed, what changed, and which earlier operator actions were associated with those changes.** These questions often require evidence spread across routing tables, measurements, inventory and operator records.

The questions below are grouped by maturity. They do **not** mean that the current implementation answers every question end to end. An **implemented building block** supplies part of an answer; **experimental** components explore how to connect evidence; other questions **require accumulated observations** or remain **architectural direction**.

## Questions supported by existing building blocks

| Operator question | Existing components and answer boundary |
|---|---|
| What BGP prefix contains this destination? | Longest-prefix matching (LPM) against the PostgreSQL routing reference finds the most specific available prefix. The answer is bounded by that reference dataset. |
| Which origin ASN is associated with this observed prefix? | MRT projection, raw/current route storage and BGP queries provide recorded origin-ASN context. This is routing evidence, not proof of the identity of every responding hop. |
| Which destinations are actually being used by this operator's network? | Observed-destination collection and persistence record destinations visible to the configured traffic source. Collection coverage and observation time limit the answer. |
| What path was observed toward this destination? | Traceroute collection, parsing and stored runs provide a path observation from a particular vantage point and time. It is not a universal path or a complete physical topology. |
| Which hops responded during a traceroute? | Traceroute parsing and hop records distinguish responding addresses from missing responses. A silent hop does not identify a device. |
| Have parts of this path been observed before? | Experimental route memory, segment matching and graph snapshots can associate recurring path evidence with stored observations. Matching a segment does not establish perfect device identity. |
| What BGP, inventory or enrichment evidence is already known about this destination? | BGP queries, inventory, enrichment and caches supply context. Experimental route reports, semantic documents and retrieval help assemble existing evidence; provenance and freshness still matter. |
| What evidence is missing before RouteBrain can give a stronger answer? | Report diagnostics, graph validation and evidence fields expose some missing BGP, hop or inventory context. Experimental semantic documents can surface available evidence, but retrieval cannot fill an observation gap or certify completeness. |

These components run through separate operations. Their existence does not establish a complete automatic traffic-to-answer pipeline. See [Architecture](../ARCHITECTURE.md) for component boundaries and [Validation](VALIDATION.md) for the public test scope.

## Questions that require accumulated temporal knowledge

These questions require multiple temporally valid observations, with their vantage points, timestamps, provenance and coverage preserved. The current historical RIB alone does not provide a week of observed paths or a timeline of routing events. Repeated ingestion of a snapshot does not create that history.

| Operator question | Evidence required |
|---|---|
| How was this network or destination reached one week ago? | Retained path observations from that period and the relevant vantage point, with routing context valid at that time. If they were never collected, the answer must remain unknown. |
| What changed between the path observed at T1 and the path observed at T2? | Comparable timestamped runs, destination and vantage-point context, and explicit handling of missing responses. Experimental report comparison is a foundation, not general historical reconstruction. |
| When did this element first appear in this path? | A retained observation sequence and contextual matching. “First observed” is bounded by collection coverage; it is not necessarily when the element first existed. |
| Is this the same network element observed previously under another context? | Repeated address, neighbor, path-position and other identity evidence. Accumulated history is necessary but insufficient: cross-context entity resolution remains architectural direction. |
| Which adjacencies are stable and which ones changed over time? | Repeated comparable path observations and relationship matching. Observed hop adjacency is not proof of a physical link. |
| Did latency change together with a routing-path change? | Time-aligned ping/traceroute measurements and routing observations with compatible scope. Co-occurrence supports investigation, not a causal conclusion. |
| Which destinations began using a different upstream or path? | Repeated destination/path observations, ASN context and, where available, edge or upstream evidence from the same network viewpoint. |
| What did the operator's relevant Internet look like before a given event? | Sufficiently retained, time-scoped destination, path and relationship evidence. Any representation must show gaps; complete point-in-time reconstruction is not implemented. |

Temporal persistence and comparison exist experimentally. General historical answers additionally require retention, freshness rules, consistent identities and reconciliation of invalid derived evidence. The [CIDR postmortem](CIDR32_POSTMORTEM.md) explains why recovered reference tables do not automatically make every historical derivative valid.

## Architectural questions / future reasoning

The longer-term direction connects policy and action records with observations before and after a change:

- When this routing policy changed previously, what changed in the paths observed from the network?
- Which past policy changes were associated with traffic moving from one edge or upstream to another?
- If an operator wants to influence inbound traffic toward another edge, what historical evidence is relevant before changing BGP communities?
- Which BGP community or policy options are plausible candidates for producing the desired routing effect?
- What evidence supports that recommendation?
- What observations would be required to validate the result after the change?

The intended evidence sequence is:

```text
policy/action
→ observation before
→ change
→ observation after
→ contextual/temporal correlation
```

Here, policy/action identifies the proposed or recorded intervention; the actual change follows the baseline observation. Useful records would include intended effect, policy scope, relevant edges or upstreams, timing and other concurrent changes. Comparing before/after observations could then surface similar past situations and their limits.

**This is architectural direction. RouteBrain does not currently provide an operational automatic BGP-community recommendation or execution loop.** Candidate policies would require evidence of the relevant upstream's supported policy semantics and operator review. Historical association does not prove causality or guarantee a future result.

Inbound-traffic questions also require observations that actually cover inbound behavior, such as relevant traffic/edge records or external vantage points. An outbound traceroute alone cannot establish how traffic enters the network. Validation would need observations of the intended effect after the change, with uncertainty and competing explanations retained.

## Why these questions become possible

The intended composition connects evidence to an operator answer:

```text
Observed traffic
→ destination
→ prefix/LPM
→ BGP context
→ enrichment
→ active observation
→ contextual entity/relationship
→ timestamped memory
→ comparison with previous observations
→ operator answer
```

Traffic supplies the working set. LPM and enrichment connect a destination to reference context; deliberately selected measurements add observations; contextual relationships and timestamps make comparison meaningful. Semantic documents and retrieval can help locate that evidence for an answer. They do not create missing history.

In the intended materialization strategy, existing knowledge is reused when its provenance, freshness and context remain valid. A newly observed destination should materialize only newly relevant parts of the graph and update affected relationships, rather than rebuild all knowledge. The automatic controller and comprehensive invalidation policy remain unfinished.

As observations accumulate, the operator can build an increasingly complete representation of **the Internet its own network actually experiences**, within the limits of collection coverage. This is the practical connection between selective materialization, contextual identity, temporal memory and operator reasoning.

## Contextual identity: observed address versus entity

**IP address != entity identity.** A private or reused address can occur in multiple contexts. The same address alone cannot prove that two observations refer to the same element; a different address alone need not prove that they refer to different elements.

A future contextual identity may combine:

- vantage point;
- predecessor and successor;
- ASN context;
- path position;
- interfaces and other evidence, when available;
- recurrence;
- timestamps;
- neighboring entities.

The architectural direction separates the **observed address** from an internal, opaque **contextual entity identity**, potentially represented by a hexadecimal fingerprint/hash. The final identity algorithm is not implemented. Existing experimental segment fingerprints and graph keys are building blocks, not the completed identity model.

A hash can encode selected evidence; it cannot establish that the evidence identifies a unique router. Resolving ambiguity, deciding when identities should merge or split, and preserving identity across context changes remain open work. Uncertain matches must stay uncertain.

## Usage-driven materialization: the architectural pivot

The first approach was **global BGP ingestion → attempted broad contextualization**. Ingesting the global reference proved much less costly than building and maintaining deep knowledge for every prefix, path and element. This is the project's engineering motivation, not a universal performance benchmark.

The new approach is **traffic-driven working set → selective deep materialization**. Global routing data remains useful as reference, while observed destinations determine where deeper context is worth collecting and retaining.

> RouteBrain does not need to deeply model the whole Internet. It needs to deeply model the part of the Internet that matters to the network using it.

This direction does not claim a complete digital twin, perfect identification of private routers, automatic prediction of Internet behavior or global real-time monitoring. Its purpose is to make operator answers better grounded in the evidence actually collected.
