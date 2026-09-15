# Public release preparation

- Scope: curated public source export with new history.
- Operational source: four approved code/test patches applied in the previous stage; no data changes. This propagation stage left the source untouched.
- Narrative: demand-driven materialization; implementation, experiments and direction distinguished.
- CIDR incident: documented honestly; derived-data debt remains.
- License: pending owner decision.
- Syntax check and API import: PASS.
- Isolated public unit/contract checks: 79 total, 79 passed, 0 failed, no skips; see docs/VALIDATION.md.
- Source baseline: 79 equivalent cases, 7 independently confirmed preexisting offline BGP fixture failures; not repaired or skipped.
- Final publication authorized by the owner, conditional on fresh gates. Clean public Git initialized on main; first commit and push are the next gated steps.
- Operational-reference scan: PASS. One residual error-message example sanitized; zero real secrets detected by documented checks.
- Four approved deltas propagated with existing public sanitization and offline fixtures preserved. Scope validation applies to newly exported graphs, not historical data.
- Final editorial review: PASS. Demand-driven semantic materialization, contextual identity and implemented/experimental/direction boundaries verified.
- Fresh offline suite: 79 passed, 0 failed, 0 skipped; syntax and API import PASS. Dependencies prepared in a disposable public-tree virtual environment; test execution used an empty inherited environment and isolated network namespace.
- Final artifact, secret and operational-reference gates: PASS. Zero detected real secrets; no copied Git or forbidden artifacts. Internal documentation links and README file references PASS.
- Pre-initialization gates PASS; new Git metadata created locally without importing any history. Publication proceeds under the owner's explicit authorization. Commit identity and post-push verification will be recorded in the publication response; no post-push content edits.
- Live integrations remain outside these checks; LICENSE_DECISION=PENDING.
- Candidate file inventory: docs/FILE_INVENTORY.md.

## Operator-question documentation update

- Scope: documentation only; operator questions grouped by maturity, evidence requirements and explicit capability limits.
- Added docs/OPERATOR_QUESTIONS.md; linked it from focused additions to README.md and ARCHITECTURE.md.
- No code, tests, original source, database, runtime or implemented architecture changes.
- Validation: existing offline_check completed with 79 passed, 0 failed, 0 skipped; syntax and API import PASS. Execution used a disposable public-tree environment, an empty inherited environment and an isolated network namespace.
- Markdown links, secret scan and operational-reference scan PASS across 218 public files; zero detected real secrets and no new operational literals. Full documentation diff reviewed before commit/push.
- Publication target: main of the existing public repository. Commit and remote verification are reported in the session result.


## Internacionalização da documentação principal

- PT-BR passa a ser o idioma canônico; README.en.md oferece a tradução secundária integral, com navegação entre idiomas nos dois READMEs.
- README, arquitetura, perguntas operacionais, história de engenharia, postmortem CIDR e roadmap traduzidos a partir da versão publicada em 7f477e6. Perguntas, semântica, claims e números auditados preservados.
- Escopo restrito à documentação; código, testes, source original, banco e arquitetura implementada sem alterações.
- Validação final: offline_check com 79 aprovados, zero falhas e zero skips; sintaxe e importação da API PASS, em ambiente descartável com namespace de rede isolado.
- Links Markdown, secret scan e operational-reference scan PASS em 219 arquivos públicos. Zero secrets detectados e nenhuma nova referência operacional.
- Revisão de equivalência: números auditados, comandos e caminhos de código preservados; grupos de perguntas mantêm 8/8/6 itens. Diff restrito aos sete documentos de idioma e a este STATUS.
- Commit e verificação remota serão registrados no resultado da sessão; LICENSE_DECISION=PENDING.
