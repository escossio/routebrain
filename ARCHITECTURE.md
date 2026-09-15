# Arquitetura

## Duas camadas com custos diferentes

A **camada de referência** ingere dados BGP globais e permite consultas por prefixo, ASN e peer. A **camada de materialização profunda** pretende concentrar-se no working set do operador: destinos observados no tráfego e selecionados para investigação adicional.

O pivô diz respeito ao escopo do trabalho semântico. Uma RIB com um milhão de registros pode ser ingerida sem construir históricos contextuais completos para cada rota e elemento de rede.

## Das observações às perguntas do operador

A materialização orientada pelo uso seleciona o que merece investigação; a identidade contextual pretende relacionar observações sem tratar o endereço como identidade definitiva; a memória temporal preserva quando e de onde a evidência foi observada. Juntas, essas bases devem permitir perguntas sobre caminhos anteriores, elementos recorrentes, mudanças e evidências relevantes à próxima ação do operador.

Componentes implementados e memória experimental fornecem partes dessas respostas. Comparações históricas exigem observações acumuladas e comparáveis. Entity resolution entre contextos e raciocínio sobre políticas/ações permanecem como direção arquitetural; correlação antes/depois não estabelece causalidade. Veja [Perguntas que o RouteBrain pretende responder](docs/OPERATOR_QUESTIONS.md).

## Componentes e fronteiras

| Componente | Código | Estado / responsabilidade |
|---|---|---|
| Projeção MRT | `app/parsers/routeviews_mrt_parser.py` | Implementado; normaliza prefixo/comprimento e seleciona a primeira entrada da RIB |
| Normalização CIDR | `app/services/bgp_prefix_normalizer.py` | Helper implementado; fallback dos chamadores em entradas inválidas continua como dívida |
| Persistência raw/current | `app/services/bgp_raw_ingest.py`, `bgp_current_builder.py` | Implementado; PostgreSQL CIDR/INET/JSONB |
| Consultas BGP | `app/services/bgp_operational_queries.py` | LPM e contexto de prefixo/ASN/peer; alguns fluxos preferem resumos persistidos |
| Candidatos derivados do tráfego | `app/services/mikrotik_observer.py`, `observed_destinations.py` | Destinos do connection tracking, execuções e enriquecimento; a configuração do dispositivo deve ser fornecida |
| Baselines | `app/services/observed_destinations.py` | Promoção/atualização explícitas e ações sugeridas; não promove automaticamente todos os destinos |
| Observações ativas | Serviços em `app/services/` e scripts de medição | Parsing e persistência de ping/traceroute; exigem execução deliberada |
| Enriquecimento | `app/services/external_enrichment.py` | RDAP/PeeringDB e contexto com cache; atribuição externa é distinta de confirmação BGP |
| Route memory | `app/services/route_memory.py`, `route_memory_persistence.py` | Observações, correspondência de segmentos, fatos de hops e snapshots de grafos experimentais |
| Contratos de grafos | `app/services/route_graph_builder.py`, `app/adapters/` | Relatórios e adaptadores; adjacência em caminho observado não prova adjacência física |
| Recuperação semântica | `app/services/semantic_memory.py`, `embedding_provider.py` | Documentos, embeddings e recuperação híbrida experimentais; não há treinamento de modelo implementado aqui |
| Interfaces do operador | `app/api/`, `app/cli.py`, `app/static/` | FastAPI, CLI e visualizações experimentais no navegador; incluem consultas e ações |
| Visualização | `deploy/grafana/dashboards/`, `grafana/` | Definições de dashboards/consultas; sem configuração real de datasource |
| Worker de bootstrap | `scripts/bootstrap_parse_bgp_snapshot.py`, `bootstrap_worker_utils.py` | Artefatos de parsing offline em chunks e manifestos; não implica cluster HA ou scheduler distribuído |

## Fluxo existente e composição pretendida

Observed destinations possui operações próprias de coleta, enriquecimento, baseline e sugestão de ações. A promoção exige confirmação. Medições possuem fluxos separados. Route memory e recuperação semântica têm builders/persistência próprios. São partes da materialização orientada pelo uso; não existe um controlador único validado que feche automaticamente todo o ciclo.

O export público não inclui listas históricas de alvos do operador, configurações de deployment ou resultados completos dos laboratórios originais. Veja os [limites do export, em inglês](docs/PUBLIC_EXPORT.md).

## Identidade contextual

O modelo pretendido combina endereço com vantage point, predecessor/sucessor, posição no caminho, ASN, recorrência e momento da observação. Fingerprints e correspondência de segmentos oferecem uma base experimental. Entity resolution independente de IP, regras de merge/split e reconciliação temporal de identidade não estão concluídas.

Nós privados/CGNAT não devem receber ASN público apenas porque um hop público próximo possui um. Um hop pode ter associação contextual sem atribuição BGP direta. Hops silenciosos registram ausência de resposta, não dispositivos identificados.

O exportador de grafos valida um IP de hop presente antes de expor ASN direto ou gerar rótulo AS. Endereços inválidos/não globais perdem a atribuição direta mesmo se o fato preferido estiver marcado como público. Evidência bruta, ASN contextual de segmento e snapshots existentes permanecem intactos; o comportamento sem IP é preservado. Essa correção limitada não é entity resolution completa nem verificação BGP independente. Veja a [validação, em inglês](docs/VALIDATION.md).

## Tempo e proveniência

É necessário distinguir o momento do registro MRT, da ingestão, da medição ativa e da materialização do conhecimento. Recalcular contexto a partir de uma RIB corrigida não equivale a uma nova medição de rede.

O dataset histórico representa principalmente uma RIB. Uma sequência de lotes de ingestão não é uma série temporal de atualizações de roteamento. A tabela histórica de mudanças tem proveniência insuficiente e comparações inválidas; seu código é legado experimental, não um fluxo confiável de incidentes.

## Controles de engenharia e limites

- Scripts do pipeline usam advisory locks do PostgreSQL e cursor por ID raw. Os nomes dos locks variam entre fluxos; não garantem exclusão global por padrão.
- Staging e manifestos separam parsing offline de persistência no servidor.
- Registros raw preservam evidências de recuperação; normalizar não deve destruir a informação de origem.
- Há deduplicação em etapas selecionadas, sem garantia universal de exactly-once.
- Hashes de documentos semânticos evitam parte do reprocessamento de embeddings; invalidação por geração em todos os derivados ainda é trabalho aberto.
- Alguns caches BGP históricos não expiram. Corrigir a referência não corrige automaticamente o conhecimento derivado.

Não se afirma modelo completo da Internet, monitoramento BGP global em tempo real, SLA de produção ou arquitetura de alta disponibilidade.
