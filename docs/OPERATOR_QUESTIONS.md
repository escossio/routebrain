# Perguntas que o RouteBrain pretende responder

O RouteBrain pretende transformar observações de rede em uma representação contextual e temporal que ajude o operador a compreender a Internet experimentada por sua própria rede. Armazenar BGP fornece uma camada de referência para esse propósito.

A pergunta central vai além de onde uma rota está agora: **como ela era, por onde passou, em qual contexto foi observada, o que mudou e quais ações anteriores estiveram associadas a essas mudanças**. Essas perguntas frequentemente exigem evidências distribuídas entre tabelas de roteamento, medições, inventário e registros do operador.

As perguntas abaixo estão agrupadas por maturidade. Elas **não** significam que a implementação atual responde a todas end-to-end. Um componente **IMPLEMENTADO** fornece parte da resposta; componentes **EXPERIMENTAIS** exploram como conectar evidências; outras perguntas **dependem de observações acumuladas** ou permanecem como **DIREÇÃO ARQUITETURAL**.

## Já suportadas por componentes existentes

| Pergunta do operador | Componentes existentes e limite da resposta |
|---|---|
| Qual prefixo BGP contém este destino? | Longest Prefix Match (LPM) sobre a referência de roteamento em PostgreSQL encontra o prefixo mais específico disponível. A resposta é limitada por esse dataset de referência. |
| Qual ASN de origem está associado a este prefixo observado? | Projeção MRT, armazenamento raw/current e consultas BGP fornecem o contexto de ASN de origem registrado. É evidência de roteamento, não prova da identidade de cada hop que responde. |
| Quais destinos são realmente utilizados pela rede deste operador? | Coleta e persistência de observed destinations registram destinos visíveis na fonte de tráfego configurada. Cobertura da coleta e momento da observação limitam a resposta. |
| Qual caminho foi observado até este destino? | Coleta, parsing e execuções armazenadas de traceroute fornecem uma observação de caminho a partir de um ponto e momento específicos. Não é um caminho universal nem uma topologia física completa. |
| Quais hops responderam durante um traceroute? | Parsing de traceroute e registros de hops distinguem endereços que responderam de respostas ausentes. Um hop silencioso não identifica um dispositivo. |
| Partes deste caminho já foram observadas antes? | Route memory, correspondência de segmentos e snapshots de grafos experimentais podem associar evidências recorrentes de caminho a observações armazenadas. Correspondência de segmento não estabelece identidade perfeita de dispositivo. |
| Quais evidências BGP, de inventário ou enriquecimento já conhecemos sobre este destino? | Consultas BGP, inventário, enriquecimento e caches fornecem contexto. Relatórios, documentos semânticos e recuperação experimentais ajudam a reunir evidências existentes; proveniência e atualidade continuam importantes. |
| Que evidência falta para o RouteBrain oferecer uma resposta mais forte? | Diagnósticos de relatórios, validação de grafos e campos de evidência expõem algumas lacunas de contexto BGP, hops ou inventário. Documentos semânticos experimentais podem recuperar evidências disponíveis, mas a recuperação não preenche lacunas de observação nem certifica completude. |

Esses componentes atuam por operações separadas. Sua existência não estabelece um pipeline automático completo do tráfego à resposta. Veja a [arquitetura](../ARCHITECTURE.md) para as fronteiras dos componentes e a [validação, em inglês](VALIDATION.md) para o escopo dos testes públicos.

## Dependem de histórico acumulado

Essas perguntas exigem múltiplas observações temporalmente válidas, preservando pontos de observação, timestamps, proveniência e cobertura. A RIB histórica atual, sozinha, não fornece uma semana de caminhos observados nem uma linha do tempo de eventos de roteamento. Reingerir um snapshot não cria esse histórico.

| Pergunta do operador | Evidência necessária |
|---|---|
| Como essa rede ou destino era alcançado uma semana atrás? | Observações de caminho retidas daquele período e do ponto de observação relevante, com contexto de roteamento válido na época. Se nunca foram coletadas, a resposta deve permanecer desconhecida. |
| O que mudou entre o caminho observado em T1 e o observado em T2? | Execuções comparáveis com timestamps, contexto de destino e ponto de observação e tratamento explícito de respostas ausentes. A comparação experimental de relatórios é uma base, não reconstrução histórica geral. |
| Quando esse elemento apareceu pela primeira vez nesse caminho? | Uma sequência de observações retidas e correspondência contextual. “Primeiro observado” é limitado pela cobertura da coleta; não é necessariamente quando o elemento passou a existir. |
| Esse é o mesmo elemento de rede observado anteriormente em outro contexto? | Evidências recorrentes de endereço, vizinhos, posição no caminho e outros aspectos da identidade. Acumular histórico é necessário, mas insuficiente: entity resolution entre contextos permanece direção arquitetural. |
| Quais adjacências são estáveis e quais mudaram ao longo do tempo? | Observações repetidas de caminhos comparáveis e correspondência entre relações. Adjacência entre hops observados não prova ligação física. |
| A latência mudou junto com uma mudança de caminho de roteamento? | Medições de ping/traceroute e observações de roteamento alinhadas no tempo, com escopo compatível. Coocorrência apoia a investigação, não uma conclusão causal. |
| Quais destinos passaram a usar outro upstream ou caminho? | Observações repetidas de destinos/caminhos, contexto de ASN e, quando disponíveis, evidências de borda ou upstream a partir do mesmo ponto de vista da rede. |
| Como era a Internet relevante ao operador antes de um determinado evento? | Evidências de destinos, caminhos e relações suficientemente retidas e delimitadas no tempo. Qualquer representação precisa mostrar lacunas; reconstrução completa em um instante arbitrário não está implementada. |

Persistência temporal e comparação existem experimentalmente. Respostas históricas gerais também exigem retenção, regras de atualidade, identidades consistentes e reconciliação de evidências derivadas inválidas. O [postmortem CIDR](CIDR32_POSTMORTEM.md) explica por que recuperar a referência não torna automaticamente válido todo derivado histórico.

## Direção arquitetural

A direção de longo prazo conecta registros de políticas e ações às observações antes e depois de uma mudança:

- Quando essa política de roteamento mudou anteriormente, o que mudou nos caminhos observados a partir da rede?
- Quais mudanças de política anteriores estiveram associadas à migração de tráfego entre bordas ou upstreams?
- Se o operador quer influenciar o tráfego de entrada por outra borda, que evidência histórica é relevante antes de alterar BGP communities?
- Quais BGP communities ou opções de política são candidatas plausíveis para produzir o efeito de roteamento desejado?
- Que evidência sustenta essa recomendação?
- Que observações seriam necessárias para validar o resultado após a mudança?

A sequência de evidências pretendida é:

```text
política/ação
→ observação antes
→ mudança
→ observação depois
→ correlação contextual/temporal
```

Aqui, política/ação identifica a intervenção proposta ou registrada; a mudança efetiva vem depois da observação de baseline. Registros úteis incluiriam efeito pretendido, escopo da política, bordas ou upstreams relevantes, horários e outras mudanças simultâneas. Comparar observações antes/depois poderia recuperar situações anteriores semelhantes e seus limites.

**Isso é direção arquitetural. O RouteBrain não oferece hoje um ciclo operacional automático de recomendação ou execução de BGP communities.** Políticas candidatas exigiriam evidência da semântica de políticas suportada pelo upstream relevante e revisão do operador. Associação histórica não prova causalidade nem garante resultado futuro.

Perguntas sobre tráfego de entrada também exigem observações que cubram esse comportamento, como registros relevantes de tráfego/borda ou pontos de observação externos. Um traceroute de saída sozinho não estabelece como o tráfego entra na rede. A validação precisaria observar o efeito pretendido depois da mudança, preservando incertezas e explicações alternativas.

## Por que essas perguntas se tornam possíveis

A composição pretendida conecta a evidência à resposta do operador:

```text
Tráfego observado
→ destino
→ prefixo/LPM
→ contexto BGP
→ enriquecimento
→ observação ativa
→ entidade/relação contextual
→ memória com timestamp
→ comparação com observações anteriores
→ resposta ao operador
```

O tráfego fornece o working set. LPM e enriquecimento conectam um destino ao contexto de referência; medições selecionadas deliberadamente acrescentam observações; relações contextuais e timestamps tornam a comparação significativa. Documentos semânticos e recuperação podem ajudar a localizar evidências para uma resposta. Eles não criam histórico ausente.

Na estratégia de materialização pretendida, o conhecimento existente é reutilizado quando proveniência, atualidade e contexto permanecem válidos. Um destino recém-observado deve materializar apenas partes novas e relevantes do grafo e atualizar relações afetadas, em vez de reconstruir todo o conhecimento. O controlador automático e a política abrangente de invalidação continuam incompletos.

Com o acúmulo de observações, o operador pode construir uma representação cada vez mais completa da **Internet que sua própria rede realmente experimenta**, dentro dos limites da cobertura de coleta. Essa é a conexão prática entre materialização seletiva, identidade contextual, memória temporal e raciocínio do operador.

## Identidade contextual: endereço observado e entidade

**IP address != entity identity.** Um endereço privado ou reutilizado pode aparecer em múltiplos contextos. O mesmo endereço sozinho não prova que duas observações se referem ao mesmo elemento; um endereço diferente sozinho também não prova que se referem a elementos distintos.

Uma identidade contextual futura pode combinar:

- vantage point, ou ponto de observação;
- predecessor e sucessor;
- contexto de ASN;
- posição no caminho;
- interfaces e outras evidências, quando disponíveis;
- recorrência;
- timestamps;
- entidades vizinhas.

A direção arquitetural separa o **endereço observado** de uma **identidade contextual de entidade** interna e opaca, potencialmente representada por fingerprint/hash hexadecimal. O algoritmo definitivo de identidade não está implementado. Fingerprints experimentais de segmentos e chaves de grafos existentes são componentes de base, não o modelo de identidade concluído.

Um hash pode codificar evidências selecionadas; não estabelece que elas identificam um roteador único. Resolver ambiguidades, decidir quando identidades devem ser unidas ou separadas e preservar identidade entre mudanças de contexto continuam como trabalho aberto. Correspondências incertas devem permanecer incertas.

## Materialização orientada pelo uso: o pivô arquitetural

A primeira abordagem foi **ingestão BGP global → tentativa de contextualização ampla**. Ingerir a referência global mostrou-se muito menos custoso que construir e manter conhecimento profundo de cada prefixo, caminho e elemento. Essa é a motivação de engenharia do projeto, não um benchmark universal de desempenho.

A nova abordagem é **working set definido pelo tráfego → materialização profunda seletiva**. Dados globais de roteamento continuam úteis como referência, enquanto destinos observados determinam onde vale coletar e reter contexto mais profundo.

> O RouteBrain não precisa modelar profundamente toda a Internet. Ele precisa modelar profundamente a parte da Internet que importa para a rede que o utiliza.

Essa direção não afirma digital twin completo, identificação perfeita de roteadores privados, previsão automática do comportamento da Internet ou monitoramento global em tempo real. Seu propósito é fundamentar melhor as respostas nas evidências efetivamente coletadas.
