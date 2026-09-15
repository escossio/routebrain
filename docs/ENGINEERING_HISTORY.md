# História de engenharia

## 1. Ingestão global

O primeiro experimento usou uma RIB real do RouteViews. O pipeline processou mais de um milhão de registros normalizados e explorou armazenamento raw/current em PostgreSQL, processamento incremental, bootstrap em chunks e apoio de worker offline.

Isso demonstrou ingestão nessa escala. Não demonstrou que cada prefixo poderia ser enriquecido em um modelo semântico profundo e continuamente mantido no hardware disponível.

## 2. O escopo virou uma restrição arquitetural

O relato arquitetural recuperado do responsável pelo projeto identifica o custo prático da contextualização global como motivação do pivô. Vazão de ingestão e custo de manter identidades, históricos, observações e documentos semânticos são problemas diferentes. Não se afirma um benchmark universal de escala ou um limite preciso de hardware.

## 3. Materialização seletiva

O tráfego observado fornece um working set operacional. Um destino se torna candidato a LPM, contexto de ASN, enriquecimento e, quando necessário, observação ativa. Promoção de baseline e medições continuam sendo operações explícitas.

O código de observed destinations, com suas execuções, enriquecimento e baselines, demonstra partes dessa direção. Não comprova um ciclo autônomo end-to-end nem um deployment de produção.

## 4. Memória contextual e temporal

Observações de rotas, fatos de hops, correspondência de segmentos e snapshots de grafos ampliam a unidade de conhecimento: do IP isolado para a observação com contexto. O resultado pretendido é a Internet relevante para o operador, vista de seu ponto de observação.

A persistência temporal existe experimentalmente. Entity resolution contextual completa e respostas históricas gerais continuam como trabalho arquitetural.

## 5. Recuperação como lição de engenharia

Uma projeção inicial perdeu os comprimentos CIDR. Preservar o JSON de origem permitiu reconstruí-los sem inventar máscaras de rede. As tabelas principais foram corrigidas; eventos, resumos e caches derivados permaneceram inconsistentes. O [postmortem](CIDR32_POSTMORTEM.md) documenta essa fronteira.

## Fronteira da publicação

Este repositório começou com um histórico público novo. O Git privado de desenvolvimento e registros operacionais não foram importados. A publicação sanitizou exemplos e removeu material de deployment privado; ela não reparou nem reescreveu retroativamente o experimento operacional.
