# Roadmap e fronteiras da implementação

## Bases existentes

- Ingestão de RIB global e preservação dos registros MRT de origem.
- Normalização CIDR, armazenamento de rotas em PostgreSQL e Longest Prefix Match.
- Inventário de destinos derivados do tráfego, enriquecimento e promoção explícita de baseline.
- Armazenamento de ping/traceroute, tratamento de hops e contratos de grafos.
- Route memory, documentos semânticos e recuperação híbrida experimentais.
- API, CLI e definições de consultas Grafana.

## Primeira prioridade de engenharia: reconciliar o incidente CIDR

As tabelas privadas principais raw/current foram recuperadas. Não se deve repetir esse trabalho sem evidência. A fronteira restante envolve semântica de eventos, resumos persistidos, caches, evidências históricas e contexto semântico derivado.

Antes de qualquer reparo: preservar estado, validar a integridade da origem, definir a semântica de baseline/evento, isolar dados legados inválidos, construir derivados corrigidos separadamente, validar e promover com rollback testado. Limpeza só depois das decisões de retenção.

## Integração experimental

- Tornar explícitas e observáveis as transições de seleção, consentimento, medição e materialização.
- Propagar a geração do dataset por resumos, evidências, caches, documentos e embeddings.
- Distinguir falha de aquisição de ausência de correspondência BGP.
- Melhorar testes de integração isolados e reproduzíveis e a preparação dos schemas.
- Tratar ponto de observação e momento da medição como restrições explícitas das consultas.

## Direção arquitetural

- Controlador automático do working set, orientado por destinos realmente observados e prioridades do operador.
- Identidades contextuais com adjacência, posição no caminho, ASN, tempo e recorrência.
- Comparação temporal de rotas/grafos com incerteza e proveniência.
- Orçamentos seletivos de enriquecimento e políticas de cache que evitem processamento desnecessário.

Esses itens são direções, não funcionalidades concluídas. Materialização de toda a Internet, monitoramento BGP global em tempo real, remediação autônoma e alta disponibilidade não são promessas desta versão.

## Decisões de publicação

- PT-BR é o idioma canônico da documentação principal; README.en.md é a tradução secundária para a audiência internacional.
- A licença do projeto permanece pendente de escolha pelo responsável.
- Assets de terceiros, datasets e pesos de modelos permanecem fora do repositório.
- Afirmações sobre deployment de produção e desempenho exigem validação separada.
