# Incidente CIDR /32: preservar evidências permitiu recuperar os dados

## Falha

O registro MRT decodificado trazia o endereço de rede e seu comprimento separadamente. O parser inicial projetava apenas o endereço na coluna normalizada `prefix`. O importador passava essa string ao tipo `cidr` do PostgreSQL, que interpretava um endereço IPv4 isolado como host `/32`.

Redes diferentes com o mesmo endereço base passaram a colidir na chave de rota corrente. Diferenças de atributos entre esses prefixos distintos apareciam como mudanças de rota.

## Recuperação

O JSONB original em `raw_record` preservava `prefix` e `length`. A combinação permitiu reconstruir a coluna CIDR de forma controlada. O processo histórico usou tabelas isoladas de reconstrução, validação e promoção planejada para preservar views dependentes.

A auditoria somente de leitura, realizada em 2026-09-15, verificou:

| Tabela | Antes: registros | Depois: registros | Antes: registros /32 | Depois: registros /32 |
|---|---:|---:|---:|---:|
| raw | 1.061.466 | 1.061.466 | 1.061.466 | 84 |
| current | 1.041.877 | 1.061.196 | 1.041.877 | 84 |

A current possui aproximadamente 1.061.192 prefixos distintos. A comparação completa de raw com o prefixo + comprimento preservados encontrou **zero divergências**. Os 84 registros `/32` restantes são legítimos nesse dataset; excluir todos os `/32` seria outro erro.

Essas medições do dataset privado são publicadas como evidência histórica agregada. O dataset e os arquivos privados de auditoria não são distribuídos aqui.

## O que não foi recuperado end-to-end

Na auditoria, a tabela histórica `bgp_route_changes` ainda continha 1.052.202 registros:

- 1.040.932 registros `NEW_ROUTE` representavam materialização inicial de chaves ausentes.
- 10.972 comparações `AS_PATH_CHANGED` e 298 `ORIGIN_TYPE_CHANGED` envolviam o mesmo endereço base e timestamp MRT, mas máscaras diferentes.

Isso **não comprova um milhão de mudanças BGP temporais reais**. Substituir apenas o prefixo desses eventos não tornaria válidas as comparações originais.

A auditoria também encontrou resumos de current desatualizados, resumos de mudanças contaminados, evidências/caches BGP antigos, snapshots de ASN e documentos semânticos derivados das contagens anteriores. Alguns caches BGP não expiravam. Corrigir uma tabela de referência não equivale a reconciliar todas as representações derivadas.

## Dívida de código remanescente

O normalizador atual valida o comprimento do prefixo, mas seus chamadores no parser podem retornar ao endereço sem máscara quando ocorre erro de normalização. Escritores e entradas de staging ainda precisam de uma política de validação end-to-end. O export público não afirma reparação completa do incidente.

O script operacional de reconstrução e os artefatos privados de promoção/rollback não foram incluídos como ferramenta pública pronta para reparo. Schemas históricos e processadores de eventos continuam experimentais e não devem ser executados cegamente.

## Lições e próximos trabalhos

1. Preservar registros de origem junto às projeções normalizadas.
2. Tratar prefixo como endereço **e** comprimento em todas as fronteiras.
3. Distinguir importação de baseline de evento temporal.
4. Versionar datasets e derivados; TTL sozinho não representa validade semântica.
5. Manter evidência histórica inválida rastreável, sem apresentá-la como verdade operacional atual.
6. Reconstruir derivados na ordem de dependência e validar consumidores antes da promoção.

Uma futura correção deve ocorrer em fluxo isolado e reversível. Nenhuma correção do deployment privado foi feita para criar esta publicação.
