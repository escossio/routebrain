# RouteBrain Voice Presentation — Design

## Objetivo

Adicionar ao repositório público uma apresentação curta, visual e narrada do RouteBrain, acessível a partir do README e publicada via GitHub Pages, sem servidor, sem chave de API e sem enfraquecer os gates existentes.

## Experiência do visitante

O README terá um CTA visível: **🔊 Ouvir apresentação do RouteBrain**.

Ao abrir a apresentação, o visitante verá uma página dark coerente com a identidade visual do projeto. Na primeira interação, um modal bloqueará o conteúdo com duas opções:

- **Toque para ouvir a apresentação** — inicia a experiência com áudio.
- **Continuar sem áudio** — fecha o modal e libera a apresentação normalmente.

O navegador não tentará autoplay antes da interação do usuário.

## Conteúdo

A apresentação deve durar aproximadamente 1–2 minutos e seguir esta narrativa:

1. qual problema operacional o RouteBrain tenta resolver;
2. ingestão real de mais de um milhão de registros BGP do RouteViews;
3. diferença entre ingestão global e materialização semântica profunda;
4. pivô para materialização orientada pelo tráfego real do operador;
5. memória temporal/contextual e a pergunta “como essa rede estava uma semana atrás?”;
6. fechamento com arquitetura, evidências e próximos passos.

A apresentação não pode transformar direção arquitetural em claim implementado.

## Arquitetura da página

Fonte versionada no próprio repositório:

- `site/index.html` — estrutura semântica e conteúdo.
- `site/styles.css` — layout responsivo/dark, modal e estados.
- `site/app.js` — controle do modal, áudio, progresso e fallback.
- `site/assets/routebrain-architecture.png` — diagrama visual.
- `site/assets/routebrain-intro.mp3` — narração principal.

A página será publicada por GitHub Pages usando workflow próprio baseado nas actions oficiais de Pages. O deploy ocorrerá somente a partir da `main`, depois dos gates já existentes.

## Áudio

O caminho principal é um MP3 pré-gerado e versionado como asset estático. Isso garante voz consistente, funciona sem expor credenciais e evita dependência de TTS em tempo real.

Fallback: caso o MP3 não carregue, `speechSynthesis` pode narrar o texto em PT-BR quando disponível. Se nem isso estiver disponível, a opção sem áudio permanece funcional.

A página deve oferecer controles mínimos após o início: reproduzir/pausar, reiniciar e ativar/desativar áudio.

## GitHub Pages

Preferência: Pages com **GitHub Actions**, não branch `gh-pages` manual. O workflow de deploy deve ter permissões mínimas e não executar contra PRs.

Se a ativação administrativa de Pages não estiver acessível pelo plugin deste chat, essa única ação será enviada ao Codex/`gh` depois que o PR estiver pronto.

## README

O README PT-BR terá o CTA acima da explicação longa do projeto. `README.en.md` pode receber um link discreto para a mesma apresentação, identificando que a narração inicial é em português.

## Segurança e governança

- nenhuma chave, token ou endpoint privado no frontend;
- nenhuma telemetria externa;
- nenhum script de terceiros necessário;
- nenhum acesso a banco ou runtime RouteBrain;
- alterações entram por branch → PR → required checks → merge;
- `main` continua protegida pelo ruleset atual.

## Acessibilidade e responsividade

- funcionamento em Android/Chrome e desktop;
- contraste alto;
- foco de teclado no modal;
- `aria` para botões e player;
- preferência `prefers-reduced-motion` respeitada;
- conteúdo continua legível sem JavaScript e sem áudio sempre que possível.

## Critérios de aceite

1. README abre a apresentação com um toque.
2. O modal exige gesto do usuário antes do áudio.
3. “Ouvir” inicia a narração e libera a apresentação.
4. “Continuar sem áudio” libera tudo sem erro.
5. MP3 é o caminho preferencial; fallback não quebra a página.
6. O diagrama novo é exibido de forma responsiva.
7. Nenhuma credencial ou dependência operacional é introduzida.
8. Todos os required checks do RouteBrain passam no PR.
9. Após merge, GitHub Pages publica a versão da `main`.

## Fora de escopo nesta V1

- TTS dinâmico via API;
- login;
- analytics;
- backend próprio;
- apresentação multilíngue narrada;
- sincronização palavra-a-palavra com o áudio;
- animações complexas que prejudiquem desempenho móvel.
