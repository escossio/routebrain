# RouteBrain Voice Presentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publicar uma apresentação curta e narrada do RouteBrain via GitHub Pages, acionada pelo README e narrada com a voz Zagan da xAI.

**Architecture:** Site estático em `site/`, sem backend e sem credenciais no navegador. O áudio é pré-gerado em MP3 com xAI TTS (`voice_id: zagan`, `language: pt-BR`) e versionado como asset. GitHub Pages publica somente a `main` via workflow próprio depois dos gates existentes.

**Tech Stack:** HTML5, CSS3, JavaScript vanilla, GitHub Actions/Pages, xAI TTS para geração offline do MP3.

**Spec:** `docs/superpowers/specs/2026-09-15-routebrain-voice-presentation-design.md`

## Global Constraints

- PT-BR é o idioma principal da apresentação.
- Voz oficial: xAI Zagan (`voice_id: zagan`).
- Nenhuma chave/token xAI no frontend ou repositório.
- Sem TTS em tempo real no site.
- Sem analytics e sem backend.
- `main` só recebe mudanças via PR com todos os required checks verdes.
- O conteúdo deve distinguir implementado, experimental e direção arquitetural.

---

### Task 1: Site estático e modal de entrada

**Files:**
- Create: `site/index.html`
- Create: `site/styles.css`
- Create: `site/app.js`

**Interfaces:**
- Consumes: `site/assets/routebrain-intro.mp3`, `site/assets/routebrain-architecture.png`
- Produces: página responsiva com modal de escolha de áudio e controles do player.

- [ ] Criar HTML semântico com hero, resumo, escala técnica, pivô arquitetural, pergunta temporal e arquitetura.
- [ ] Criar modal com `Ouvir apresentação` e `Continuar sem áudio`, sem autoplay antes do gesto.
- [ ] Implementar player com play/pause, reinício e mute/unmute.
- [ ] Se o MP3 falhar, mostrar aviso não intrusivo e liberar o conteúdo sem tentar outra voz.
- [ ] Garantir navegação por teclado, `aria` e `prefers-reduced-motion`.
- [ ] Revisar em largura móvel e desktop.

### Task 2: Assets visuais e áudio

**Files:**
- Create: `site/assets/routebrain-architecture.png`
- Create: `site/assets/routebrain-intro.mp3`

**Interfaces:**
- Consumes: diagrama aprovado e roteiro PT-BR aprovado.
- Produces: assets estáticos usados pelo site.

- [ ] Copiar o diagrama novo para `site/assets/routebrain-architecture.png`.
- [ ] Gerar `routebrain-intro.mp3` com xAI TTS usando `voice_id=zagan`, `language=pt-BR`, qualidade MP3 padrão de alta fidelidade.
- [ ] Confirmar que o MP3 contém somente a narração prevista e nenhuma informação sensível.
- [ ] Confirmar que nenhum token/chave foi adicionado ao Git.

### Task 3: Publicação via GitHub Pages

**Files:**
- Create: `.github/workflows/pages.yml`

**Interfaces:**
- Consumes: diretório `site/` na `main`.
- Produces: deployment GitHub Pages.

- [ ] Configurar `actions/configure-pages`, `actions/upload-pages-artifact` e `actions/deploy-pages` com permissões mínimas.
- [ ] Executar apenas em `push` da `main` e `workflow_dispatch`.
- [ ] Publicar somente `site/`.
- [ ] Não executar deploy em PR.

### Task 4: Integração com README

**Files:**
- Modify: `README.md`
- Modify: `README.en.md`

**Interfaces:**
- Consumes: URL pública do GitHub Pages.
- Produces: CTA visível para a apresentação.

- [ ] Adicionar `🔊 Ouvir apresentação do RouteBrain` próximo ao topo do README PT-BR.
- [ ] Adicionar link discreto no README em inglês informando que a narração é em português.
- [ ] Preservar badges e links existentes.

### Task 5: Validação e PR

**Files:**
- No new source files beyond tasks above.

- [ ] Validar links e referências locais.
- [ ] Executar `python scripts/offline_check.py`.
- [ ] Confirmar ausência de segredo/operational refs novos.
- [ ] Abrir PR de `feat/voice-presentation` para `main`.
- [ ] Esperar `Offline Tests (Python 3.13)`, `Docs & Public Export Guard`, `Analyze (python)` e `Dependency Review` ficarem verdes.
- [ ] Fazer merge somente com 100% dos required checks verdes.
- [ ] Ativar GitHub Pages administrativamente somente se ainda não estiver ativo e sem alterar os gates existentes.
- [ ] Validar a URL pública em Android/Chrome e desktop.
