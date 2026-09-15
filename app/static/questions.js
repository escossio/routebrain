const state = {
  current: null,
  speech: null,
  targetOverride: null,
  asnOverride: null,
  auth: { authenticated: false, username: null, role: null, permissions: [] },
};

const $ = (id) => document.getElementById(id);

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function escapeHtml(value, fallback = "-") {
  return text(value, fallback)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = payload && payload.detail ? payload.detail : response.statusText;
    throw new Error(detail);
  }
  return payload;
}

function isAdmin() {
  return state.auth && state.auth.role === "admin";
}

function isViewer() {
  return state.auth && state.auth.role === "viewer";
}

function authStatusElement() {
  return document.querySelector("[data-auth-status]") || $("auth-status") || $("authStatus") || $("authBadge");
}

function setAuthBadge(textValue, className) {
  const el = authStatusElement();
  if (!el) return;
  el.textContent = textValue;
  el.className = className;
}

function renderAuthBadge() {
  const el = authStatusElement();
  if (!el) return;
  if (!state.auth.authenticated) {
    el.className = "auth-badge auth-badge-error anonymous";
    el.textContent = "não autenticado";
    return;
  }
  const roleLabel = state.auth.role === "admin" ? "operador" : "somente leitura";
  el.className = `auth-badge auth-badge-${state.auth.role || "anonymous"} ${state.auth.role || "anonymous"}`;
  el.textContent = `Usuário: ${state.auth.username} · perfil: ${state.auth.role} · ${roleLabel}`;
}

async function loadAuthStatus() {
  try {
    const response = await fetch("/auth/me", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (response.status === 401) {
      state.auth = { authenticated: false, username: null, role: null, permissions: [] };
      setAuthBadge("Não autenticado", "auth-badge auth-badge-error anonymous");
      return state.auth;
    }
    if (!response.ok) {
      state.auth = { authenticated: false, username: null, role: null, permissions: [] };
      setAuthBadge("Falha ao verificar autenticação", "auth-badge auth-badge-warning anonymous");
      return state.auth;
    }
    const payload = await response.json();
    const role = payload.role || "desconhecido";
    const username = payload.username || payload.user || "usuário";
    const label = role === "admin" ? "operador" : role === "viewer" ? "somente leitura" : role;
    state.auth = { ...payload, authenticated: true, username, role };
    setAuthBadge(`Usuário: ${username} · perfil: ${role} · ${label}`, `auth-badge auth-badge-${role} ${role}`);
    return state.auth;
  } catch (error) {
    state.auth = { authenticated: false, username: null, role: null, permissions: [] };
    setAuthBadge("Falha ao verificar autenticação", "auth-badge auth-badge-error anonymous");
    return state.auth;
  }
}

const loadAuthContext = loadAuthStatus;

function renderHealth(payload) {
  const el = $("semanticHealth");
  const status = payload.status || "unknown";
  el.className = `health ${status}`;
  if (payload.search_mode || payload.provider) {
    el.innerHTML = `
      <strong>Semantic health: ${text(status)}</strong><br>
      modo: ${text(payload.search_mode)}<br>
      provider: ${text(payload.provider)}<br>
      tempo: ${text(payload.elapsed_seconds || payload.total_seconds, "0")}s
    `;
    return;
  }
  el.innerHTML = `
    <strong>API health: ${text(status)}</strong><br>
    serviço: ${text(payload.service)}
  `;
}

async function loadHealth() {
  try {
    renderHealth(await api("/semantic/health"));
  } catch (error) {
    $("semanticHealth").className = "health failed";
    $("semanticHealth").textContent = `Semantic health falhou: ${error.message}`;
  }
}

function renderSemantic(context) {
  const rows = [
    ["search_mode", context && context.search_mode],
    ["top object_type", context && context.top_object_type],
    ["top object_ref", context && context.top_object_ref],
    ["confidence", context && context.confidence],
    ["title", context && context.title],
  ];
  $("semanticContext").innerHTML = rows
    .map(([key, value]) => `<div><strong>${key}</strong>${text(value)}</div>`)
    .join("");
}

function renderList(id, rows, emptyText, renderer) {
  const el = $(id);
  if (!rows || rows.length === 0) {
    el.innerHTML = `<article>${emptyText}</article>`;
    return;
  }
  el.innerHTML = rows.map(renderer).join("");
}

function renderAgentObservability(payload) {
  const obs = payload && payload.agent_observability;
  const box = $("agentObservabilityBox");
  const badge = $("agentOriginBadge");
  const details = $("agentObservabilityDetails");
  if (!box || !badge || !details) return;
  if (!obs) {
    box.classList.add("hidden");
    badge.textContent = "";
    details.innerHTML = "";
    return;
  }

  const guardrails = Array.isArray(obs.guardrails_triggered) ? obs.guardrails_triggered : [];
  const safetyNotes = Array.isArray(obs.safety_notes) ? obs.safety_notes : [];
  const handoffs = Array.isArray(obs.handoffs) ? obs.handoffs : [];
  const tools = Array.isArray(obs.tools_called) ? obs.tools_called : [];
  const responseType = obs.response_type || "local_utility";
  const usedAgent = Boolean(obs.used_agent);
  let title = "Resposta local utilitária";
  if (usedAgent) title = "Resposta conversacional";
  else if (responseType === "local_operational") title = "Resposta operacional local do RouteBrain";
  else if (obs.evidence_source === "fallback") title = "Resposta conversacional local";
  badge.textContent = guardrails.length ? "Guardrail aplicado" : title;
  badge.className = guardrails.length ? "origin-badge guardrail" : "origin-badge";
  box.open = guardrails.length || usedAgent;
  box.classList.remove("hidden");

  const rows = [];
  rows.push(["Tipo", title]);
  if (usedAgent) {
    rows.push(["Provider/modelo", `${text(obs.provider)} / ${text(obs.model)}`]);
    rows.push(["Agente principal", obs.primary_agent || "-"]);
    rows.push(["Agente final", obs.final_agent || obs.primary_agent || "-"]);
  } else if (responseType === "local_operational") {
    rows.push(["Fonte", "backend RouteBrain/evidências"]);
  } else {
    rows.push(["Fonte", obs.evidence_source || "local_utility"]);
  }
  rows.push(["Ação ativa executada", obs.active_action_executed ? "sim" : "não"]);
  if (handoffs.length) rows.push(["Handoff", handoffs.join(" → ")]);
  if (tools.length) rows.push(["Tools read-only", tools.join(", ")]);
  if (guardrails.length) rows.push(["Guardrails", guardrails.join(", ")]);
  if (safetyNotes.length) rows.push(["Safety notes", safetyNotes.join(" · ")]);
  if (usedAgent) rows.push(["Política", "Nenhuma ação ativa foi executada por esta camada."]);

  details.innerHTML = rows.map(([key, value]) => `
    <div>
      <strong>${escapeHtml(key)}</strong>
      <span>${escapeHtml(value)}</span>
    </div>
  `).join("");
}

function actionTypeLabel(value) {
  const labels = {
    read_only: "leitura",
    active_measurement: "medição ativa",
    state_change: "alteração de estado",
    synthetic_navigation: "navegação sintética",
    report: "relatório",
  };
  return labels[value] || text(value);
}

function renderActionPlan(payload) {
  const plan = payload && payload.action_plan;
  const box = $("actionPlanBox");
  const summary = $("actionPlanSummary");
  const status = $("actionPlanStatus");
  const stepsEl = $("actionPlanSteps");
  if (!box || !summary || !status || !stepsEl) return;
  if (!plan || !Array.isArray(plan.steps) || !plan.steps.length) {
    box.classList.add("hidden");
    summary.textContent = "";
    stepsEl.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  summary.textContent = plan.summary || plan.title || "Plano sugerido pelo RouteBrain.";
  status.textContent = text(plan.status, "planned");
  const recommended = new Set((payload.recommended_actions || []).map((item) => item.id || item.action).filter(Boolean));
  stepsEl.innerHTML = plan.steps.map((step, index) => {
    const actionId = step.action_id || "";
    const hasExistingAction = actionId && recommended.has(actionId);
    const hasEndpoint = Boolean(step.endpoint);
    const blockedForViewer = isViewer() && step.requires_admin;
    const canClick = Boolean(step.executable && !blockedForViewer && (hasEndpoint || (payload.request_uid && hasExistingAction)));
    const buttonText = blockedForViewer
      ? "Requer operador/admin"
      : !step.executable
        ? (step.reason || "Planejado")
        : hasEndpoint
          ? (step.requires_confirmation ? "Mapear rota" : "Executar backend")
          : hasExistingAction
            ? (step.requires_confirmation ? "Usar fluxo com confirmação" : "Abrir ação")
            : "Planejado";
    return `
      <article class="plan-step">
        <div class="plan-step-index">${index + 1}</div>
        <div class="plan-step-body">
          <h4>${escapeHtml(step.label)}</h4>
          <p>${escapeHtml(step.description)}</p>
          <div class="plan-meta">
            <span>${escapeHtml(actionTypeLabel(step.action_type))}</span>
            <span>risco: ${escapeHtml(step.risk || "none")}</span>
            <span>admin: ${step.requires_admin ? "sim" : "não"}</span>
            <span>confirmação: ${step.requires_confirmation ? "sim" : "não"}</span>
            <span>status: ${escapeHtml(step.status || "planned")}</span>
          </div>
          ${(actionId || hasEndpoint)
            ? `<button type="button" class="${step.requires_confirmation ? "danger" : "secondary"}" data-plan-action="${escapeHtml(actionId || step.id)}" data-plan-endpoint="${escapeHtml(step.endpoint || "")}" data-plan-method="${escapeHtml(step.method || "")}" data-plan-params="${escapeHtml(JSON.stringify(step.params || {}))}" ${canClick ? "" : "disabled"}>${escapeHtml(buttonText)}</button>`
            : `<small>${escapeHtml(buttonText)}</small>`}
        </div>
      </article>
    `;
  }).join("");
  stepsEl.querySelectorAll("button[data-plan-action]").forEach((button) => {
    button.addEventListener("click", () => runAction(button.dataset.planAction, button));
  });
}

function renderResult(payload) {
  state.current = payload;
  state.speech = null;
  state.targetOverride = (payload.target_context && (payload.target_context.target_domain || payload.target_context.target_ip || payload.target_context.target_prefix)) || null;
  state.asnOverride = (payload.asn_monitoring && payload.asn_monitoring.asn) || (payload.target_context && payload.target_context.asn) || null;
  $("resultPanel").classList.remove("hidden");
  if (payload.status === "error") {
    $("resultStatus").textContent = text(payload.error_code, "error");
    $("resultIntent").textContent = "error";
    $("resultConsent").textContent = "-";
    $("elapsed").textContent = "-";
    $("resultQuestion").textContent = text(payload.message, "Erro");
    $("answerText").textContent = payload.details ? `${text(payload.message)}: ${text(payload.details)}` : text(payload.message);
    renderAgentObservability({});
    $("semanticContext").innerHTML = "";
    $("gapsList").innerHTML = "";
    $("evidenceList").innerHTML = "";
    $("activePanel").classList.add("hidden");
    $("recommendedActions").innerHTML = "";
    renderActionPlan({});
    $("targetHint").textContent = "";
    $("ipOperationalBox").classList.add("hidden");
    $("ipOperationalBox").innerHTML = "";
    $("bgpVisibilityBox").classList.add("hidden");
    $("bgpVisibilityBox").innerHTML = "";
    $("asnMonitoringBox").classList.add("hidden");
    $("asnMonitoringBox").innerHTML = "";
    $("actionMessage").textContent = "";
  $("traceButton").classList.add("hidden");
  $("traceState").textContent = "";
  $("traceGraph").classList.add("hidden");
  $("traceDetails").classList.add("hidden");
  $("rttChart").classList.add("hidden");
  $("speechStatus").textContent = "";
  $("speechPlayer").innerHTML = "";
  $("speechPlayer").classList.add("hidden");
  $("speechButton").disabled = true;
  $("asnMonitoringBox").classList.add("hidden");
  $("asnMonitoringBox").innerHTML = "";
  return;
}
  $("resultStatus").textContent = text(payload.status);
  $("resultIntent").textContent = text(payload.intent);
  $("resultConsent").textContent = text(payload.consent_status);
  $("elapsed").textContent = `${text(payload.elapsed_seconds, "0")}s`;
  $("resultQuestion").textContent = text(payload.question);
  $("answerText").textContent = text(payload.operational_answer || payload.answer, "Sem resposta compacta ainda.");
  renderAgentObservability(payload);
  const isConversational = Boolean(payload.llm_assistant) || ["general_greeting", "help_prompt", "general_test", "conversational_help"].includes(payload.intent);
  if (isConversational && payload.llm_assistant && payload.llm_assistant.used_llm) {
    $("resultIntent").textContent = `${text(payload.intent)} · resposta conversacional`;
  }
  renderTargetHint(payload.target_context || {});
  renderIpOperational(payload.ip_operational || {});
  if (payload.bgp_visibility && payload.bgp_visibility.asn) {
    renderBgpVisibility(payload.bgp_visibility || {});
  } else {
    $("bgpVisibilityBox").classList.add("hidden");
    $("bgpVisibilityBox").innerHTML = "";
  }
  renderAsnMonitoring(payload.asn_monitoring || {});
  renderRouteProfile(payload);
  renderActionPlan(payload);
  renderRecommendedActions(payload.recommended_actions || [], payload.target_context || {});
  const semanticGrid = $("semanticContext") && $("semanticContext").closest(".grid");
  const evidenceSection = $("evidenceList") && $("evidenceList").closest("section");
  if (isConversational) {
    if (semanticGrid) semanticGrid.classList.add("hidden");
    if (evidenceSection) evidenceSection.classList.add("hidden");
    $("targetHint").textContent = "Exemplos para testar";
    renderActiveMeasurements(payload.active_measurements || {});
    renderTraceSummary(payload.traceroute || {});
    $("speechStatus").textContent = "";
    $("speechPlayer").innerHTML = "";
    $("speechPlayer").classList.add("hidden");
    $("speechButton").disabled = true;
    return;
  }
  if (semanticGrid) semanticGrid.classList.remove("hidden");
  if (evidenceSection) evidenceSection.classList.remove("hidden");
  renderSemantic(payload.semantic_context || {});
  renderList("gapsList", payload.gaps, "Sem lacunas abertas.", (gap) => `
    <article>
      <strong>${text(gap.type)}</strong>
      ${text(gap.status)} · ${text(gap.reason)}
    </article>
  `);
  renderList("evidenceList", payload.evidence_summary, "Sem evidência resumida.", (item) => `
    <article>
      <strong>${text(item.type)}</strong>
      ${text(item.summary)}<br>
      <small>${text(item.source)} · ${text(item.confidence)}</small>
    </article>
  `);
  renderActiveMeasurements(payload.active_measurements || {});
  renderTraceSummary(payload.traceroute || {});
  $("speechStatus").textContent = "";
  $("speechPlayer").innerHTML = "";
  $("speechPlayer").classList.add("hidden");
  $("speechButton").disabled = false;
}

function renderTargetHint(target) {
  const hint = $("targetHint");
  if (!target) {
    hint.textContent = "";
    return;
  }
  if (target.target_domain) {
    hint.textContent = target.needs_target_confirmation
      ? `Destino sugerido: ${target.target_domain}. Confirme antes de medir.`
      : `Destino identificado: ${target.target_domain}.`;
    return;
  }
  if (target.target_ip) {
    hint.textContent = `Destino IP identificado: ${target.target_ip}.`;
    return;
  }
  if (target.target_prefix) {
    hint.textContent = `Prefixo identificado: ${target.target_prefix}.`;
    return;
  }
  if (target.target_label) {
    hint.textContent = `Interpretação provisória: ${target.target_label}.`;
  } else {
    hint.textContent = "Não identifiquei um destino técnico específico.";
  }
}

function renderIpOperational(op) {
  const box = $("ipOperationalBox");
  if (!op || !op.target_ip) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  const bgpRoute = op.bgp_route || {};
  const observed = op.observed_destination || {};
  const baseline = op.baseline || {};
  const latest = op.latest_measurement || {};
  box.innerHTML = `
    <strong>Análise operacional do IP</strong><br>
    IP: ${text(op.target_ip)}<br>
    IP público: ${op.is_public ? "sim" : "não"}<br>
    ASN: ${text(op.asn)}<br>
    Organização: ${text(op.organization)}<br>
    Fonte ASN: ${text(op.asn_source)}<br>
    BGP confirmado: ${op.bgp_confirmed ? "sim" : "não"}<br>
    Rota BGP local: ${bgpRoute.found ? "encontrada" : "não encontrada"}<br>
    ${bgpRoute.prefix ? `Prefixo BGP: ${text(bgpRoute.prefix)}<br>` : ""}
    Observado na MikroTik: ${observed.found ? "sim" : "não"}<br>
    ${observed.found ? `Observações: ${text(observed.observation_count, "0")}<br>` : ""}
    Baseline: ${baseline.exists ? "sim" : "não"}<br>
    ${baseline.exists ? `Baseline UID: ${text(baseline.baseline_uid)} · status: ${text(baseline.status)}<br>` : ""}
    Última medição: ${latest.exists ? "sim" : "não"}<br>
    ${latest.exists ? `Ping: ${text(latest.ping_summary && latest.ping_summary.status)} · Traceroute: ${text(latest.traceroute_summary && latest.traceroute_summary.status)}<br>` : ""}
    ${latest.graph_available ? `Graph: <a href="${text(latest.graph_url)}" target="_blank" rel="noopener">ver caminho da rota</a><br>` : ""}
    ${op.gaps && op.gaps.length ? `Lacunas: ${op.gaps.join(", ")}` : ""}
  `;
}

function renderAsnMonitoring(monitoring) {
  const box = $("asnMonitoringBox");
  const current = state.current || {};
  const routeChange = current.asn_route_change || {};
  if (!monitoring || !monitoring.asn) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  const target = monitoring.target || {};
  const currentState = monitoring.current || {};
  const summary = currentState.summary || {};
  const topAddedPrefixes = (routeChange.top_changes && routeChange.top_changes.added_prefixes) || [];
  const topRemovedPrefixes = (routeChange.top_changes && routeChange.top_changes.removed_prefixes) || [];
  const topPeerChanges = (routeChange.top_changes && routeChange.top_changes.peer_route_count_changes) || [];
  box.innerHTML = `
    <strong>Monitoramento ASN</strong><br>
    ASN: ${text(monitoring.asn)}<br>
    status: ${text(target.status || "not_monitored")} · baseline: ${text(target.baseline_status || monitoring.baseline_status || "pending")}<br>
    rotas atuais: ${text(summary.total_current_routes, "0")} · prefixos: ${text(summary.total_prefixes, "0")} · peers: ${text(summary.total_peers, "0")}<br>
    ${monitoring.baseline_exists ? "Existe baseline para comparação." : "Ainda não há baseline histórico suficiente."}
    ${routeChange && routeChange.change_detected !== undefined ? `<br>mudança detectada: ${routeChange.change_detected ? "sim" : "não"} · confiança: ${text(routeChange.confidence, "indefinida")}<br>Δ rotas: ${text(routeChange.summary && routeChange.summary.route_count_delta, "0")} · Δ prefixos: ${text(routeChange.summary && routeChange.summary.prefix_count_delta, "0")} · Δ peers: ${text(routeChange.summary && routeChange.summary.peer_count_delta, "0")}` : ""}
    ${topAddedPrefixes.length ? `<br>prefixos adicionados: ${topAddedPrefixes.slice(0, 5).join(", ")}` : ""}
    ${topRemovedPrefixes.length ? `<br>prefixos removidos: ${topRemovedPrefixes.slice(0, 5).join(", ")}` : ""}
    ${topPeerChanges.length ? `<br>peers com maior mudança: ${topPeerChanges.slice(0, 5).map((item) => `${text(item.peer_ip)} (${text(item.route_count_delta)})`).join(", ")}` : ""}
  `;
}

function renderRouteProfile(payload) {
  const box = $("routeProfileBox");
  const summary = payload && payload.route_profile_summary;
  if (!box) return;
  if (!summary || !summary.profile_uid) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }

  const routeSummary = summary.route_summary || {};
  const learnedFrom = summary.learned_from || {};
  const asn = summary.asn_attribution_status || {};
  const reuse = summary.reuse_policy || {};
  const temporal = summary.temporal_comparison || {};
  const baseline = temporal.baseline_availability || {};
  const sourceEndpoints = Array.isArray(summary.source_endpoints) ? summary.source_endpoints : [];
  const limitations = Array.isArray(summary.limitations) ? summary.limitations : [];
  const remaining = Array.isArray(summary.remaining_ignorance) ? summary.remaining_ignorance : [];

  box.classList.remove("hidden");
  box.innerHTML = `
    <strong>Perfil de rota</strong><br>
    status: ${text(summary.status)}<br>
    profile_uid: ${text(summary.profile_uid)}<br>
    aprendido de: ${text(learnedFrom.dedicated_run_uid)} · ${text(learnedFrom.execution_type)}<br>
    hops/edges: ${text(routeSummary.hop_count, "0")} / ${text(routeSummary.edge_count, "0")}<br>
    ping/traceroute: ${text(routeSummary.ping_status)} / ${text(routeSummary.traceroute_status)}<br>
    confiança: ${text(summary.confidence)}<br>
    tronco comum com Google: ${text(routeSummary.common_trunk_with_google)} · branch_point: ${text(routeSummary.branch_point)}<br>
    final_destination_asserted: ${routeSummary.final_destination_asserted === true ? "sim" : "não"}<br>
    baseline temporal: ${text(temporal.status)} · ${text(baseline.status)}<br>
    ${temporal.endpoint ? `endpoint temporal: <code>${escapeHtml(temporal.endpoint)}</code><br>` : ""}
    ${temporal.operator_message ? `${escapeHtml(temporal.operator_message)}<br>` : ""}
    ASN atual: ${text(asn.attribution_engine_status)} · privados: ${text(asn.private_ip_hops, "0")} · sem ASN: ${text(asn.hops_without_asn, "0")}<br>
    ${limitations.length ? `limitações: ${limitations.map((item) => text(item)).join(", ")}<br>` : ""}
    ${remaining.length ? `ignorância restante: ${remaining.map((item) => text(item && item.type ? item.type : item)).join(", ")}<br>` : ""}
    ${reuse.stale_after_hours ? `stale_after_hours: ${text(reuse.stale_after_hours)}<br>` : ""}
    ${sourceEndpoints.length ? `endpoints: ${sourceEndpoints.map((item) => `<code>${escapeHtml(item)}</code>`).join(" ")}` : ""}
    ${payload.active_action_executed === false ? "<br>ação ativa executada: não" : ""}
  `;
}

function renderBgpVisibility(visibility) {
  const box = $("bgpVisibilityBox");
  if (!visibility || !visibility.asn) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  const asnIsOrigin = visibility.asn_is_origin;
  const seenInPath = visibility.asn_seen_in_as_path;
  box.innerHTML = `
    <strong>Visão BGP ASN/IP</strong><br>
    ASN consultado: ${text(visibility.asn)}<br>
    ${visibility.ip ? `IP consultado: ${text(visibility.ip)}<br>` : ""}
    ${visibility.prefix ? `Prefixo consultado: ${text(visibility.prefix)}<br>` : ""}
    prefixo encontrado: ${text(visibility.matched_prefix, "não encontrado")}<br>
    origin_asn: ${text(visibility.origin_asn, "desconhecido")}<br>
    route_count: ${text(visibility.route_count, "0")} · peer_count: ${text(visibility.peer_count, "0")}<br>
    asn_is_origin: ${asnIsOrigin === true ? "sim" : asnIsOrigin === false ? "não" : "desconhecido"}<br>
    asn_seen_in_as_path: ${seenInPath === true ? "sim" : seenInPath === false ? "não" : "desconhecido"}<br>
    direct_view_available: ${visibility.direct_view_available ? "sim" : "não"}<br>
    ${visibility.sample_as_paths && visibility.sample_as_paths.length ? `exemplos de AS path: ${visibility.sample_as_paths.slice(0, 3).join(" | ")}<br>` : ""}
    ${visibility.limitations && visibility.limitations.length ? `limitações: ${visibility.limitations.join(", ")}` : ""}
  `;
}

function actionButtonLabel(action) {
  const label = action.label || action.action || action.id || "ação";
  if (!action.enabled) {
    return action.needs_executor
      ? `${label} - executor sintético não conectado`
      : `${label} - disponível, exige confirmação`;
  }
  return action.requires_confirmation ? `${label} - disponível, exige confirmação` : label;
}

function renderRecommendedActions(actions, target) {
  const el = $("recommendedActions");
  if (!actions || !actions.length) {
    el.innerHTML = "<article class='action-card'><p>Nenhuma ação recomendada no momento.</p></article>";
    return;
  }
  el.innerHTML = actions.map((action) => {
    const actionId = action.id || action.action || "";
    const label = action.label || actionId || "ação";
    if (action.example_question) {
      return `
      <article class="action-card example-card">
        <h4>${text(label)}</h4>
        <p>${text(action.description)}</p>
        <div class="meta">risco: ${text(action.risk)}</div>
        <button type="button" class="secondary" data-example-question="${text(action.example_question, "")}">
          Usar exemplo
        </button>
        <small>${text(action.example_question)}</small>
      </article>
    `;
    }
    const needsOverride = actionId === "resolve_dns" && (target.needs_target_confirmation || (!target.target_domain && !target.target_ip));
    const targetValue = target.target_domain || target.target_ip || target.target_prefix || state.targetOverride || "";
    const asnValue = (state.current && state.current.asn_monitoring && state.current.asn_monitoring.asn) || target.asn || "";
    const disabled = isViewer() && (action.requires_confirmation || !action.enabled);
    const statusLabel = !action.enabled
      ? (action.needs_executor ? "Executor sintético não conectado" : "Disponível — exige confirmação")
      : action.requires_confirmation ? "Disponível — exige confirmação" : "Disponível";
    return `
      <article class="action-card">
        <h4>${text(label)}</h4>
        <p>${text(action.description)}</p>
        <div class="meta">risco: ${text(action.risk)} · ${statusLabel}</div>
        ${needsOverride ? `<input data-action-target="${actionId}" placeholder="Destino sugerido: facebook.com" value="${text(targetValue, "")}" />` : ""}
        ${actionId.startsWith("asn_") || actionId.includes("asn") ? `<input data-action-asn="${actionId}" type="number" min="0" placeholder="ASN" value="${text(asnValue, "")}" />` : ""}
        <button type="button" class="${action.requires_confirmation ? "danger" : "secondary"}" data-action="${actionId}" ${disabled ? "disabled" : ""}>
          ${needsOverride ? `Usar ${text(targetValue || "facebook.com")}` : actionButtonLabel(action)}
        </button>
      </article>
    `;
  }).join("");
  el.querySelectorAll("button[data-example-question]").forEach((button) => {
    button.addEventListener("click", () => {
      $("questionInput").value = button.dataset.exampleQuestion || "";
      $("questionInput").focus();
    });
  });
  el.querySelectorAll("button[data-action]").forEach((button) => {
    button.addEventListener("click", () => runAction(button.dataset.action));
  });
}

function renderActiveMeasurements(active) {
  const panel = $("activePanel");
  const message = $("activeMessage");
  $("activeConfirm").checked = false;
  if (!active.required) {
    panel.classList.remove("hidden");
    panel.classList.add("hidden");
    $("activeStatus").textContent = "";
    $("activeTasks").innerHTML = "";
    $("approveActiveButton").disabled = true;
    $("executeActiveButton").disabled = true;
    message.textContent = "";
    return;
  }
  panel.classList.remove("hidden");
  $("activeStatus").textContent = `consentimento: ${text(active.consent_status)} · runtime estimado: ${text(active.estimated_runtime_seconds, "0")}s`;
  if (isViewer()) {
    $("approveActiveButton").disabled = true;
    $("executeActiveButton").disabled = true;
    message.textContent = "Requer perfil operador/admin.";
  }
  if (active.consent_status === "approved") {
    $("approveActiveButton").disabled = true;
    $("approveActiveButton").textContent = "Medição aprovada";
    message.textContent = active.approval_note || "Aprovado. Marque a confirmação e clique em Executar medição ativa.";
  } else {
    $("approveActiveButton").textContent = "Aprovar medição ativa";
  }
  if (isAdmin()) {
    $("approveActiveButton").disabled = !active.can_approve;
    $("executeActiveButton").disabled = !active.can_execute || !$("activeConfirm").checked;
    if (!message.textContent) {
      message.textContent = "Disponível — exige confirmação.";
    }
  }
  renderList("activeTasks", active.tasks, "Nenhuma tarefa ativa.", (task) => `
    <article>
      <strong>${text(task.type)}</strong>
      alvo: ${text(task.target)}<br>
      status: ${text(task.status)} · permitido: ${task.allowed ? "sim" : "não"}<br>
      ${task.reason_if_blocked ? `<small>bloqueio: ${task.reason_if_blocked === "missing_dns_resolution_for_active_targets" ? "Ainda não há IP público resolvido para medir. Ao executar, o RouteBrain tentará resolver DNS primeiro." : task.reason_if_blocked === "no_allowed_targets" ? "Ainda não há IP público resolvido para medir. Ao executar, o RouteBrain tentará resolver DNS primeiro." : text(task.reason_if_blocked)}</small>` : ""}
    </article>
  `);
  if (active.consent_status !== "approved") {
    $("approveActiveButton").disabled = !active.can_approve;
  }
  $("executeActiveButton").disabled = !active.can_execute || !$("activeConfirm").checked;
  $("executeActiveButton").textContent = active.consent_status === "approved" && $("activeConfirm").checked
    ? "Executar medição ativa"
    : "Executar medição ativa";
  if (active.consent_status !== "approved") {
    message.textContent = text(active.approval_note, "");
  } else if (active.next_safe_step === "dns_resolution" && !active.can_execute) {
    message.textContent = active.approval_note || "Aprovado. Ao executar, o RouteBrain vai tentar resolver DNS primeiro.";
  }
}

function renderTraceSummary(trace) {
  $("traceGraph").classList.add("hidden");
  $("traceDetails").classList.add("hidden");
  $("rttChart").classList.add("hidden");
  if (trace.available) {
    $("traceState").textContent = `${text(trace.target || trace.target_ip)} · ${text((trace.summary || {}).total_hops, "0")} hops`;
    $("traceButton").classList.remove("hidden");
    $("traceButton").dataset.url = trace.graph_url || `/questions/${state.current.request_uid}/traceroute-graph`;
  } else {
    $("traceButton").classList.add("hidden");
    const reason = trace.reason || "no_traceroute_evidence";
    $("traceState").textContent = reason === "no_traceroute_evidence"
      ? "sem traceroute disponível; medição ativa exige consentimento"
      : reason;
  }
}

function renderTraceGraph(graph) {
  const graphEl = $("traceGraph");
  const edgeByTarget = new Map((graph.edges || []).map((edge) => [edge.target, edge]));
  graphEl.innerHTML = (graph.nodes || []).map((node, index) => {
    const edge = edgeByTarget.get(node.id);
    const arrow = index === 0 ? "" : `<div class="hop-edge ${edge && edge.latency_jump ? "jump" : ""}">→</div>`;
    return `
      ${arrow}
      <button class="hop-node ${text(node.role, "unknown")}" data-hop="${node.hop}" type="button">
        <div class="hop">hop ${text(node.hop)}</div>
        <div class="ip">${text(node.ip, "*")}</div>
        <div class="rtt">${node.rtt_ms === null || node.rtt_ms === undefined ? "sem RTT" : `${node.rtt_ms} ms`}</div>
      </button>
    `;
  }).join("");
  graphEl.classList.remove("hidden");
  graphEl.querySelectorAll(".hop-node").forEach((button) => {
    button.addEventListener("click", () => {
      const hop = Number(button.dataset.hop);
      const node = (graph.nodes || []).find((item) => Number(item.hop) === hop);
      $("traceDetails").innerHTML = `
        <strong>hop ${text(node.hop)}</strong><br>
        ip: ${text(node.ip, "*")}<br>
        hostname: ${text(node.hostname)}<br>
        role: ${text(node.role)}<br>
        confidence: ${text(node.confidence)}<br>
        source: ${text(node.evidence_source)}
      `;
      $("traceDetails").classList.remove("hidden");
    });
  });
  renderRttChart(graph.rtt_series || []);
}

function renderRttChart(series) {
  const values = series.filter((item) => item.rtt_ms !== null && item.rtt_ms !== undefined);
  const width = Math.max(520, series.length * 42);
  const height = 190;
  const max = Math.max(10, ...values.map((item) => Number(item.rtt_ms)));
  const bars = series.map((item, index) => {
    const x = 28 + index * 42;
    const barHeight = item.rtt_ms === null || item.rtt_ms === undefined ? 0 : Math.max(2, (Number(item.rtt_ms) / max) * 120);
    const y = 145 - barHeight;
    return `
      <rect x="${x}" y="${y}" width="24" height="${barHeight}" fill="#2364aa"></rect>
      <text x="${x + 12}" y="165" text-anchor="middle" font-size="11">${text(item.hop)}</text>
    `;
  }).join("");
  $("rttChart").innerHTML = `
    <svg width="${width}" height="${height}" role="img" aria-label="RTT por hop">
      <line x1="20" y1="145" x2="${width - 10}" y2="145" stroke="#d9e0e8"></line>
      ${bars}
      <text x="20" y="18" font-size="12" fill="#627084">RTT por hop, max ${max.toFixed(1)} ms</text>
    </svg>
  `;
  $("rttChart").classList.remove("hidden");
}

async function askQuestion() {
  const question = $("questionInput").value.trim();
  if (!question) return;
  $("askButton").disabled = true;
  $("askButton").textContent = "Perguntando...";
  try {
    const payload = await api("/questions/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, compact: true }),
    });
    renderResult(payload);
    await loadRecent();
  } catch (error) {
    $("answerText").textContent = error.message;
    $("resultPanel").classList.remove("hidden");
  } finally {
    $("askButton").disabled = false;
    $("askButton").textContent = "Perguntar";
  }
}

async function approveActive() {
  if (!state.current || !state.current.request_uid) return;
  $("approveActiveButton").disabled = true;
  $("activeMessage").textContent = "Aprovando medição ativa...";
  try {
    renderResult(await api(`/questions/${state.current.request_uid}/approve-active`, { method: "POST" }));
    await loadRecent();
  } catch (error) {
    $("activeMessage").textContent = `Erro: ${error.message}`;
  }
}

async function executeActive() {
  if (!state.current || !state.current.request_uid) return;
  if (!$("activeConfirm").checked) {
    $("activeMessage").textContent = "Marque a confirmação antes de executar ping/traceroute.";
    return;
  }
  $("executeActiveButton").disabled = true;
  $("activeMessage").textContent = "Resolvendo DNS e executando medições...";
  try {
    renderResult(await api(`/questions/${state.current.request_uid}/execute-active`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    }));
    await loadRecent();
  } catch (error) {
    $("activeMessage").textContent = `Erro: ${error.message}`;
    $("executeActiveButton").disabled = !((state.current && state.current.active_measurements && state.current.active_measurements.can_execute) && $("activeConfirm").checked);
  }
}

function getActionTarget(actionId) {
  const input = document.querySelector(`[data-action-target="${actionId}"]`);
  if (input && input.value.trim()) return input.value.trim();
  return state.targetOverride || null;
}

function getActionAsn(actionId) {
  const input = document.querySelector(`[data-action-asn="${actionId}"]`);
  if (input && input.value.trim()) return Number(input.value.trim());
  return state.asnOverride || null;
}

async function runAction(actionId, buttonEl = null) {
  const planSteps = (state.current && state.current.action_plan && Array.isArray(state.current.action_plan.steps)) ? state.current.action_plan.steps : [];
  const action = planSteps.find((item) => (item.action_id || item.id) === actionId) || (state.current && state.current.recommended_actions || []).find((item) => (item.id || item.action) === actionId);
  if (!action) return;
  const actionEnabled = action.executable !== false && action.enabled !== false;
  if (isViewer() && (action.requires_confirmation || !actionEnabled || action.requires_admin)) {
    $("actionMessage").textContent = "Requer perfil operador/admin.";
    return;
  }
  const targetOverride = getActionTarget(actionId);
  const asn = getActionAsn(actionId);
  const endpoint = action.endpoint || (state.current && state.current.request_uid ? `/questions/${state.current.request_uid}/actions/${actionId}` : null);
  if (!endpoint) {
    $("actionMessage").textContent = "Ação sem endpoint disponível.";
    return;
  }
  let params = {};
  try {
    params = action.params && typeof action.params === "object" ? { ...action.params } : {};
  } catch (error) {
    params = {};
  }
  if (buttonEl && buttonEl.dataset.planParams) {
    try {
      params = { ...params, ...JSON.parse(buttonEl.dataset.planParams) };
    } catch (error) {
      // ignore malformed plan params in the DOM
    }
  }
  if (!action.endpoint && targetOverride && !params.target_override) {
    params.target_override = targetOverride;
  }
  if (!action.endpoint && asn && !params.asn) {
    params.asn = asn;
  }
  if (action.endpoint) {
    params.confirm = true;
  }
  if (action.requires_confirmation) {
    if (!window.confirm("Esta ação executa ping/traceroute a partir do RouteBrain. Confirmo executar medição ativa para os alvos permitidos.")) {
      return;
    }
  }
  $("actionMessage").textContent = action.requires_confirmation ? "Executando ação ativa..." : "Executando ação...";
  try {
    const payload = await api(endpoint, {
      method: action.method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        action.endpoint
          ? {
              confirm: true,
              target_override: params.target_override ?? null,
              max_hops: params.max_hops ?? 20,
            }
          : {
              confirm: !!action.requires_confirmation,
              target_override: targetOverride || undefined,
              asn: asn || undefined,
              label: state.current && state.current.target_context ? state.current.target_context.target_label : undefined,
            },
      ),
    });
    renderResult(payload);
    await loadRecent();
    $("actionMessage").textContent = `Ação ${actionId} concluída.`;
  } catch (error) {
    $("actionMessage").textContent = `Erro: ${error.message}`;
  }
}

async function generateSpeech() {
  if (!state.current || !state.current.request_uid) return;
  $("speechButton").disabled = true;
  $("speechStatus").textContent = "Gerando áudio...";
  $("speechPlayer").innerHTML = "";
  $("speechPlayer").classList.add("hidden");
  try {
    const payload = await api(`/questions/${state.current.request_uid}/speech`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text_mode: "answer" }),
    });
    state.speech = payload;
    if (payload.status === "disabled") {
      $("speechStatus").textContent = payload.message || "TTS desabilitado.";
      return;
    }
    if (payload.status !== "ok" || !payload.audio_url) {
      $("speechStatus").textContent = payload.message || "Não foi possível gerar o áudio.";
      return;
    }
    const note = payload.provider ? `Provider: ${payload.provider}` : "Áudio pronto.";
    $("speechStatus").textContent = payload.message ? `${payload.message} ${note}` : note;
    $("speechPlayer").innerHTML = `
      <audio controls preload="metadata" src="${payload.audio_url}"></audio>
      <p><a href="${payload.audio_url}" target="_blank" rel="noreferrer">abrir áudio</a></p>
    `;
    $("speechPlayer").classList.remove("hidden");
  } catch (error) {
    $("speechStatus").textContent = `Erro ao gerar áudio: ${error.message}`;
  } finally {
    $("speechButton").disabled = !state.current || !state.current.request_uid;
  }
}

async function loadRecent() {
  const rows = await api("/questions/recent?limit=10");
  $("recentList").innerHTML = rows.map((row) => `
    <button class="recent-card" type="button" data-uid="${row.request_uid}">
      <p>${text(row.question)}</p>
      <small>${text(row.intent)} · gaps ${text(row.gaps_count, "0")} · trace ${row.traceroute_available ? "sim" : "não"}</small>
    </button>
  `).join("");
  $("recentList").querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", async () => renderResult(await api(`/questions/${button.dataset.uid}`)));
  });
}

$("askButton").addEventListener("click", askQuestion);
$("questionInput").addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") askQuestion();
});
$("traceButton").addEventListener("click", async () => {
  const graph = await api($("traceButton").dataset.url);
  if (!graph.available) {
    $("traceState").textContent = graph.reason || "sem traceroute disponível";
    return;
  }
  renderTraceGraph(graph);
});
$("approveActiveButton").addEventListener("click", approveActive);
$("executeActiveButton").addEventListener("click", executeActive);
$("speechButton").addEventListener("click", generateSpeech);
$("activeConfirm").addEventListener("change", () => {
  const active = (state.current && state.current.active_measurements) || {};
  $("executeActiveButton").disabled = !active.can_execute || !$("activeConfirm").checked;
  if (active.consent_status === "approved" && $("activeConfirm").checked) {
    $("activeMessage").textContent = active.approval_note || "Aprovado. Marque a confirmação e clique em Executar medição ativa.";
  }
});

renderAuthBadge();
const authReady = loadAuthStatus();
authReady.finally(() => {
  loadHealth();
  loadRecent();
});
