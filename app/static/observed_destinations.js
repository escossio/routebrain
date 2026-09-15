const state = {
  summary: null,
  top: [],
  asns: [],
  categories: [],
  filteredTop: [],
  baselines: [],
  trendsSummary: null,
  trends: [],
  trendsAsns: [],
  trendsCategories: [],
  detailTrend: null,
  detailIp: null,
  detailReport: null,
  detailBaseline: null,
  detailMeasurement: null,
  detailGraph: null,
  auth: { authenticated: false, username: null, role: null, permissions: [] },
};

const $ = (id) => document.getElementById(id);

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
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

function isViewer() {
  return state.auth && state.auth.role === "viewer";
}

function isAdmin() {
  return state.auth && state.auth.role === "admin";
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

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2600);
}

function applyAuthControls() {
  const disabled = isViewer();
  [
    ["collectButton", "Coleta requer operador/admin."],
    ["enrichButton", "Enrichment requer operador/admin."],
    ["promoteButton", "Promoção requer operador/admin."],
    ["measureButton", "Medição requer operador/admin."],
  ].forEach(([id, title]) => {
    const button = $(id);
    if (!button) return;
    if (disabled) {
      button.disabled = true;
      button.title = title;
    } else {
      button.disabled = false;
      button.title = "";
    }
  });
}

function badgeClassForCategory(category) {
  return `badge ${String(category || "unknown").toLowerCase()}`;
}

function summarizeTopItems(items, key = "destination_ip", limit = 3) {
  return (items || [])
    .slice(0, limit)
    .map((item) => item[key] || item.asn || item.category)
    .filter(Boolean)
    .join(", ");
}

function renderSummary(summary) {
  const cards = [
    ["Total de destinos", summary.total_destinations, `${summary.total_observations || 0} observações`],
    ["Total de ASNs", summary.total_asns, `bgp ${summary.asn_source_counts?.bgp || 0} · externo ${summary.asn_source_counts?.external || 0}`],
    ["Categorias", summary.total_categories, "cdn / cloud / social / unknown"],
    ["Última coleta", summary.last_collect_run?.started_at || summary.last_seen, summary.last_collect_run?.run_uid ? `run ${summary.last_collect_run.run_uid}` : "sem coleta recente"],
    ["Pendentes", summary.enrichment_status_counts?.pending || 0, `enriquecidos ${summary.enrichment_status_counts?.enriched || 0}`],
    ["Sem ASN", summary.asn_source_counts?.none || 0, `bgp confirmado ${summary.asn_source_counts?.bgp || 0}`],
  ];
  $("summaryCards").innerHTML = cards
    .map(
      ([label, value, meta]) => `
        <article class="summary-card">
          <div class="label">${text(label)}</div>
          <div class="value">${text(value, "0")}</div>
          <div class="meta">${text(meta)}</div>
        </article>
      `,
    )
    .join("");
}

function renderBaselines() {
  const items = state.baselines || [];
  const summary = $("baselineSummary");
  if (!summary) return;
  $("baselineStatus").textContent = `${items.length} baselines`;
  summary.innerHTML = items.length
    ? items
        .slice(0, 8)
        .map(
          (row) =>
            `<span class="badge ${row.status || "monitoring"}">${text(row.destination_ip)} · ${text(row.baseline_uid)} · ${text(row.status)}</span>`,
        )
        .join(" ")
    : "Nenhuma baseline criada ainda.";
}

function trendBadge(direction) {
  const value = direction || "stable";
  const label = value === "increasing" ? "↑ increasing" : value === "decreasing" ? "↓ decreasing" : value === "new" ? "novo" : value === "disappeared" ? "sumiu" : "→ stable";
  return `<span class="badge ${value}">${label}</span>`;
}

function renderTrends() {
  const summary = state.trendsSummary || {};
  const cards = [
    ["Total de coletas", summary.total_runs || 0, summary.latest_run?.started_at || "sem coleta"],
    ["Destinos novos", (summary.new_destinations || []).length || 0, "janela recente"],
    ["Em alta", (summary.top_increasing || []).length || 0, "↑ increasing"],
    ["Em queda", (summary.top_decreasing || []).length || 0, "↓ decreasing"],
    ["Sumiram", (summary.disappeared_destinations || []).length || 0, "janela recente"],
    ["Histórico", summary.trend_status || "insufficient_history", summary.latest_run?.run_uid ? `run ${summary.latest_run.run_uid}` : "-"],
  ];
  $("trendCards").innerHTML = cards
    .map(
      ([label, value, meta]) => `
        <article class="summary-card">
          <div class="label">${text(label)}</div>
          <div class="value">${text(value, "0")}</div>
          <div class="meta">${text(meta)}</div>
        </article>
      `,
    )
    .join("");
  $("trendDestinationsBody").innerHTML = state.trends
    .map((row) => `
      <tr>
        <td><strong>${text(row.destination_ip)}</strong></td>
        <td>${text(row.asn)}</td>
        <td>${text(row.organization)}</td>
        <td><span class="${badgeClassForCategory(row.category)}">${text(row.category)}</span></td>
        <td>${text(row.current_count)}</td>
        <td>${text(row.previous_count)}</td>
        <td>${text(row.delta)}</td>
        <td>${trendBadge(row.trend_direction)}</td>
        <td>${text(row.last_seen)}</td>
        <td><button class="ghost" data-trend-details="${text(row.destination_ip)}">Detalhes</button></td>
      </tr>
    `)
    .join("");
  $("trendAsnsBody").innerHTML = state.trendsAsns
    .map((row) => `
      <tr>
        <td><strong>${text(row.dimension_value)}</strong></td>
        <td>${text(row.total_count)}</td>
        <td>${text(row.summary?.current_count)}</td>
        <td>${text(row.summary?.previous_count)}</td>
        <td>${text(row.summary?.delta)}</td>
        <td>${trendBadge(row.summary?.trend_direction)}</td>
      </tr>
    `)
    .join("");
  $("trendCategoriesBody").innerHTML = state.trendsCategories
    .map((row) => `
      <tr>
        <td><strong>${text(row.dimension_value)}</strong></td>
        <td>${text(row.total_count)}</td>
        <td>${text(row.summary?.current_count)}</td>
        <td>${text(row.summary?.previous_count)}</td>
        <td>${text(row.summary?.delta)}</td>
        <td>${trendBadge(row.summary?.trend_direction)}</td>
      </tr>
    `)
    .join("");
  $("trendDestinationsBody").querySelectorAll("button[data-trend-details]").forEach((button) => {
    button.addEventListener("click", () => openDetails(button.dataset.trendDetails));
  });
}

function applyFilters() {
  const q = ($("searchInput").value || "").trim().toLowerCase();
  const category = $("categoryFilter").value;
  const asnSource = $("asnSourceFilter").value;
  const bgpConfirmed = $("bgpConfirmedFilter").value;
  state.filteredTop = state.top.filter((row) => {
    const matchesSearch =
      !q ||
      [row.destination_ip, row.organization, row.asn, row.category, row.asn_source]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(q));
    const matchesCategory = !category || row.category === category;
    const matchesAsnSource = !asnSource || (asnSource === "none" ? !row.asn : row.asn_source === asnSource);
    const matchesBgp = !bgpConfirmed || String(Boolean(row.bgp_confirmed)) === bgpConfirmed;
    return matchesSearch && matchesCategory && matchesAsnSource && matchesBgp;
  });
  renderDestinations();
}

function renderDestinations() {
  const rows = state.filteredTop.length ? state.filteredTop : state.top;
  $("topStatus").textContent = `${rows.length} destinos visíveis`;
  $("destinationsBody").innerHTML = rows
    .map((row) => {
      const asnBadge = row.asn_source === "external" ? "external" : row.asn_source === "bgp" ? "bgp" : "none";
      const bgpLabel = row.bgp_confirmed ? "sim" : "não";
      const categoryClass = badgeClassForCategory(row.category);
      return `
        <tr>
          <td><strong>${text(row.destination_ip)}</strong></td>
          <td>${text(row.destination_port)}</td>
          <td>${text(row.protocol)}</td>
          <td>${text(row.observation_count)}</td>
          <td>${row.asn ? `<strong>${text(row.asn)}</strong>` : "-"}</td>
          <td>${text(row.organization)}</td>
          <td><span class="${categoryClass}">${text(row.category || "unknown")}</span></td>
          <td><span class="badge ${asnBadge}">${text(row.asn_source || "none")}</span></td>
          <td>${text(row.asn_confidence || "no_match")}</td>
          <td>${bgpLabel}</td>
          <td>${text(row.last_seen)}</td>
          <td>
            <div class="row-actions">
              <button class="ghost" data-action="details" data-ip="${text(row.destination_ip)}">Detalhes</button>
              <button class="ghost" data-action="report" data-ip="${text(row.destination_ip)}">Relatório</button>
              <button class="ghost" data-action="bgp" data-ip="${text(row.destination_ip)}">Ver BGP visibility</button>
              <button class="warn disabled" disabled title="Disponível - exige confirmação">Traçar rota</button>
              <button class="disabled" disabled title="Disponível - exige confirmação">Promover para baseline</button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
  $("destinationsBody").querySelectorAll("button[data-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const ip = button.dataset.ip;
      const action = button.dataset.action;
      if (action === "details") {
        await openDetails(ip);
      } else if (action === "bgp") {
        window.open(`/bgp/visibility/ip/${encodeURIComponent(ip)}`, "_blank", "noopener");
      } else if (action === "report") {
        window.open(`/questions/ui`, "_blank", "noopener");
        toast(`Abra a UI de perguntas para gerar relatório do destino ${ip}.`);
      }
    });
  });
}

function renderAsns() {
  $("asnsBody").innerHTML = state.asns
    .map((row) => {
      const sourceClass = row.asn_source === "external" ? "external" : row.asn_source === "bgp" ? "bgp" : "none";
      return `
        <tr>
          <td><strong>${text(row.asn)}</strong></td>
          <td><span class="badge ${sourceClass}">${text(row.asn_source || "none")}</span></td>
          <td>${text(row.organization)}</td>
          <td>${text(row.destination_count)}</td>
          <td>${text(row.total_observations)}</td>
          <td>${text(row.bgp_confirmed_count || 0)}</td>
          <td>${text(row.external_inferred_count || 0)}</td>
          <td>${(row.categories || []).map((cat) => `<span class="${badgeClassForCategory(cat)}">${text(cat)}</span>`).join(" ")}</td>
          <td>${summarizeTopItems(row.top_destinations, "destination_ip", 4)}</td>
        </tr>
      `;
    })
    .join("");
}

function renderCategories() {
  $("categoriesGrid").innerHTML = state.categories
    .map((row) => `
      <article class="category-card">
        <h3>${text(row.category)}</h3>
        <div class="count">${text(row.destination_count)}</div>
        <div class="meta">${text(row.total_observations)} observações</div>
        <div style="margin-top:8px;"><strong>Top ASNs:</strong> ${text((row.top_asns || []).join(", "))}</div>
        <div style="margin-top:8px;"><strong>Top destinos:</strong> ${summarizeTopItems(row.top_destinations, "destination_ip", 4)}</div>
      </article>
    `)
    .join("");
}

function setCategoriesFilter() {
  const current = $("categoryFilter").value;
  const categories = [...new Set(state.categories.map((row) => row.category).filter(Boolean))];
  $("categoryFilter").innerHTML =
    `<option value="">Todas as categorias</option>` +
    categories.map((category) => `<option value="${category}">${category}</option>`).join("");
  $("categoryFilter").value = current;
}

function rowByIp(ip) {
  return state.top.find((row) => row.destination_ip === ip);
}

function setPromoteState(enabled) {
  const button = $("promoteButton");
  if (!button) return;
  const allowed = enabled && !isViewer();
  button.disabled = !allowed;
  button.classList.toggle("disabled", !allowed);
  button.title = isViewer() ? "Requer perfil operador/admin." : "";
}

function renderReport(report) {
  const panel = $("reportPanel");
  if (!panel) return;
  if (!report) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  $("reportHeadline").textContent = report.destination_ip || "-";
  $("reportOperational").textContent = report.operational_report || "-";
  const sections = [
    ["Observado", report.observed],
    ["ASN/enrichment", report.enrichment],
    ["BGP visibility", report.bgp_visibility],
    ["Baseline", report.baseline],
    ["Lacunas", report.gaps],
    ["Próximas ações", report.recommended_actions],
    ["Medições", report.measurements],
  ];
  $("reportSections").innerHTML = sections
    .map(([label, value]) => {
      const body = typeof value === "string" ? value : JSON.stringify(value, null, 2);
      return `<details class="report-block"><summary>${text(label)}</summary><pre>${text(body)}</pre></details>`;
    })
    .join("");
}

function renderMeasurement(measurement) {
  const panel = $("measurementPanel");
  if (!panel) return;
  if (!measurement) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  $("measurementSummary").textContent = JSON.stringify(measurement, null, 2);
}

function renderGraph(graph) {
  const panel = $("graphPanel");
  if (!panel) return;
  if (!graph) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  $("graphSummary").textContent = JSON.stringify(graph, null, 2);
}

async function openDetails(ip) {
  const fallback = rowByIp(ip);
  const data = await api(`/observed-destinations/${encodeURIComponent(ip)}`);
  const baseline = await api(`/observed-destinations/baselines/${encodeURIComponent(ip)}`).catch(() => null);
  const trend = await api(`/observed-destinations/${encodeURIComponent(ip)}/trend`).catch(() => null);
  const dest = data.destination || fallback || {};
  const ports = data.ports || [];
  state.detailIp = ip;
  state.detailBaseline = baseline;
  state.detailReport = null;
  state.detailMeasurement = null;
  state.detailGraph = null;
  state.detailTrend = trend;
  renderReport(null);
  renderMeasurement(null);
  renderGraph(null);
  $("detailTitle").textContent = `${text(dest.destination_ip)}${dest.destination_port ? `:${dest.destination_port}` : ""}`;
  setPromoteState(!baseline);
  $("measureButton").disabled = isViewer() || !baseline;
  $("graphButton").disabled = !baseline;
  if (isViewer()) $("measureButton").title = "Requer perfil operador/admin.";
  $("detailBody").innerHTML = [
    baseline ? ["Baseline ativo", `${text(baseline.baseline_uid)} · ${text(baseline.status)} · ${text(baseline.promoted_at)}`] : null,
    ["ASN", dest.asn],
    ["ASN source", dest.asn_source],
    ["BGP confirmado", dest.bgp_confirmed ? "sim" : "não"],
    ["ASN confidence", dest.asn_confidence],
    ["Organização", dest.organization],
    ["País", dest.country],
    ["Categoria", dest.category],
    ["Domain guess", dest.domain_guess],
    ["Reverse DNS", dest.reverse_dns],
    ["BGP prefix", dest.bgp_prefix],
    ["BGP route count", dest.bgp_route_count],
    ["BGP peer count", dest.bgp_peer_count],
    ["Last seen", dest.last_seen],
    ["First seen", dest.first_seen],
    ["Observations", dest.observation_count],
    ["Enrichment status", dest.enrichment_status],
    ["Limitations", data.limitations || (dest.metadata && dest.metadata.limitations)],
  ]
    .filter(Boolean)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([label, value]) => `<div class="kv"><div class="k">${text(label)}</div><div class="v">${text(value)}</div></div>`)
    .join("") +
    `
      <div class="kv"><div class="k">Ports/protocols</div><div class="v">${ports.map((p) => `${text(p.destination_port)} / ${text(p.protocol)} (${text(p.observation_count)})`).join("<br>")}</div></div>
      ${trend ? `<div class="kv"><div class="k">Tendência</div><div class="v">${trendBadge(trend.summary?.trend_direction)} · ${text(trend.summary?.current_count)} / ${text(trend.summary?.previous_count)} · Δ ${text(trend.summary?.delta)}</div></div>` : ""}
      <div class="kv"><div class="k">Ações sugeridas</div><div class="v">${(data.suggested_actions || []).map((a) => `${text(a.action)}${a.requires_confirmation ? " (confirmação)" : ""}`).join("<br>")}</div></div>
    `;
  $("detailPanel").classList.remove("hidden");
  $("detailPanel").setAttribute("aria-hidden", "false");
}

async function generateReport() {
  if (!state.detailIp) return;
  const report = await api(`/observed-destinations/${encodeURIComponent(state.detailIp)}/report`);
  state.detailReport = report;
  renderReport(report);
  toast("Relatório operacional carregado.");
}

async function measureBaseline() {
  if (!state.detailIp || !state.detailBaseline) return;
  if (isViewer()) {
    toast("Requer perfil operador/admin.");
    return;
  }
  if (!confirm("Esta ação executa ping/traceroute a partir do RouteBrain para este IP público. Confirmo executar medição ativa.")) return;
  const button = $("measureButton");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Executando ping/traceroute...";
  try {
    const response = await api(`/observed-destinations/baselines/${encodeURIComponent(state.detailIp)}/measure`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true, ping: true, traceroute: true }),
    });
    state.detailMeasurement = response;
    renderMeasurement(response);
    if (response.graph_url) {
      const graph = await api(response.graph_url).catch(() => null);
      state.detailGraph = graph;
      renderGraph(graph);
    }
    toast("Medição ativa concluída.");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function viewGraph() {
  if (!state.detailIp || !state.detailBaseline) return;
  const graph = await api(`/observed-destinations/baselines/${encodeURIComponent(state.detailIp)}/traceroute-graph`);
  state.detailGraph = graph;
  renderGraph(graph);
  toast("Traceroute graph carregado.");
}

function closeDetail() {
  $("detailPanel").classList.add("hidden");
  $("detailPanel").setAttribute("aria-hidden", "true");
}

async function loadAll() {
  $("topStatus").textContent = "carregando...";
  const [summary, top, asns, categories, baselines, trendsSummary, trends, trendsAsns, trendsCategories] = await Promise.all([
    api("/observed-destinations/summary"),
    api("/observed-destinations/top?limit=200"),
    api("/observed-destinations/asns?limit=50"),
    api("/observed-destinations/categories?limit=50"),
    api("/observed-destinations/baselines?limit=50"),
    api("/observed-destinations/trends-summary?window_runs=10"),
    api("/observed-destinations/trends?limit=20&window_runs=10"),
    api("/observed-destinations/trends/asns?limit=20&window_runs=10"),
    api("/observed-destinations/trends/categories?limit=20&window_runs=10"),
  ]);
  state.summary = summary;
  state.top = top.items || [];
  state.asns = asns.items || [];
  state.categories = categories.items || [];
  state.baselines = baselines.items || [];
  state.trendsSummary = trendsSummary.summary || {};
  state.trends = trends.items || [];
  state.trendsAsns = trendsAsns.items || [];
  state.trendsCategories = trendsCategories.items || [];
  state.filteredTop = [...state.top];
  renderSummary(summary);
  renderBaselines();
  setCategoriesFilter();
  renderDestinations();
  renderAsns();
  renderCategories();
  renderTrends();
  $("topStatus").textContent = `atualizado em ${summary.last_seen || "-"}`;
}

async function collectNow() {
  if (isViewer()) {
    toast("Requer perfil operador/admin.");
    return;
  }
  if (!confirm("Esta ação lê a tabela de conexões da MikroTik de forma read-only. Não altera firewall/NAT/tráfego e não coleta payload. Continuar?")) return;
  $("collectButton").disabled = true;
  try {
    await api("/observed-destinations/collect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit: 1000, dry_run: false }),
    });
    toast("Coleta enviada.");
    await loadAll();
  } catch (error) {
    toast(`Falha na coleta: ${error.message}`);
  } finally {
    $("collectButton").disabled = false;
  }
}

async function enrichPending() {
  if (isViewer()) {
    toast("Requer perfil operador/admin.");
    return;
  }
  $("enrichButton").disabled = true;
  try {
    await api("/observed-destinations/enrich", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit: 100, refresh: false, resolve_bgp: true, allow_external_asn: true }),
    });
    toast("Enrichment concluído.");
    await loadAll();
  } catch (error) {
    toast(`Falha no enrichment: ${error.message}`);
  } finally {
    $("enrichButton").disabled = false;
  }
}

async function init() {
  await loadAuthStatus();
  $("refreshButton").addEventListener("click", loadAll);
  $("applyFiltersButton").addEventListener("click", applyFilters);
  $("collectButton").addEventListener("click", collectNow);
  $("enrichButton").addEventListener("click", enrichPending);
  $("closeDetailButton").addEventListener("click", closeDetail);
  $("reportButton").addEventListener("click", generateReport);
  $("measureButton").addEventListener("click", measureBaseline);
  $("graphButton").addEventListener("click", viewGraph);
  $("promoteButton").addEventListener("click", async () => {
    if (!state.detailIp) return;
    if (isViewer()) {
      toast("Requer perfil operador/admin.");
      return;
    }
    if (!confirm("Isto cria uma baseline de monitoramento para este destino observado. Não executa ping/traceroute. Deseja continuar?")) return;
    const response = await api(`/observed-destinations/${encodeURIComponent(state.detailIp)}/promote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true, notes: "promoção via UI" }),
    });
    toast(`Baseline criada: ${response.baseline_uid || "ok"}`);
    await loadAll();
    await openDetails(state.detailIp);
  });
  $("detailPanel").addEventListener("click", (event) => {
    if (event.target === $("detailPanel")) closeDetail();
  });
  ["searchInput", "categoryFilter", "asnSourceFilter", "bgpConfirmedFilter"].forEach((id) => {
    $(id).addEventListener("input", applyFilters);
    $(id).addEventListener("change", applyFilters);
  });
  applyAuthControls();
  await loadAll();
}

renderAuthBadge();
loadAuthStatus().finally(() => {
  init().catch((error) => {
    $("topStatus").textContent = `erro: ${error.message}`;
    toast(error.message);
  });
});
