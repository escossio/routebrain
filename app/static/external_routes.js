const state = {
  auth: { authenticated: false, username: null, role: null, permissions: [] },
  services: [],
  hops: [],
  unknownHops: [],
  selectedService: null,
  compare: null,
};

const $ = (id) => document.getElementById(id);

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

function html(value) {
  return text(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { Accept: "application/json", ...(options.headers || {}) },
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

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2600);
}

function setAuthBadge(textValue, className) {
  const el = $("auth-status");
  if (!el) return;
  el.textContent = textValue;
  el.className = className;
}

async function loadAuthStatus() {
  try {
    const response = await fetch("/auth/me", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      state.auth = { authenticated: false, username: null, role: null, permissions: [] };
      setAuthBadge("Não autenticado", "auth-badge auth-badge-error anonymous");
      return;
    }
    const payload = await response.json();
    const role = payload.role || "desconhecido";
    const username = payload.username || "usuário";
    state.auth = { ...payload, authenticated: true, username, role };
    const label = role === "admin" ? "operador" : "somente leitura";
    setAuthBadge(`Usuário: ${username} · perfil: ${role} · ${label}`, `auth-badge auth-badge-${role} ${role}`);
  } catch (error) {
    state.auth = { authenticated: false, username: null, role: null, permissions: [] };
    setAuthBadge("Falha ao verificar autenticação", "auth-badge auth-badge-error anonymous");
  }
}

function applyAuthControls() {
  const disable = !isAdmin();
  [
    ["seedButton", "Requer operador/admin."],
    ["ingestButton", "Requer operador/admin."],
    ["enrichButton", "Requer operador/admin."],
    ["traceServiceButton", "Requer operador/admin."],
  ].forEach(([id, title]) => {
    const button = $(id);
    if (!button) return;
    button.disabled = disable;
    button.title = disable ? title : "";
  });
}

function badge(value) {
  return `<span class="badge ${html(value)}">${html(value)}</span>`;
}

function serviceSummaryTotals() {
  const services = state.services || [];
  const hops = state.hops || [];
  const unknownHops = state.unknownHops || [];
  const totalAsns = new Set(hops.map((item) => item.asn).filter((value) => value !== null && value !== undefined && value !== "")).size;
  return {
    services: services.length,
    hops: hops.length,
    asns: totalAsns,
    unknown: unknownHops.length,
    observations: services.reduce((sum, row) => sum + Number(row.observation_count || 0), 0),
  };
}

function renderSummaryCards() {
  const totals = serviceSummaryTotals();
  $("summaryCards").innerHTML = [
    ["Serviços", totals.services, "google / youtube / meta / cloudflare"],
    ["Hops", totals.hops, "inventário histórico consolidado"],
    ["ASNs", totals.asns, "unique ASNs nas rotas"],
    ["Unknown", totals.unknown, "hops externos sem confiança suficiente"],
  ]
    .map(
      ([label, value, meta]) => `
        <article class="summary-card">
          <div class="label">${html(label)}</div>
          <div class="value">${html(value)}</div>
          <div class="meta">${html(meta)}</div>
        </article>
      `,
    )
    .join("");
}

function renderServices() {
  const rows = state.services || [];
  $("servicesBody").innerHTML = rows.length
    ? rows
        .map(
          (row) => `
            <tr class="clickable-row" data-service="${html(row.service_slug)}">
              <td><strong>${html(row.display_name)}</strong><br><small>${html(row.service_slug)}</small></td>
              <td>${html(row.category)}</td>
              <td>${html(row.target_count || 0)}</td>
              <td>${html(row.observation_count || 0)}</td>
              <td>${html(row.hop_count || 0)}</td>
              <td>${html(row.distinct_asn_count || 0)}</td>
              <td>${html(row.unknown_hop_count || 0)}</td>
              <td>${html(row.last_seen_at)}</td>
              <td>
                <button
                  type="button"
                  class="secondary trace-row-button"
                  data-trace-service="${html(row.service_slug)}"
                  ${isAdmin() ? "" : "disabled"}
                  title="${isAdmin() ? "Executar traceroute controlado para este serviço." : "Requer operador/admin."}"
                >
                  Mapear rota
                </button>
              </td>
            </tr>
          `,
        )
        .join("")
    : `<tr><td colspan="9">Nenhum serviço seedado.</td></tr>`;
  $("servicesBody").querySelectorAll("tr[data-service]").forEach((row) => {
    row.addEventListener("click", () => selectService(row.dataset.service));
  });
  $("servicesBody").querySelectorAll("button[data-trace-service]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      traceService(button.dataset.traceService).catch((error) => toast(error.message));
    });
  });
}

function renderHops() {
  const rows = state.hops || [];
  $("hopsBody").innerHTML = rows.length
    ? rows
        .slice(0, 200)
        .map(
          (row) => `
            <tr>
              <td><strong>${html(row.hop_ip)}</strong></td>
              <td>${html(row.services || [])}</td>
              <td>${html(row.asn)}</td>
              <td>${html(row.organization)}</td>
              <td>${html(row.country)}</td>
              <td>${badge(row.category || "unknown")}</td>
              <td>${html(row.role)}</td>
              <td>${html(row.confidence)}</td>
              <td>${html(row.observation_count || 0)}</td>
            </tr>
          `,
        )
        .join("")
    : `<tr><td colspan="9">Nenhum hop inventariado.</td></tr>`;
}

function renderUnknownHops() {
  const rows = state.unknownHops || [];
  $("unknownBody").innerHTML = rows.length
    ? rows
        .map(
          (row) => `
            <tr>
              <td><strong>${html(row.hop_ip)}</strong></td>
              <td>${html(row.services || [])}</td>
              <td>${html(row.asn)}</td>
              <td>${html(row.organization)}</td>
              <td>${html(row.country)}</td>
              <td>${badge(row.category || "unknown")}</td>
              <td>${html(row.role)}</td>
              <td>${html(row.confidence)}</td>
              <td>${html(row.last_seen_at)}</td>
            </tr>
          `,
        )
        .join("")
    : `<tr><td colspan="9">Sem hops desconhecidos no inventário atual.</td></tr>`;
}

function renderServiceDetail(summaryResponse) {
  const service = summaryResponse?.service || {};
  const summary = summaryResponse?.summary || {};
  const hops = summaryResponse?.hops || [];
  const targets = summaryResponse?.targets || [];
  const edges = summaryResponse?.edges || [];
  const latestTraceRun = summaryResponse?.latest_trace_run || {};
  $("serviceDetail").innerHTML = `
    <div class="detail-grid">
      <div class="kv"><strong>Serviço</strong><span>${html(service.display_name || service.service_slug || "-")}</span></div>
      <div class="kv"><strong>Categoria</strong><span>${html(service.category)}</span></div>
      <div class="kv"><strong>Targets</strong><span>${html(summary.target_count || 0)}</span></div>
      <div class="kv"><strong>Obs.</strong><span>${html(summary.observation_count || 0)}</span></div>
      <div class="kv"><strong>Hops</strong><span>${html(summary.hop_count || 0)}</span></div>
      <div class="kv"><strong>ASNs</strong><span>${html(summary.distinct_asn_count || 0)}</span></div>
      <div class="kv"><strong>Unknown</strong><span>${html(summary.unknown_hop_count || 0)}</span></div>
      <div class="kv"><strong>Edges</strong><span>${html(summaryResponse?.edge_count || edges.length || 0)}</span></div>
      <div class="kv"><strong>Último visto</strong><span>${html(summary.last_seen_at)}</span></div>
    </div>
    <div class="detail-block">
      <strong>Targets</strong>
      <div>${targets.length ? targets.map((item) => badge(item)).join(" ") : "Sem targets seedados."}</div>
    </div>
    <div class="detail-block">
      <strong>Top hops</strong>
      <div class="detail-list">
        ${hops.length
          ? hops
              .slice(0, 8)
              .map(
                (hop) => `
                  <div class="detail-item">
                    <strong>${html(hop.hop_ip)}</strong>
                    <span>${html(hop.asn)} · ${html(hop.organization)} · ${html(hop.category)} · ${html(hop.confidence)}</span>
                  </div>
                `,
              )
              .join("")
          : "<p>Nenhum hop consolidado para este serviço.</p>"}
      </div>
    </div>
    <div class="detail-block">
      <strong>Edges</strong>
      <div class="detail-list">
        ${edges.length
          ? edges
              .slice(0, 10)
              .map(
                (edge) => `
                  <div class="detail-item">
                    <strong>${html(edge.from_hop_ip || "-")} → ${html(edge.to_hop_ip || "-")}</strong>
                    <span>${html(edge.transition_type)} · ${html(edge.from_ip_type)} → ${html(edge.to_ip_type)} · ${html(edge.confidence)}</span>
                  </div>
                `,
              )
              .join("")
          : "<p>Nenhuma edge registrada para este serviço.</p>"}
      </div>
    </div>
    <div class="detail-block">
      <strong>Último trace</strong>
      <div>
        ${latestTraceRun.run_uid ? `Run: <code>${html(latestTraceRun.run_uid)}</code><br>` : "Sem run de traceroute externo ainda.<br>"}
        ${latestTraceRun.target_resolved_ip ? `Target: ${html(latestTraceRun.target_resolved_ip)}<br>` : ""}
        ${latestTraceRun.status ? `Status: ${html(latestTraceRun.status)}<br>` : ""}
        ${latestTraceRun.graph_url ? `Graph: <a href="${html(latestTraceRun.graph_url)}" target="_blank" rel="noopener">abrir grafo</a><br>` : ""}
      </div>
    </div>
  `;
  $("serviceStatus").textContent = `${service.service_slug || "-"} · ${hops.length} hops · ${edges.length} edges`;
}

function renderCompare(data) {
  const comparison = data?.comparison || {};
  const overlap = comparison.overlap || {};
  const serviceA = data?.service_a?.summary || {};
  const serviceB = data?.service_b?.summary || {};
  $("compareBox").innerHTML = `
    <div class="detail-grid">
      <div class="kv"><strong>Serviço A</strong><span>${html(comparison.service_a)}</span></div>
      <div class="kv"><strong>Serviço B</strong><span>${html(comparison.service_b)}</span></div>
      <div class="kv"><strong>Hops compartilhados</strong><span>${html(overlap.shared_hop_count || 0)}</span></div>
      <div class="kv"><strong>ASNs compartilhados</strong><span>${html(overlap.shared_asn_count || 0)}</span></div>
      <div class="kv"><strong>Roles</strong><span>${html(overlap.shared_role_count || 0)}</span></div>
      <div class="kv"><strong>Categorias</strong><span>${html(overlap.shared_category_count || 0)}</span></div>
      <div class="kv"><strong>Ratio A</strong><span>${html(overlap.shared_hop_ratio_a || 0)}</span></div>
      <div class="kv"><strong>Ratio B</strong><span>${html(overlap.shared_hop_ratio_b || 0)}</span></div>
    </div>
    <div class="detail-block">
      <strong>Resumo A/B</strong>
      <p>${html(serviceA.display_name || comparison.service_a || "-")} · hops ${html(serviceA.hop_count || 0)} · ASNs ${html(serviceA.distinct_asn_count || 0)}</p>
      <p>${html(serviceB.display_name || comparison.service_b || "-")} · hops ${html(serviceB.hop_count || 0)} · ASNs ${html(serviceB.distinct_asn_count || 0)}</p>
    </div>
  `;
  const sharedExamples = comparison.shared_examples || [];
  if (sharedExamples.length) {
    $("compareBox").innerHTML += `
      <div class="detail-block">
        <strong>Exemplos compartilhados</strong>
        <div class="detail-list">
          ${sharedExamples
            .slice(0, 5)
            .map((item) => `<div class="detail-item"><strong>${html(item.hop_ip)}</strong></div>`)
            .join("")}
        </div>
      </div>
    `;
  }
}

async function loadServices() {
  const rows = await api("/external-routes/services");
  state.services = rows || [];
  renderServices();
  renderSummaryCards();
  fillCompareSelectors();
  if (!state.selectedService && state.services.length) {
    await selectService(state.services[0].service_slug);
  }
}

async function loadHops() {
  const rows = await api("/external-routes/hops?limit=200");
  state.hops = rows || [];
  renderHops();
  renderSummaryCards();
}

async function loadUnknownHops() {
  const rows = await api("/external-routes/unknown-hops?limit=100");
  state.unknownHops = rows || [];
  renderUnknownHops();
  renderSummaryCards();
}

function fillCompareSelectors() {
  const services = state.services || [];
  const a = $("serviceASelect");
  const b = $("serviceBSelect");
  const options = services
    .map((row) => `<option value="${html(row.service_slug)}">${html(row.display_name || row.service_slug)}</option>`)
    .join("");
  a.innerHTML = options;
  b.innerHTML = options;
  if (services.length >= 1) a.value = state.selectedService || services[0].service_slug;
  if (services.length >= 2) b.value = services[1].service_slug;
  else b.value = services[0]?.service_slug || "";
}

async function selectService(serviceSlug) {
  if (!serviceSlug) return;
  state.selectedService = serviceSlug;
  const response = await api(`/external-routes/services/${encodeURIComponent(serviceSlug)}/summary`);
  renderServiceDetail(response);
  const service = response?.service?.service_slug || serviceSlug;
  $("serviceStatus").textContent = `${service} · ${response?.summary?.hop_count || 0} hops`;
  if ($("serviceASelect").value !== serviceSlug) $("serviceASelect").value = serviceSlug;
}

async function traceService(serviceSlug = null) {
  if (!isAdmin()) return toast("Requer operador/admin.");
  const selectedService = serviceSlug || state.selectedService || $("serviceASelect").value;
  const traceTarget = selectedService;
  const traceLabel = traceTarget || "serviço";
  if (!traceTarget) return toast("Selecione um serviço.");
  if (!window.confirm(`Mapear rota para ${traceLabel}? O backend vai escolher o alvo real e executar o traceroute com confirmação.`)) return;
  const data = await api(`/external-routes/services/${encodeURIComponent(traceTarget)}/trace`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true, target_override: null, max_hops: 20 }),
  });
  toast(`Trace ${data.status || "ok"}: ${data.hops_count || 0} hops, ${data.edges_count || 0} edges`);
  await refreshAll();
  if (traceTarget) {
    await selectService(traceTarget);
  }
}

async function runCompare() {
  const serviceA = $("serviceASelect").value;
  const serviceB = $("serviceBSelect").value;
  if (!serviceA || !serviceB) {
    toast("Selecione dois serviços.");
    return;
  }
  const data = await api(`/external-routes/compare?service_a=${encodeURIComponent(serviceA)}&service_b=${encodeURIComponent(serviceB)}`);
  state.compare = data;
  renderCompare(data);
}

async function refreshAll() {
  $("serviceStatus").textContent = "carregando...";
  $("hopsStatus").textContent = "carregando...";
  $("unknownStatus").textContent = "carregando...";
  await Promise.all([loadServices(), loadHops(), loadUnknownHops()]);
  $("serviceStatus").textContent = state.selectedService ? `${state.selectedService} · pronto` : "pronto";
  $("hopsStatus").textContent = `${state.hops.length} hops`;
  $("unknownStatus").textContent = `${state.unknownHops.length} desconhecidos`;
}

async function seedServices() {
  if (!isAdmin()) return toast("Requer operador/admin.");
  const data = await api("/external-routes/seed-services", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  toast(`Seed concluído: ${data.inserted_services || 0} serviços, ${data.inserted_targets || 0} targets`);
  await refreshAll();
}

async function ingestExisting() {
  if (!isAdmin()) return toast("Requer operador/admin.");
  const dryRun = $("dryRunInput").checked;
  if (!dryRun && !window.confirm("Persistir ingestão histórica de traceroutes já existentes?")) return;
  const data = await api("/external-routes/ingest-existing", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dry_run: dryRun }),
  });
  toast(dryRun ? `Dry-run: ${data.sources_seen || 0} fontes, ${data.hops_seen || 0} hops` : `Ingestão concluída: ${data.counters?.observations_total || 0} observações`);
  await refreshAll();
}

async function enrichHops() {
  if (!isAdmin()) return toast("Requer operador/admin.");
  const data = await api("/external-routes/enrich", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ limit: 100 }),
  });
  toast(`Enriched ${data.count || 0} hops.`);
  await refreshAll();
}

function bindEvents() {
  $("refreshButton").addEventListener("click", () => refreshAll().catch((error) => toast(error.message)));
  $("seedButton").addEventListener("click", () => seedServices().catch((error) => toast(error.message)));
  $("ingestButton").addEventListener("click", () => ingestExisting().catch((error) => toast(error.message)));
  $("enrichButton").addEventListener("click", () => enrichHops().catch((error) => toast(error.message)));
  $("traceServiceButton").addEventListener("click", () => traceService().catch((error) => toast(error.message)));
  $("compareButton").addEventListener("click", () => runCompare().catch((error) => toast(error.message)));
  $("serviceASelect").addEventListener("change", (event) => {
    const value = event.target.value;
    if (value) selectService(value).catch((error) => toast(error.message));
  });
  $("serviceBSelect").addEventListener("change", () => {
    if (state.compare) runCompare().catch((error) => toast(error.message));
  });
}

async function init() {
  bindEvents();
  await loadAuthStatus();
  applyAuthControls();
  try {
    await refreshAll();
  } catch (error) {
    toast(error.message);
  }
}

document.addEventListener("DOMContentLoaded", init);
