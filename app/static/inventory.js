const state = {
  auth: { authenticated: false, username: null, role: null, permissions: [] },
  summary: {},
  candidates: [],
};

const $ = (id) => document.getElementById(id);

function text(value, fallback = "-") {
  if (value === null || value === undefined || value === "") return fallback;
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

function isViewer() {
  return state.auth && state.auth.role === "viewer";
}

function isAdmin() {
  return state.auth && state.auth.role === "admin";
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2800);
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
    const label = role === "admin" ? "operador" : role === "viewer" ? "somente leitura" : role;
    state.auth = { ...payload, authenticated: true, username, role };
    setAuthBadge(`Usuário: ${username} · perfil: ${role} · ${label}`, `auth-badge auth-badge-${role} ${role}`);
  } catch (error) {
    state.auth = { authenticated: false, username: null, role: null, permissions: [] };
    setAuthBadge("Falha ao verificar autenticação", "auth-badge auth-badge-error anonymous");
  }
}

function applyAuthControls() {
  const collectButton = $("collectButton");
  if (!collectButton) return;
  if (isViewer()) {
    collectButton.disabled = true;
    collectButton.title = "Requer operador/admin.";
  } else {
    collectButton.disabled = false;
    collectButton.title = "Executa apenas coleta administrativa read-only.";
  }
}

function confidenceClass(value) {
  const number = Number(value || 0);
  if (number >= 0.8) return "high";
  if (number >= 0.5) return "medium";
  return "low";
}

function renderSummary() {
  const summary = state.summary || {};
  const cards = [
    ["Hosts confirmados", summary.confirmed_hosts || 0, "inventory_hosts"],
    ["Candidatos", summary.candidates || 0, "status candidate"],
    ["Alta confiança", summary.high_confidence_candidates || 0, "confidence >= 0.80"],
    ["Sem hostname", summary.candidates_without_hostname || 0, "precisam revisão"],
    ["Última descoberta", summary.last_discovery_at || "-", summary.last_discovery_run_uid || "sem run"],
    ["Fontes", (summary.sources || []).join(", ") || "-", "evidência read-only"],
  ];
  $("summaryCards").innerHTML = cards.map(([label, value, meta]) => `
    <article class="summary-card">
      <div class="label">${html(label)}</div>
      <div class="value">${html(value)}</div>
      <div class="meta">${html(meta)}</div>
    </article>
  `).join("");
}

function renderCandidates() {
  const rows = state.candidates || [];
  $("candidatesBody").innerHTML = rows.length ? rows.map((row) => {
    const disabled = !isAdmin() || row.status !== "candidate";
    const disabledTitle = isViewer() ? "Requer operador/admin." : "Ação indisponível para este status.";
    return `
      <tr>
        <td><strong>${html(row.ip)}</strong><br><small>${html(row.candidate_uid)}</small></td>
        <td>${html(row.mac)}</td>
        <td>${html(row.hostname)}</td>
        <td>${html(row.interface_name)}</td>
        <td>${html(row.source)}<br><small>${html(row.source_detail)}</small></td>
        <td><span class="badge ${confidenceClass(row.confidence)}">${html(row.confidence)}</span></td>
        <td><span class="badge ${html(row.status)}">${html(row.status)}</span></td>
        <td>${html(row.last_seen_at)}</td>
        <td>
          <div class="row-actions">
            <button type="button" data-detail="${html(row.candidate_uid)}">Detalhe</button>
            <button type="button" data-promote="${html(row.candidate_uid)}" ${disabled ? "disabled" : ""} title="${disabled ? html(disabledTitle) : "Promover com confirmação"}">Promover</button>
            <button type="button" data-ignore="${html(row.candidate_uid)}" ${disabled ? "disabled" : ""} title="${disabled ? html(disabledTitle) : "Ignorar com confirmação"}">Ignorar</button>
          </div>
        </td>
      </tr>
    `;
  }).join("") : `<tr><td colspan="9">Nenhum candidato encontrado.</td></tr>`;
}

function renderPreview(result) {
  const box = $("previewBox");
  const counters = result.counters || {};
  const preview = result.preview || [];
  box.classList.remove("hidden");
  box.innerHTML = `
    <strong>Dry-run:</strong>
    raw=${html(counters.raw_seen || 0)}
    candidatos=${html(counters.candidates_seen || 0)}
    skipped=${html(counters.skipped || 0)}
    <br>
    ${preview.slice(0, 8).map((row) => `${html(row.ip)} ${html(row.hostname)} ${html(row.source_detail)}`).join("<br>") || "Sem preview."}
  `;
}

function field(label, value) {
  return `<div class="kv"><strong>${html(label)}</strong><span>${html(value)}</span></div>`;
}

async function openDetail(candidateUid) {
  const data = await api(`/inventory/discovery/candidates/${encodeURIComponent(candidateUid)}`);
  $("detailTitle").textContent = data.hostname || data.ip || data.candidate_uid;
  const evidence = data.evidence || [];
  const reasons = data.confidence_reason || [];
  $("detailBody").innerHTML = [
    field("UID", data.candidate_uid),
    field("IP", data.ip),
    field("MAC", data.mac),
    field("Hostname", data.hostname),
    field("Interface", data.interface_name),
    field("Fonte", `${text(data.source)} / ${text(data.source_detail)}`),
    field("Confiança", `${text(data.confidence)} (${reasons.map((item) => item.reason || item).join(", ") || "sem detalhe"})`),
    field("Status", data.status),
    `<section><h3>Evidências</h3>${
      evidence.length ? evidence.map((item) => `
        <div class="kv">
          <strong>${html(item.evidence_type)}</strong>
          <span>${html(item.ip)} ${html(item.mac)} ${html(item.hostname)} ${html(item.interface_name)}<br><small>${html(item.observed_at)}</small></span>
        </div>
      `).join("") : "<p>Sem evidências registradas.</p>"
    }</section>`,
  ].join("");
  $("detailPanel").classList.remove("hidden");
  $("detailPanel").setAttribute("aria-hidden", "false");
}

function closeDetail() {
  $("detailPanel").classList.add("hidden");
  $("detailPanel").setAttribute("aria-hidden", "true");
}

async function loadCandidates() {
  const status = $("statusFilter").value;
  const query = new URLSearchParams({ limit: "100" });
  if (status) query.set("status", status);
  const data = await api(`/inventory/discovery/candidates?${query.toString()}`);
  state.summary = data.summary || {};
  state.candidates = data.items || [];
  renderSummary();
  renderCandidates();
  applyAuthControls();
}

async function collectDiscovery() {
  if (!isAdmin()) {
    toast("Requer operador/admin.");
    return;
  }
  const dryRun = $("dryRunInput").checked;
  if (!dryRun && !window.confirm("Coleta read-only real será persistida como candidatos. Confirmar?")) return;
  $("collectStatus").textContent = dryRun ? "executando dry-run..." : "coletando read-only...";
  const limit = Number($("limitInput").value || 500);
  try {
    const result = await api("/inventory/discovery/collect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: "mikrotik", dry_run: dryRun, limit }),
    });
    $("collectStatus").textContent = "ok";
    if (dryRun) renderPreview(result);
    toast(dryRun ? "Dry-run concluído." : "Coleta read-only registrada.");
    await loadCandidates();
  } catch (error) {
    $("collectStatus").textContent = "erro";
    toast(error.message);
  }
}

async function promoteCandidate(candidateUid) {
  if (!isAdmin()) return toast("Requer operador/admin.");
  if (!window.confirm("Promover candidato para inventory_hosts?")) return;
  await api(`/inventory/discovery/candidates/${encodeURIComponent(candidateUid)}/promote`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true }),
  });
  toast("Candidato promovido.");
  await loadCandidates();
}

async function ignoreCandidate(candidateUid) {
  if (!isAdmin()) return toast("Requer operador/admin.");
  if (!window.confirm("Ignorar candidato?")) return;
  await api(`/inventory/discovery/candidates/${encodeURIComponent(candidateUid)}/ignore`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirm: true, reason: "ignored_from_ui" }),
  });
  toast("Candidato ignorado.");
  await loadCandidates();
}

document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const detailUid = target.getAttribute("data-detail");
  const promoteUid = target.getAttribute("data-promote");
  const ignoreUid = target.getAttribute("data-ignore");
  try {
    if (detailUid) await openDetail(detailUid);
    if (promoteUid) await promoteCandidate(promoteUid);
    if (ignoreUid) await ignoreCandidate(ignoreUid);
  } catch (error) {
    toast(error.message);
  }
});

$("refreshButton").addEventListener("click", loadCandidates);
$("collectButton").addEventListener("click", collectDiscovery);
$("statusFilter").addEventListener("change", loadCandidates);
$("closeDetailButton").addEventListener("click", closeDetail);

async function init() {
  await loadAuthStatus();
  applyAuthControls();
  await loadCandidates();
}

init().catch((error) => toast(error.message));
