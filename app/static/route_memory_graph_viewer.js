const state = {
  snapshot: null,
  selected: null,
};

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "-").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[char]);
}

async function loadSnapshot() {
  const response = await fetch("/route-memory/graphs/latest", { credentials: "same-origin", headers: { Accept: "application/json" } });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload?.detail || payload?.message || response.statusText);
  }
  return payload;
}

function setStatus(message) {
  const el = $("statusBox");
  if (el) el.textContent = message;
}

function renderSummary(snapshot) {
  const payload = snapshot.payload || {};
  const cards = [
    ["Routes", payload.routes?.length || snapshot.route_count || 0],
    ["Nodes", payload.nodes?.length || 0],
    ["Edges", payload.edges?.length || 0],
    ["Segments", payload.segments?.length || 0],
    ["Divergences", payload.divergences?.length || 0],
    ["Shared nodes", (payload.nodes || []).filter((item) => item.shared).length],
    ["Shared edges", (payload.edges || []).filter((item) => item.shared).length],
  ];
  $("summaryCards").innerHTML = cards.map(([label, value]) => `
    <article class="summary-card">
      <div class="label">${esc(label)}</div>
      <div class="value">${esc(value)}</div>
    </article>
  `).join("");
}

function routeColor(routeIds, shared) {
  if (shared || (routeIds || []).length > 1) return "#1d4ed8";
  if ((routeIds || []).includes("route_2")) return "#0f766e";
  return "#b45309";
}

function buildNodeLayout(snapshot) {
  const nodes = snapshot.payload?.nodes || [];
  const map = new Map();
  const byRoute = new Map();
  for (const node of nodes) {
    for (const routeId of node.route_ids || []) {
      if (!byRoute.has(routeId)) byRoute.set(routeId, []);
      byRoute.get(routeId).push(node);
    }
  }
  for (const [routeId, items] of byRoute.entries()) {
    items.sort((a, b) => String(a.label || a.canonical_key).localeCompare(String(b.label || b.canonical_key)));
    items.forEach((node, index) => {
      if (!map.has(node.node_id)) map.set(node.node_id, { x: 180 + index * 150, y: 120 + byRoute.size * 70 });
      const pos = map.get(node.node_id);
      pos.y += routeId === "route_2" ? 120 : 0;
    });
  }
  nodes.forEach((node, index) => {
    if (!map.has(node.node_id)) map.set(node.node_id, { x: 140 + (index % 6) * 180, y: 120 + Math.floor(index / 6) * 120 });
  });
  return map;
}

function renderDetail(item) {
  if (!item) {
    $("detailBox").innerHTML = "Selecione um node ou edge.";
    return;
  }
  if (item.kind === "edge") {
    $("detailBox").innerHTML = `
      <div class="detail-title">Edge</div>
      <div class="kv"><strong>source</strong><span>${esc(item.data.source)}</span></div>
      <div class="kv"><strong>target</strong><span>${esc(item.data.target)}</span></div>
      <div class="kv"><strong>route_ids</strong><span>${esc((item.data.route_ids || []).join(", "))}</span></div>
      <div class="kv"><strong>shared</strong><span>${esc(item.data.shared)}</span></div>
      <div class="kv"><strong>edge_type</strong><span>${esc(item.data.edge_type)}</span></div>
    `;
    return;
  }
  $("detailBox").innerHTML = `
    <div class="detail-title">Node</div>
    <div class="kv"><strong>node_id</strong><span>${esc(item.data.node_id)}</span></div>
    <div class="kv"><strong>label</strong><span>${esc(item.data.label || item.data.canonical_key)}</span></div>
    <div class="kv"><strong>canonical_key</strong><span>${esc(item.data.canonical_key)}</span></div>
    <div class="kv"><strong>ip</strong><span>${esc(item.data.ip || "-")}</span></div>
    <div class="kv"><strong>route_ids</strong><span>${esc((item.data.route_ids || []).join(", "))}</span></div>
    <div class="kv"><strong>shared</strong><span>${esc(item.data.shared)}</span></div>
  `;
}

function drawGraph(snapshot) {
  const svg = $("graphSvg");
  const payload = snapshot.payload || {};
  const nodes = payload.nodes || [];
  const edges = payload.edges || [];
  const divergences = payload.divergences || [];
  const layout = buildNodeLayout(snapshot);
  const nodeById = new Map(nodes.map((node) => [node.node_id, node]));
  const edgeItems = [];
  let markup = "";

  svg.setAttribute("viewBox", "0 0 1500 920");
  markup += `<defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
      <path d="M0,0 L10,5 L0,10 z" fill="#64748b"></path>
    </marker>
  </defs>`;

  for (const edge of edges) {
    const source = layout.get(edge.source);
    const target = layout.get(edge.target);
    if (!source || !target) continue;
    const stroke = edge.shared ? "#1d4ed8" : routeColor(edge.route_ids, false);
    const strokeWidth = edge.shared ? 4 : 2;
    const x1 = source.x;
    const y1 = source.y;
    const x2 = target.x;
    const y2 = target.y;
    markup += `
      <g class="edge-group" data-kind="edge" data-id="${esc(edge.edge_id)}">
        <line class="edge-line ${edge.shared ? "shared" : ""}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="${strokeWidth}" marker-end="url(#arrow)"></line>
      </g>`;
    edgeItems.push({ kind: "edge", data: edge, element: null });
  }

  const divergenceIndex = new Set((divergences || []).map((item) => item.at_segment));
  nodes.forEach((node) => {
    const pos = layout.get(node.node_id);
    if (!pos) return;
    const shared = !!node.shared;
    const fill = shared ? "#dbeafe" : (node.ip ? routeColor(node.route_ids, false) : "#f8fafc");
    const stroke = shared ? "#1d4ed8" : (divergenceIndex.has(node.node_id) ? "#bc332d" : "#94a3b8");
    const width = shared ? 170 : 150;
    markup += `
      <g class="node-group" data-kind="node" data-id="${esc(node.node_id)}" transform="translate(${pos.x}, ${pos.y})">
        <rect x="${-width / 2}" y="-26" width="${width}" height="52" rx="16" ry="16" fill="${fill}" stroke="${stroke}" stroke-width="${shared ? 3 : 2}"></rect>
        <text x="0" y="-2" text-anchor="middle" class="node-label">${esc(node.label || node.canonical_key)}</text>
        <text x="0" y="16" text-anchor="middle" class="node-meta">${esc(node.ip || node.canonical_key)}</text>
      </g>`;
  });

  divergences.forEach((divergence, index) => {
    markup += `
      <g class="divergence-note" transform="translate(${1100}, ${120 + index * 54})">
        <rect x="0" y="0" width="330" height="42" rx="12" fill="#fff7ed" stroke="#fb923c"></rect>
        <text x="14" y="18" class="divergence-title">${esc(divergence.divergence_type)}</text>
        <text x="14" y="34" class="divergence-text">${esc(divergence.summary)}</text>
      </g>`;
  });

  svg.innerHTML = markup;
  const items = [...edgeItems];
  svg.querySelectorAll("[data-kind='node'], [data-kind='edge']").forEach((el) => {
    const kind = el.getAttribute("data-kind");
    const id = el.getAttribute("data-id");
    const item = kind === "node"
      ? { kind, data: nodeById.get(id) }
      : { kind, data: edges.find((edge) => edge.edge_id === id) };
    if (!item.data) return;
    el.style.cursor = "pointer";
    el.addEventListener("click", () => {
      state.selected = item;
      renderDetail(item);
      svg.querySelectorAll(".selected").forEach((selectedEl) => selectedEl.classList.remove("selected"));
      el.classList.add("selected");
    });
    items.push(item);
  });
}

async function refresh() {
  setStatus("carregando...");
  try {
    const snapshot = await loadSnapshot();
    state.snapshot = snapshot;
    $("graphUid").textContent = snapshot.graph_uid || "-";
    $("sourceNode").textContent = snapshot.source_node || "-";
    $("schemaVersion").textContent = snapshot.schema_version || "-";
    $("createdAt").textContent = snapshot.created_at || "-";
    $("graphType").textContent = snapshot.graph_type || "-";
    renderSummary(snapshot);
    drawGraph(snapshot);
    setStatus("snapshot carregado");
    if (state.selected) renderDetail(state.selected);
  } catch (error) {
    setStatus("falha ao carregar");
    $("detailBox").textContent = error.message || String(error);
  }
}

$("reloadButton").addEventListener("click", refresh);
refresh();
