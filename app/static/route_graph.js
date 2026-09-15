const state = {
  auth: { authenticated: false, username: null, role: null, permissions: [] },
  services: [],
  graph: null,
  selectedService: "all",
  viewMode: "all",
  collapsedClusters: new Set(),
  cy: null,
  selectedDetail: null,
};

const CLUSTER_ORDER = [
  "local",
  "cpe_onu",
  "provider_private",
  "provider_public_edge",
  "transit",
  "cdn_cloud",
  "ptt_ix",
  "destination",
  "unknown",
];

const CLUSTER_COLORS = {
  local: "#1d4ed8",
  cpe_onu: "#0f766e",
  provider_private: "#2563eb",
  provider_public_edge: "#c2410c",
  transit: "#475569",
  cdn_cloud: "#0ea5e9",
  ptt_ix: "#7c3aed",
  destination: "#111827",
  unknown: "#6b7280",
};

const PRIVATE_CLUSTER_IDS = new Set(["local", "cpe_onu", "provider_private", "provider_public_edge"]);
const EDGE_LABELS = {
  lan_to_cpe: "Rede local -> CPE/ONU",
  cpe_to_provider_private: "CPE/ONU -> operadora privada",
  provider_private_to_provider_private: "Operadora privada interna",
  provider_private_to_public_edge: "Operadora privada -> borda pública",
  public_edge_to_transit: "Borda pública -> trânsito",
  transit_to_cdn: "Trânsito -> CDN/Cloud",
  cdn_to_destination: "CDN/Cloud -> destino",
  same_ip_repeated_next_hop: "Mesmo IP repetido",
  unknown_transition: "Transição não classificada",
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

function getBgpEvidence(data) {
  if (!data) return null;
  if (data.bgp_evidence && typeof data.bgp_evidence === "object") {
    return data.bgp_evidence;
  }
  if (data.bgp_matched_prefix || data.bgp_origin_asn || data.bgp_source) {
    return {
      matched_prefix: data.bgp_matched_prefix || null,
      origin_asn: data.bgp_origin_asn || null,
      as_path: data.bgp_as_path || null,
      source: data.bgp_source || null,
      lookup_ip: data.bgp_lookup_ip || data.ip || null,
      confidence: data.bgp_confidence || null,
      attribution_scope: data.bgp_attribution_scope || null,
    };
  }
  return null;
}

function renderBgpDetail(data) {
  const evidence = getBgpEvidence(data);
  const context = data?.bgp_context && typeof data.bgp_context === "object" ? data.bgp_context : null;
  if (!evidence && !context) return "";
  if (context) {
    const status = context.status || "private_ip_no_direct_bgp_attribution";
    const reason = context.reason || "private_or_cgnat_ip";
    return `
      <div class="detail-block">
        <strong>BGP</strong>
        <p>IP privado/CGNAT: sem atribuição BGP direta.</p>
        <div class="detail-grid">
          <div class="kv"><strong>Status</strong><span>${html(status)}</span></div>
          <div class="kv"><strong>Motivo</strong><span>${html(reason)}</span></div>
        </div>
      </div>
    `;
  }
  return `
    <div class="detail-block">
      <strong>BGP LPM</strong>
      <div class="detail-grid">
        <div class="kv"><strong>Prefixo</strong><span>${html(evidence.matched_prefix)}</span></div>
        <div class="kv"><strong>ASN origem</strong><span>${html(evidence.origin_asn ? `AS${evidence.origin_asn}` : "-")}</span></div>
        <div class="kv"><strong>AS path</strong><span>${html(evidence.as_path)}</span></div>
        <div class="kv"><strong>Fonte</strong><span>${html(evidence.source)}</span></div>
        <div class="kv"><strong>Confiança</strong><span>${html(evidence.confidence)}</span></div>
      </div>
    </div>
  `;
}

function toast(message) {
  const el = $("toast");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2600);
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

function setAuthBadge(textValue, className) {
  const el = $("auth-status");
  if (!el) return;
  el.textContent = textValue;
  el.className = className;
}

function isAdmin() {
  return state.auth?.role === "admin";
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
  } catch {
    state.auth = { authenticated: false, username: null, role: null, permissions: [] };
    setAuthBadge("Falha ao verificar autenticação", "auth-badge auth-badge-error anonymous");
  }
}

function normalizeArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item));
}

function serviceMatches(node) {
  if (state.selectedService === "all") return true;
  const services = normalizeArray(node.services_seen);
  return services.includes(state.selectedService);
}

function currentModeLabel() {
  if (state.viewMode === "service") return "Apenas serviço selecionado";
  if (state.viewMode === "privatePath") return "Caminho privado destacado";
  if (state.viewMode === "unknownOnly") return "Somente unknown";
  if (state.viewMode === "privateOnly") return "Somente private";
  return "Mostrar tudo";
}

function matchesMode(node) {
  if (state.viewMode === "service") {
    if (state.selectedService === "all") return false;
    return serviceMatches(node);
  }
  if (state.viewMode === "unknownOnly") return node.is_unknown;
  if (state.viewMode === "privateOnly") return node.is_private || PRIVATE_CLUSTER_IDS.has(node.cluster);
  return true;
}

function isPrivatePathNode(node) {
  return PRIVATE_CLUSTER_IDS.has(node.cluster) || node.is_private;
}

function edgeMatches(edge) {
  if (state.selectedService === "all") return true;
  const services = normalizeArray(edge.services);
  return services.includes(state.selectedService);
}

function edgeClassList(edge) {
  const transition = String(edge.transition_type || "unknown_transition");
  const classes = [];
  if (transition === "unknown_transition") {
    classes.push("is-unknown-edge");
  }
  if (
    transition.includes("lan_to_cpe") ||
    transition.includes("cpe_to_provider_private") ||
    transition.includes("provider_private_to_provider_private") ||
    transition.includes("same_ip_repeated_next_hop")
  ) {
    classes.push("edge-private");
  }
  if (transition.includes("provider_private_to_public_edge") || transition.includes("public_edge_to_transit")) {
    classes.push("edge-public");
  }
  if (transition.includes("transit_to_cdn") || transition.includes("cdn_to_destination")) {
    classes.push("edge-cdn");
  }
  return classes;
}

function nodeVisible(node) {
  if (!matchesMode(node)) return false;
  if (state.collapsedClusters.has(node.cluster)) return false;
  return true;
}

function edgeVisible(edge, visibleNodeIds) {
  if (!edgeMatches(edge)) return false;
  if (!visibleNodeIds.has(edge.source) || !visibleNodeIds.has(edge.target)) return false;
  if (state.viewMode === "unknownOnly" && edge.transition_type !== "unknown_transition") return false;
  return true;
}

function renderSummaryCards() {
  const summary = state.graph?.summary || {};
  const cards = [
    ["Serviços", summary.services_count || 0, "serviços seedados"],
    ["Nodes", summary.nodes_count || 0, "hops inventariados"],
    ["Edges", summary.edges_count || 0, "transições aprendidas"],
    ["Private", summary.private_hops_count || 0, "hops privados"],
    ["Unknown", summary.unknown_hops_count || 0, "hops sem confiança"],
    ["ASNs", summary.asn_count || 0, "ASNs distintos"],
  ];
  $("summaryCards").innerHTML = cards
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

function renderServiceSelect() {
  const options = [`<option value="all">Todos os serviços</option>`]
    .concat(
      state.services.map(
        (service) =>
          `<option value="${html(service.service_slug)}">${html(service.display_name || service.service_slug)}</option>`,
      ),
    )
    .join("");
  $("serviceSelect").innerHTML = options;
  $("serviceSelect").value = state.selectedService;
}

function renderModeButtons() {
  [
    ["showAllButton", "all"],
    ["serviceOnlyButton", "service"],
    ["privatePathButton", "privatePath"],
    ["unknownOnlyButton", "unknownOnly"],
    ["privateOnlyButton", "privateOnly"],
  ].forEach(([id, mode]) => {
    const button = $(id);
    if (!button) return;
    button.classList.toggle("active", state.viewMode === mode);
  });
}

function renderServiceHint() {
  const hint = $("serviceHint");
  if (!hint) return;
  const selected = state.selectedService;
  const graph = state.graph || {};
  const serviceEvidence = selected === "all"
    ? true
    : (graph.nodes || []).some((node) => normalizeArray(node.services_seen).includes(selected));
  if (state.viewMode === "service" && selected === "all") {
    hint.innerHTML = "Escolha um serviço no seletor acima e depois clique em <strong>Apenas serviço selecionado</strong>.";
    return;
  }
  if (state.viewMode === "service" && selected !== "all" && !serviceEvidence) {
    hint.innerHTML = "Este serviço está seedado, mas ainda não possui rota observada no inventário.";
    return;
  }
  if (state.viewMode === "service" && selected !== "all") {
    hint.innerHTML = `Mostrando apenas <strong>${html(selected)}</strong>. Clique no nó para abrir o contexto do hop.`;
    return;
  }
  if (state.viewMode === "privateOnly") {
    hint.innerHTML = "Mostrando somente nós privados do caminho observado.";
    return;
  }
  if (state.viewMode === "unknownOnly") {
    hint.innerHTML = "Mostrando apenas hops ainda sem classificação suficiente.";
    return;
  }
  if (state.viewMode === "privatePath") {
    hint.innerHTML = "Caminho privado destacado para facilitar leitura operacional. Nós fora do trecho privado ficam esmaecidos.";
    return;
  }
  hint.innerHTML = "Visão global do grafo. Use os botões para isolar um serviço ou destacar trechos privados.";
}

function renderClustersList() {
  const clusters = state.graph?.clusters || [];
  $("clustersList").innerHTML = clusters
    .slice()
    .sort((a, b) => CLUSTER_ORDER.indexOf(a.id) - CLUSTER_ORDER.indexOf(b.id))
    .map((cluster) => {
      const collapsed = state.collapsedClusters.has(cluster.id);
      return `
        <article class="cluster-card cluster-card--${html(cluster.id)}" data-cluster="${html(cluster.id)}">
          <header>
            <div>
              <div class="title">${html(cluster.label)}</div>
              <div class="muted">${html(cluster.id)}</div>
            </div>
            <div class="count">${html(cluster.node_count || 0)}</div>
          </header>
          <div class="desc">${html(cluster.description || "")}</div>
          <div class="actions">
            <button type="button" class="secondary" data-toggle-cluster="${html(cluster.id)}">
              ${collapsed ? "Expandir" : "Colapsar"}
            </button>
          </div>
        </article>
      `;
    })
    .join("");

  $("clustersList").querySelectorAll("[data-toggle-cluster]").forEach((button) => {
    button.addEventListener("click", () => {
      const clusterId = button.dataset.toggleCluster;
      if (state.collapsedClusters.has(clusterId)) {
        state.collapsedClusters.delete(clusterId);
      } else {
        state.collapsedClusters.add(clusterId);
      }
      renderClustersList();
      renderGraph().catch((error) => toast(error.message));
    });
  });
}

function buildElements() {
  const graph = state.graph || {};
  const clusters = graph.clusters || [];
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const elements = [];
  const visibleNodeIds = new Set();
  const visibleClusterIds = new Set();

  nodes.forEach((node) => {
    const visible = nodeVisible(node);
    if (visible) {
      visibleNodeIds.add(node.id);
      visibleClusterIds.add(node.cluster);
    }
    elements.push({
      group: "nodes",
      data: {
        ...node,
        parent: `cluster:${node.cluster}`,
        color: CLUSTER_COLORS[node.cluster] || CLUSTER_COLORS.unknown,
      },
      classes: [
        `node-${node.cluster}`,
        node.cluster === "destination" ? "node-destination" : "",
        node.is_private ? "is-private" : "",
        node.is_unknown ? "is-unknown" : "",
        node.is_ptt_candidate ? "is-ptt-candidate" : "",
        node.is_common_hop ? "is-common" : "",
        state.viewMode === "privatePath" && !isPrivatePathNode(node) ? "is-dimmed" : "",
        state.viewMode === "privatePath" && isPrivatePathNode(node) ? "is-highlight-private" : "",
        visible ? "" : "is-hidden",
      ]
        .filter(Boolean)
        .join(" "),
    });
  });

  clusters.forEach((cluster) => {
    if ((state.viewMode === "service" || state.viewMode === "unknownOnly" || state.viewMode === "privateOnly") && !visibleClusterIds.has(cluster.id)) {
      return;
    }
    if (state.viewMode !== "all" && state.viewMode !== "privatePath" && !visibleClusterIds.has(cluster.id)) {
      return;
    }
    elements.push({
      group: "nodes",
      data: {
        id: `cluster:${cluster.id}`,
        label: `${cluster.label}\n(${cluster.node_count || 0})`,
        isCluster: true,
        clusterId: cluster.id,
        nodeCount: cluster.node_count || 0,
        description: cluster.description || "",
        color: CLUSTER_COLORS[cluster.id] || CLUSTER_COLORS.unknown,
      },
      classes: `cluster-node cluster-${cluster.id}`,
    });
  });

  edges.forEach((edge) => {
    if (!edgeVisible(edge, visibleNodeIds)) return;
    const edgeClasses = edgeClassList(edge);
    elements.push({
      group: "edges",
      data: {
        ...edge,
        id: edge.id,
        source: edge.source,
        target: edge.target,
      },
      classes: [
        ...edgeClasses,
        state.viewMode === "privatePath" && !edgeClasses.includes("edge-private") ? "is-dimmed" : "",
        state.viewMode === "privatePath" && edgeClasses.includes("edge-private") ? "is-highlight-private" : "",
      ]
        .filter(Boolean)
        .join(" "),
    });
  });

  return elements;
}

function renderGraphStatus() {
  const graph = state.graph || {};
  const summary = graph.summary || {};
  const counts = state.cy
    ? {
        nodes: state.cy.nodes().filter((node) => !node.hasClass("is-hidden") && !node.data("isCluster")).length,
        edges: state.cy.edges().filter((edge) => edge.visible()).length,
      }
    : { nodes: 0, edges: 0 };
  const bits = [
    currentModeLabel(),
    state.selectedService === "all" ? "serviço:todos" : `serviço:${state.selectedService}`,
    `global=${summary.nodes_count || 0}n/${summary.edges_count || 0}e`,
    `visíveis=${counts.nodes}n/${counts.edges}e`,
  ];
  $("graphStatus").textContent = bits.join(" · ");
}

function getBreadthRoots(elements) {
  const nodeIds = new Set(
    (elements || [])
      .filter(
        (element) =>
          element.group === "nodes" &&
          !element.data.isCluster &&
          !String(element.data.id || "").startsWith("cluster:") &&
          !String(element.classes || "").includes("is-hidden"),
      )
      .map((element) => element.data.id),
  );
  const incoming = new Map([...nodeIds].map((id) => [id, 0]));
  (elements || [])
    .filter((element) => element.group === "edges")
    .forEach((element) => {
      const target = element.data.target;
      if (incoming.has(target)) {
        incoming.set(target, (incoming.get(target) || 0) + 1);
      }
    });
  const roots = [...incoming.entries()].filter(([, count]) => count === 0).map(([id]) => id);
  return roots.length ? roots : [...nodeIds];
}

function renderGraph() {
  if (!window.cytoscape) {
    throw new Error("Cytoscape.js não carregou.");
  }
  if (state.cy) {
    state.cy.destroy();
  }
  const elements = buildElements();
  state.cy = window.cytoscape({
    container: $("graphCanvas"),
    elements,
    layout: {
      name: "breadthfirst",
      directed: true,
      roots: getBreadthRoots(elements),
      circle: false,
      spacingFactor: 1.55,
      avoidOverlap: true,
      nodeDimensionsIncludeLabels: true,
      padding: 42,
      animate: false,
      fit: true,
      direction: "rightward",
    },
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          color: "#102030",
          "font-size": 11,
          "font-weight": 700,
          "text-valign": "center",
          "text-halign": "center",
          "background-color": "#ffffff",
          "border-width": 2,
          "border-color": "data(color)",
          width: 38,
          height: 38,
          "text-outline-color": "#ffffff",
          "text-outline-width": 2,
          "text-wrap": "wrap",
          "text-max-width": 96,
          "transition-property": "opacity, background-color, border-color, width, height",
          "transition-duration": "0.18s",
        },
      },
      { selector: "node.is-private", style: { "background-color": "#edf4ff" } },
      { selector: "node.is-unknown", style: { "background-color": "#f3f5f8", "border-style": "dashed" } },
      { selector: "node.is-ptt-candidate", style: { "background-color": "#f5ecff", "border-color": "#7c3aed" } },
      { selector: "node.is-common", style: { "border-width": 3 } },
      { selector: "node.is-dimmed", style: { opacity: 0.18 } },
      { selector: "node.is-highlight-private", style: { opacity: 1, "border-width": 3 } },
      { selector: "node.node-local", style: { "background-color": "rgba(29,78,216,0.14)", "border-color": "#1d4ed8" } },
      { selector: "node.node-cpe_onu", style: { "background-color": "rgba(15,118,110,0.14)", "border-color": "#0f766e" } },
      { selector: "node.node-provider_private", style: { "background-color": "rgba(37,99,235,0.14)", "border-color": "#2563eb" } },
      { selector: "node.node-provider_public_edge", style: { "background-color": "rgba(194,65,12,0.14)", "border-color": "#c2410c" } },
      { selector: "node.node-transit", style: { "background-color": "rgba(71,85,105,0.14)", "border-color": "#475569" } },
      { selector: "node.node-cdn_cloud", style: { "background-color": "rgba(14,165,233,0.14)", "border-color": "#0ea5e9" } },
      { selector: "node.node-ptt_ix", style: { "background-color": "rgba(124,58,237,0.14)", "border-color": "#7c3aed" } },
      { selector: "node.node-destination", style: { shape: "diamond", "background-color": "rgba(17,24,39,0.14)", "border-color": "#111827" } },
      { selector: "node.node-unknown", style: { "background-color": "rgba(107,114,128,0.10)", "border-color": "#6b7280" } },
      {
        selector: "node.is-hidden",
        style: {
          display: "none",
        },
      },
      {
        selector: "node.cluster-node",
        style: {
          shape: "round-rectangle",
          "background-opacity": 0.06,
          "border-style": "dashed",
          "border-width": 2,
          "font-size": 12,
          "font-weight": 700,
          "text-valign": "top",
          "text-halign": "center",
          padding: 20,
          width: "mapData(nodeCount, 0, 20, 130, 260)",
          height: "mapData(nodeCount, 0, 20, 92, 200)",
          "min-width": 130,
          "min-height": 92,
          "text-margin-y": -32,
          "text-outline-color": "#ffffff",
          "text-outline-width": 2,
        },
      },
      { selector: "node.cluster-local", style: { "background-color": "rgba(29,78,216,0.10)", "border-color": "#1d4ed8" } },
      { selector: "node.cluster-cpe_onu", style: { "background-color": "rgba(15,118,110,0.10)", "border-color": "#0f766e" } },
      { selector: "node.cluster-provider_private", style: { "background-color": "rgba(37,99,235,0.10)", "border-color": "#2563eb" } },
      { selector: "node.cluster-provider_public_edge", style: { "background-color": "rgba(194,65,12,0.10)", "border-color": "#c2410c" } },
      { selector: "node.cluster-transit", style: { "background-color": "rgba(71,85,105,0.08)", "border-color": "#475569" } },
      { selector: "node.cluster-cdn_cloud", style: { "background-color": "rgba(14,165,233,0.10)", "border-color": "#0ea5e9" } },
      { selector: "node.cluster-ptt_ix", style: { "background-color": "rgba(124,58,237,0.10)", "border-color": "#7c3aed" } },
      { selector: "node.cluster-destination", style: { "shape": "diamond", "background-color": "rgba(17,24,39,0.10)", "border-color": "#111827" } },
      { selector: "node.cluster-unknown", style: { "background-color": "rgba(107,114,128,0.08)", "border-color": "#6b7280" } },
      { selector: "node.node-destination", style: { "shape": "diamond", "width": 42, height: 42 } },
      {
        selector: "edge",
        style: {
          width: 2.4,
          "curve-style": "bezier",
          "target-arrow-shape": "triangle",
          "line-color": "#94a3b8",
          "target-arrow-color": "#94a3b8",
          opacity: 0.72,
          "arrow-scale": 1.05,
          "transition-property": "line-color, target-arrow-color, opacity, width",
          "transition-duration": "0.18s",
        },
      },
      { selector: "edge.is-unknown-edge", style: { "line-style": "dashed", "line-color": "#94a3b8", "target-arrow-color": "#94a3b8" } },
      { selector: "edge.edge-private", style: { "line-color": "#2563eb", "target-arrow-color": "#2563eb" } },
      { selector: "edge.edge-public", style: { "line-color": "#c2410c", "target-arrow-color": "#c2410c" } },
      { selector: "edge.edge-cdn", style: { "line-color": "#0ea5e9", "target-arrow-color": "#0ea5e9" } },
      { selector: "edge.is-dimmed", style: { opacity: 0.12 } },
      { selector: "edge.is-highlight-private", style: { opacity: 0.96, width: 3.5 } },
      {
        selector: ":selected",
        style: {
          "border-width": 3,
          "border-color": "#1f5eff",
          "line-color": "#1f5eff",
          "target-arrow-color": "#1f5eff",
          "background-color": "#eff5ff",
        },
      },
    ],
  });

  state.cy.on("tap", "node", (event) => {
    const node = event.target;
    if (node.data("isCluster")) {
      const clusterId = node.data("clusterId");
      if (state.collapsedClusters.has(clusterId)) {
        state.collapsedClusters.delete(clusterId);
      } else {
        state.collapsedClusters.add(clusterId);
      }
      renderGraph().catch((error) => toast(error.message));
      return;
    }
    const ip = node.data("ip");
    const href = `/route-graph/hop/${encodeURIComponent(ip)}`;
    window.open(href, "_blank", "noopener,noreferrer");
    renderNodeDetail(node.data()).catch((error) => toast(error.message));
  });

  state.cy.on("tap", "edge", (event) => {
    renderEdgeDetail(event.target.data());
  });

  state.cy.on("tap", (event) => {
    if (event.target === state.cy) {
      state.selectedDetail = null;
      $("detailBox").textContent = "Selecione um elemento do grafo.";
    }
  });

  const visibleNodes = state.cy.nodes().filter((node) => !node.hasClass("is-hidden") && !node.data("isCluster"));
  if (visibleNodes.length) {
    state.cy.fit(visibleNodes, 24);
  } else {
    state.cy.fit();
  }
  state.cy.resize();
  renderGraphStatus();
  renderModeButtons();
  renderServiceHint();
  if (state.viewMode === "service" && state.selectedService !== "all" && !visibleNodes.length) {
    renderEmptyServiceMessage();
  }
}

function renderClusterDetail(clusterId) {
  const cluster = (state.graph?.clusters || []).find((item) => item.id === clusterId);
  if (!cluster) return "<p>Cluster não encontrado.</p>";
  return `
    <div class="detail-grid">
      <div class="kv"><strong>Cluster</strong><span>${html(cluster.label)}</span></div>
      <div class="kv"><strong>ID</strong><span>${html(cluster.id)}</span></div>
      <div class="kv"><strong>Nós</strong><span>${html(cluster.node_count || 0)}</span></div>
      <div class="kv"><strong>Tipo</strong><span>${html(cluster.type)}</span></div>
      <div class="kv"><strong>Confidence</strong><span>${html(cluster.confidence)}</span></div>
    </div>
    <div class="detail-block">
      <strong>Descrição</strong>
      <p>${html(cluster.description || "")}</p>
    </div>
  `;
}

function nodeOperationalExplanation(node, classification = {}) {
  if (classification.is_unknown || node.is_unknown) {
    return "Hop ainda não classificado. Pode faltar ASN, reverse DNS, evidência suficiente ou enriquecimento.";
  }
  if (node.cluster === "local") {
    return "Rede/host sob nosso lado. Normalmente é o ponto local antes da saída para acesso.";
  }
  if (node.cluster === "cpe_onu") {
    return "CPE/ONU ou equipamento de acesso. Marca a transição entre o ambiente local e o provedor.";
  }
  if (node.cluster === "provider_private") {
    return "IP privado observado no traceroute. A posição no caminho e os vizinhos sugerem rede interna da operadora.";
  }
  if (node.cluster === "provider_public_edge") {
    return "Possível borda pública da operadora. Normalmente é o primeiro salto público depois do trecho privado.";
  }
  if (node.cluster === "cdn_cloud") {
    return "Hop associado a CDN/cloud conforme ASN, organização, reverse DNS ou serviço observado.";
  }
  if (node.cluster === "ptt_ix") {
    return "Candidato a PTT/IX. A evidência atual é suficiente para suspeita, mas não para confirmação direta.";
  }
  if (node.cluster === "destination") {
    return "Destino final do serviço ou hop resolvido como alvo final do caminho.";
  }
  return "Hop classificado a partir da posição no caminho, das observações e do enriquecimento disponível.";
}

function edgeOperationalExplanation(transitionType) {
  return (
    {
      lan_to_cpe: "Transição da rede local para CPE/ONU ou equipamento de acesso.",
      cpe_to_provider_private: "Transição do acesso local para a rede privada da operadora.",
      provider_private_to_provider_private: "Trecho interno privado da operadora observado no traceroute.",
      provider_private_to_public_edge: "Possível saída da rede privada da operadora para borda pública.",
      public_edge_to_transit: "Da borda pública para um segmento de trânsito.",
      transit_to_cdn: "Transição de trânsito para CDN/cloud.",
      cdn_to_destination: "Transição da CDN/cloud para o destino final.",
      same_ip_repeated_next_hop: "Mesmo IP repetido em hops consecutivos, indicando ausência de avanço claro.",
      unknown_transition: "Transição observada, mas ainda sem classificação suficiente.",
    }[transitionType] || "Transição observada no caminho, ainda sem narrativa específica."
  );
}

function renderEdgeDetail(edge) {
  const source = String(edge.source || "").replace(/^hop:/, "");
  const target = String(edge.target || "").replace(/^hop:/, "");
  $("detailBox").innerHTML = `
    <div class="detail-block">
      <strong>Leitura operacional</strong>
      <p>${html(edgeOperationalExplanation(edge.transition_type))}</p>
    </div>
    <div class="detail-grid">
      <div class="kv"><strong>Transição</strong><span>${html(edge.transition_type)}</span></div>
      <div class="kv"><strong>Origem</strong><span>${html(source)}</span></div>
      <div class="kv"><strong>Destino</strong><span>${html(target)}</span></div>
      <div class="kv"><strong>Serviços</strong><span>${html(edge.services || [])}</span></div>
      <div class="kv"><strong>Confiança</strong><span>${html(edge.confidence)}</span></div>
      <div class="kv"><strong>Obs.</strong><span>${html(edge.observations_count || 0)}</span></div>
      <div class="kv"><strong>RTT delta</strong><span>${html(edge.rtt_delta_ms)}</span></div>
      <div class="kv"><strong>Primeiro visto</strong><span>${html(edge.first_seen_at)}</span></div>
      <div class="kv"><strong>Último visto</strong><span>${html(edge.last_seen_at)}</span></div>
    </div>
    <div class="detail-block">
      <strong>Metadata seguro</strong>
      <pre>${html(JSON.stringify(edge.metadata || {}, null, 2))}</pre>
    </div>
  `;
}

async function renderNodeDetail(node) {
  const context = await api(`/route-graph/hop/${encodeURIComponent(node.ip)}`);
  const previous = normalizeArray(context.previous_hops);
  const next = normalizeArray(context.next_hops);
  const classification = context.classification || {};
  $("detailBox").innerHTML = `
    <div class="detail-block">
      <strong>Leitura operacional</strong>
      <p>${html(nodeOperationalExplanation(node, classification))}</p>
    </div>
    <div class="detail-grid">
      <div class="kv"><strong>IP</strong><span>${html(node.ip)}</span></div>
      <div class="kv"><strong>Cluster</strong><span>${html(node.cluster)}</span></div>
      <div class="kv"><strong>Categoria</strong><span>${html(node.category)}</span></div>
      <div class="kv"><strong>Papel provável</strong><span>${html(node.role)}</span></div>
      <div class="kv"><strong>Confiança</strong><span>${html(node.confidence)}</span></div>
      <div class="kv"><strong>ASN</strong><span>${html(node.asn)}</span></div>
      <div class="kv"><strong>Org.</strong><span>${html(node.organization)}</span></div>
      <div class="kv"><strong>País</strong><span>${html(node.country)}</span></div>
      <div class="kv"><strong>Observações</strong><span>${html(node.observations_count || 0)}</span></div>
      <div class="kv"><strong>Primeiro visto</strong><span>${html(node.first_seen_at)}</span></div>
      <div class="kv"><strong>Último visto</strong><span>${html(node.last_seen_at)}</span></div>
      <div class="kv"><strong>Common hop</strong><span>${html(node.is_common_hop ? "sim" : "não")}</span></div>
    </div>
    <div class="detail-block">
      <strong>Anterior / posterior</strong>
      <div class="detail-grid">
        <div class="kv"><strong>Previous hops</strong><span>${html(previous)}</span></div>
        <div class="kv"><strong>Next hops</strong><span>${html(next)}</span></div>
      </div>
    </div>
    <div class="detail-block">
      <strong>Serviços</strong>
      <div>${normalizeArray(node.services_seen).map((item) => `<span class="badge">${html(item)}</span>`).join(" ") || "Nenhum."}</div>
    </div>
    ${renderBgpDetail(node)}
    <div class="detail-block">
      <strong>Classificação</strong>
      <div class="detail-grid">
        <div class="kv"><strong>Unknown</strong><span>${html(classification.is_unknown ? "sim" : "não")}</span></div>
        <div class="kv"><strong>PTT candidate</strong><span>${html(classification.is_ptt_candidate ? "sim" : "não")}</span></div>
        <div class="kv"><strong>Private</strong><span>${html(classification.is_private ? "sim" : "não")}</span></div>
        <div class="kv"><strong>Common</strong><span>${html(classification.is_common_hop ? "sim" : "não")}</span></div>
      </div>
    </div>
    <div class="detail-block">
      <strong>Sample paths</strong>
      <pre>${html(JSON.stringify(context.sample_paths || [], null, 2))}</pre>
    </div>
    <div class="detail-block">
      <strong>Metadata seguro</strong>
      <pre>${html(JSON.stringify(node.metadata || {}, null, 2))}</pre>
    </div>
    <div class="detail-block">
      <a class="ghost-link" href="/route-graph/hop/${encodeURIComponent(node.ip)}" target="_blank" rel="noopener noreferrer">Abrir contexto do hop</a>
    </div>
  `;
}

function renderDetailPlaceholder() {
  $("detailBox").textContent = "Selecione um elemento do grafo.";
}

function renderEmptyServiceMessage() {
  $("detailBox").innerHTML = `
    <div class="detail-block">
      <strong>Sem evidência observada</strong>
      <p>Este serviço está seedado, mas ainda não possui rota observada no inventário.</p>
    </div>
  `;
}

async function loadServices() {
  state.services = await api("/external-routes/services");
  renderServiceSelect();
}

async function loadGraph() {
  state.graph = await api("/route-graph/global");
  renderSummaryCards();
  renderClustersList();
  renderModeButtons();
  renderServiceHint();
  renderGraph();
  renderDetailPlaceholder();
}

async function refreshGraph() {
  await loadGraph();
}

function wireControls() {
  $("reloadButton").addEventListener("click", () => refreshGraph().catch((error) => toast(error.message)));
  $("resetViewButton").addEventListener("click", () => {
    state.selectedService = "all";
    state.viewMode = "all";
    state.collapsedClusters = new Set();
    state.selectedDetail = null;
    $("serviceSelect").value = "all";
    renderClustersList();
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
    renderDetailPlaceholder();
  });
  $("serviceSelect").addEventListener("change", (event) => {
    state.selectedService = event.target.value || "all";
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("showAllButton").addEventListener("click", () => {
    state.viewMode = "all";
    state.selectedService = "all";
    $("serviceSelect").value = "all";
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("serviceOnlyButton").addEventListener("click", () => {
    state.viewMode = "service";
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("privatePathButton").addEventListener("click", () => {
    state.viewMode = "privatePath";
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("unknownOnlyButton").addEventListener("click", () => {
    state.viewMode = "unknownOnly";
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("privateOnlyButton").addEventListener("click", () => {
    state.viewMode = "privateOnly";
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
  });
  $("resetVisualButton").addEventListener("click", () => {
    state.selectedService = "all";
    state.viewMode = "all";
    state.collapsedClusters = new Set();
    $("serviceSelect").value = "all";
    renderClustersList();
    renderModeButtons();
    renderServiceHint();
    renderGraph().catch((error) => toast(error.message));
    renderDetailPlaceholder();
  });
}

async function bootstrap() {
  await loadAuthStatus();
  wireControls();
  await loadServices();
  await loadGraph();
}

document.addEventListener("DOMContentLoaded", () => {
  bootstrap().catch((error) => {
    console.error(error);
    toast(error.message);
  });
});
