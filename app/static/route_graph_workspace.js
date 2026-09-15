const state = {
  auth: { authenticated: false, username: null, role: null },
  graph: null,
  loadStatus: "loading",
  renderStatus: "idle",
  errorSource: null,
  errorMessage: null,
  emptyReason: null,
  selectedCluster: "local",
  selectedService: "all",
  derivedServices: [],
  cy: null,
  selectedElement: null,
  collapsedClusters: new Set(),
  orphanNodes: [],
  focusPrivate: false,
  focusUnknown: false,
  symbolLibrary: null,
  symbolIndex: null,
  symbolLibraryPromise: null,
  ui: {
    sidebarVisible: true,
    detailsVisible: true,
    diagnosticVisible: false,
  },
};

const FALLBACK_CLUSTERS = [
  { id: "local", label: "Local", node_count: 0, confidence: "inferred", description: "Hops privados da rede local conhecida, antes da borda de acesso." },
  { id: "cpe_onu", label: "CPE/ONU", node_count: 0, confidence: "inferred", description: "Primeiro ou segundo hop privado após a origem local." },
  { id: "provider_private", label: "Operadora privada", node_count: 0, confidence: "inferred", description: "Hops privados observados após CPE/ONU e antes da borda pública." },
  { id: "provider_public_edge", label: "Borda pública", node_count: 0, confidence: "inferred", description: "Primeiro hop público depois de uma sequência privada." },
  { id: "transit", label: "Transit", node_count: 0, confidence: "inferred", description: "Hop público sem sinal forte de CDN, IX/PTT ou destino." },
  { id: "cdn_cloud", label: "CDN/Cloud", node_count: 0, confidence: "inferred", description: "Hop associado a CDN, provedor cloud ou edge conhecido." },
  { id: "ptt_ix", label: "PTT/IX", node_count: 0, confidence: "inferred", description: "Hop com sinal de IX/PTT em nome, organização ou contexto." },
  { id: "destination", label: "Destino", node_count: 0, confidence: "inferred", description: "Hop final do serviço conhecido ou target resolvido." },
  { id: "unknown", label: "Unknown", node_count: 0, confidence: "inferred", description: "Hop sem evidência suficiente para classificação mais forte." },
];

const CLUSTER_DESCRIPTIONS = {
  local: "Rede/host sob nosso lado",
  cpe_onu: "Saída local ou equipamento de acesso",
  provider_private: "IP privado observado no caminho",
  provider_public_edge: "Primeiro trecho público ou trânsito",
  transit: "Trânsito sem evidência forte de CDN/PTT",
  cdn_cloud: "CDN/cloud como Google, Cloudflare, Meta, Netflix",
  ptt_ix: "Candidato a ponto de troca",
  destination: "Alvo final do serviço",
  unknown: "Ainda sem classificação",
};

const FALLBACK_SYMBOL_LIBRARY = {
  version: "fallback-1.0.0",
  generated_by: "routebrain-js-fallback",
  icons: [
    { id: "RB-ICON-0010", key: "router", name: "Router", file: "/static/symbols/device/rb-icon-0010-router.svg" },
    { id: "RB-ICON-0020", key: "switch", name: "Switch", file: "/static/symbols/device/rb-icon-0020-switch.svg" },
    { id: "RB-ICON-0030", key: "firewall", name: "Firewall", file: "/static/symbols/device/rb-icon-0030-firewall.svg" },
    { id: "RB-ICON-0040", key: "server", name: "Server", file: "/static/symbols/device/rb-icon-0040-server.svg" },
    { id: "RB-ICON-0050", key: "cloud", name: "Cloud", file: "/static/symbols/device/rb-icon-0050-cloud.svg" },
    { id: "RB-ICON-0060", key: "cpe_onu", name: "CPE / ONU", file: "/static/symbols/device/rb-icon-0060-cpe-onu.svg" },
    { id: "RB-ICON-0070", key: "ptt_ix", name: "PTT / IX", file: "/static/symbols/device/rb-icon-0070-ptt-ix.svg" },
    { id: "RB-ICON-0080", key: "unknown", name: "Unknown", file: "/static/symbols/device/rb-icon-0080-unknown.svg" },
    { id: "RB-ICON-0090", key: "destination", name: "Destination", file: "/static/symbols/device/rb-icon-0090-destination.svg" },
    { id: "RB-ICON-0100", key: "provider_router", name: "Provider router", file: "/static/symbols/device/rb-icon-0100-provider-router.svg" },
    { id: "RB-ICON-0110", key: "local_gateway", name: "Local gateway", file: "/static/symbols/device/rb-icon-0110-local-gateway.svg" },
    { id: "RB-ICON-0120", key: "cdn_edge", name: "CDN edge", file: "/static/symbols/device/rb-icon-0120-cdn-edge.svg" },
  ],
  flags: [
    { id: "RB-FLAG-BR", key: "br", label: "BR", file: "/static/symbols/flags/br.svg", country_codes: ["BR"] },
    { id: "RB-FLAG-US", key: "us", label: "US", file: "/static/symbols/flags/us.svg", country_codes: ["US"] },
    { id: "RB-FLAG-UN", key: "unknown", label: "GL", file: "/static/symbols/flags/unknown.svg", country_codes: ["UN", "GLOBAL", "UNKNOWN"] },
  ],
  organizations: [
    { id: "RB-ORG-0010", key: "google", label: "Google", asn: [15169], organization_contains: ["Google"], symbol_type: "text_badge" },
    { id: "RB-ORG-0020", key: "cloudflare", label: "Cloudflare", asn: [13335], organization_contains: ["Cloudflare"], symbol_type: "text_badge" },
    { id: "RB-ORG-0030", key: "meta", label: "Meta", asn: [32934], organization_contains: ["Meta", "Facebook"], symbol_type: "text_badge" },
    { id: "RB-ORG-0040", key: "netflix", label: "Netflix", asn: [], organization_contains: ["Netflix"], symbol_type: "text_badge" },
    { id: "RB-ORG-0050", key: "akamai", label: "Akamai", asn: [16625, 20940], organization_contains: ["Akamai"], symbol_type: "text_badge" },
    { id: "RB-ORG-0060", key: "fastly", label: "Fastly", asn: [54113], organization_contains: ["Fastly"], symbol_type: "text_badge" },
    { id: "RB-ORG-0070", key: "amazon", label: "Amazon", asn: [14618, 16509], organization_contains: ["Amazon", "AWS"], symbol_type: "text_badge" },
    { id: "RB-ORG-0080", key: "microsoft", label: "Microsoft", asn: [8075], organization_contains: ["Microsoft", "Azure"], symbol_type: "text_badge" },
    { id: "RB-ORG-0090", key: "private_path", label: "Private path", asn: [], organization_contains: ["Private path"], symbol_type: "text_badge" },
    { id: "RB-ORG-0100", key: "unknown_org", label: "Unknown", asn: [], organization_contains: ["Unknown"], symbol_type: "text_badge" },
  ],
  states: [
    { id: "RB-STATE-0010", key: "private", label: "private", file: "/static/symbols/state/private.svg" },
    { id: "RB-STATE-0020", key: "unknown", label: "unknown", file: "/static/symbols/state/unknown.svg" },
    { id: "RB-STATE-0030", key: "inferred", label: "inferred", file: "/static/symbols/state/inferred.svg" },
    { id: "RB-STATE-0040", key: "confirmed", label: "confirmed", file: "/static/symbols/state/confirmed.svg" },
    { id: "RB-STATE-0050", key: "ptt_candidate", label: "ptt_candidate", file: "/static/symbols/state/ptt-candidate.svg" },
  ],
  role_mapping: {
    router: "RB-ICON-0010",
    edge_router: "RB-ICON-0010",
    transit_router: "RB-ICON-0010",
    switch: "RB-ICON-0020",
    aggregation_switch: "RB-ICON-0020",
    firewall: "RB-ICON-0030",
    security_gateway: "RB-ICON-0030",
    server: "RB-ICON-0040",
    host: "RB-ICON-0040",
    destination_host: "RB-ICON-0090",
    cloud: "RB-ICON-0050",
    cdn: "RB-ICON-0120",
    cloud_edge: "RB-ICON-0120",
    cpe: "RB-ICON-0060",
    onu: "RB-ICON-0060",
    access_device: "RB-ICON-0060",
    ptt: "RB-ICON-0070",
    ix: "RB-ICON-0070",
    peering_exchange: "RB-ICON-0070",
    destination: "RB-ICON-0090",
    target: "RB-ICON-0090",
    endpoint: "RB-ICON-0090",
    provider_router: "RB-ICON-0100",
    provider_edge: "RB-ICON-0100",
    provider_internal_transit_candidate: "RB-ICON-0100",
    gateway: "RB-ICON-0110",
    local_gateway: "RB-ICON-0110",
    edge_gateway: "RB-ICON-0110",
    cdn_edge: "RB-ICON-0120",
    cache_edge: "RB-ICON-0120",
    delivery_edge: "RB-ICON-0120",
    unknown: "RB-ICON-0080",
  },
  cluster_mapping: {
    local: "RB-ICON-0110",
    cpe_onu: "RB-ICON-0060",
    provider_private: "RB-ICON-0100",
    provider_public_edge: "RB-ICON-0100",
    transit: "RB-ICON-0010",
    cdn_cloud: "RB-ICON-0120",
    ptt_ix: "RB-ICON-0070",
    destination: "RB-ICON-0090",
    unknown: "RB-ICON-0080",
  },
  category_mapping: {
    private: "RB-ICON-0100",
    public: "RB-ICON-0010",
    destination: "RB-ICON-0090",
    cloud: "RB-ICON-0120",
    cdn: "RB-ICON-0120",
    access: "RB-ICON-0060",
    local: "RB-ICON-0110",
    security: "RB-ICON-0030",
    exchange: "RB-ICON-0070",
    interconnect: "RB-ICON-0070",
    hosted: "RB-ICON-0040",
    unknown: "RB-ICON-0080",
  },
};

function normalizeKey(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s/]+/g, "_")
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function buildSymbolIndex(library) {
  const iconById = new Map();
  const iconByKey = new Map();
  const flagById = new Map();
  const flagByKey = new Map();
  const orgById = new Map();
  const orgByKey = new Map();
  const stateById = new Map();
  const stateByKey = new Map();

  for (const icon of library.icons || []) {
    if (icon?.id) iconById.set(icon.id, icon);
    if (icon?.key) iconByKey.set(normalizeKey(icon.key), icon);
  }
  for (const flag of library.flags || []) {
    if (flag?.id) flagById.set(flag.id, flag);
    if (flag?.key) flagByKey.set(normalizeKey(flag.key), flag);
  }
  for (const org of library.organizations || []) {
    if (org?.id) orgById.set(org.id, org);
    if (org?.key) orgByKey.set(normalizeKey(org.key), org);
  }
  for (const stateDef of library.states || []) {
    if (stateDef?.id) stateById.set(stateDef.id, stateDef);
    if (stateDef?.key) stateByKey.set(normalizeKey(stateDef.key), stateDef);
  }

  return { iconById, iconByKey, flagById, flagByKey, orgById, orgByKey, stateById, stateByKey };
}

function getSymbolLibrary() {
  const library = state.symbolLibrary || FALLBACK_SYMBOL_LIBRARY;
  if (!state.symbolIndex) {
    state.symbolIndex = buildSymbolIndex(library);
  }
  return library;
}

function getSymbolById(category, id) {
  const library = getSymbolLibrary();
  const index = state.symbolIndex || buildSymbolIndex(library);
  const map = {
    icons: index.iconById,
    flags: index.flagById,
    organizations: index.orgById,
    states: index.stateById,
  }[category];
  return map?.get(id) || null;
}

function findIconFromMapping(candidateKeys, mapping) {
  const library = getSymbolLibrary();
  const index = state.symbolIndex || buildSymbolIndex(library);
  const normalizedCandidates = candidateKeys.map((value) => normalizeKey(value)).filter(Boolean);

  for (const candidate of normalizedCandidates) {
    const directId = mapping?.[candidate];
    if (directId) {
      const direct = getSymbolById("icons", directId);
      if (direct) return direct;
    }
  }

  const entries = Object.entries(mapping || {});
  for (const candidate of normalizedCandidates) {
    for (const [key, iconId] of entries) {
      if (!key) continue;
      if (candidate === key || candidate.includes(key) || key.includes(candidate)) {
        const resolved = getSymbolById("icons", iconId);
        if (resolved) return resolved;
      }
    }
  }

  return getSymbolById("icons", "RB-ICON-0080") || library.icons?.[0] || null;
}

function iconIdFromNode(node) {
  return node?.device_icon_id || node?.symbol_icon_id || null;
}

function loadSymbolLibrary() {
  if (state.symbolLibraryPromise) return state.symbolLibraryPromise;
  state.symbolLibraryPromise = (async () => {
    try {
      const response = await fetch("/static/symbols/index.json", {
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      state.symbolLibrary = payload && typeof payload === "object" ? payload : FALLBACK_SYMBOL_LIBRARY;
      state.symbolIndex = buildSymbolIndex(state.symbolLibrary);
      return state.symbolLibrary;
    } catch (error) {
      logWorkspaceWarning("fallback para symbol library em uso", error);
      state.symbolLibrary = FALLBACK_SYMBOL_LIBRARY;
      state.symbolIndex = buildSymbolIndex(state.symbolLibrary);
      return state.symbolLibrary;
    }
  })();
  return state.symbolLibraryPromise;
}

function resolveNodeDeviceIcon(node) {
  const library = getSymbolLibrary();
  const roleCandidates = [
    node?.role,
    node?.device_role,
    node?.role_key,
    node?.router_role,
    node?.category_role,
  ].filter(Boolean);
  const categoryCandidates = [
    node?.category,
    node?.node_category,
    node?.classification,
    node?.kind,
  ].filter(Boolean);
  const clusterCandidates = [node?.cluster].filter(Boolean);

  let icon = iconIdFromNode(node) ? getSymbolById("icons", iconIdFromNode(node)) : null;
  let source = icon ? "explicit" : "";

  if (!icon) {
    icon = findIconFromMapping(roleCandidates, library.role_mapping);
    source = "role";
  }
  if (!icon || icon.id === "RB-ICON-0080") {
    const categoryIcon = findIconFromMapping(categoryCandidates, library.category_mapping);
    if (categoryIcon && categoryIcon.id !== "RB-ICON-0080") {
      icon = categoryIcon;
      source = "category";
    }
  }
  if (!icon || icon.id === "RB-ICON-0080") {
    const clusterIcon = findIconFromMapping(clusterCandidates, library.cluster_mapping);
    if (clusterIcon && clusterIcon.id !== "RB-ICON-0080") {
      icon = clusterIcon;
      source = "cluster";
    }
  }
  if (!icon) {
    icon = getSymbolById("icons", "RB-ICON-0080") || library.icons?.find((item) => item.id === "RB-ICON-0080") || null;
    source = "fallback";
  }

  return {
    id: icon?.id || "RB-ICON-0080",
    key: icon?.key || "unknown",
    name: icon?.name || "Unknown",
    file: icon?.file || "/static/symbols/device/rb-icon-0080-unknown.svg",
    source,
    category: "device",
    description: icon?.description || "Fallback symbol",
  };
}

function resolveNodeOrgBadge(node) {
  const library = getSymbolLibrary();
  const orgs = library.organizations || [];
  const asnValues = Array.isArray(node?.asn) ? node.asn : [node?.asn].filter((value) => value !== null && value !== undefined && value !== "");
  const organizationText = String(node?.organization || node?.org || node?.org_name || "").trim();
  const reverseDnsText = String(node?.reverse_dns || node?.ptr || node?.dns_name || "").trim();

  for (const asnValue of asnValues) {
    const asnNumber = Number(asnValue);
    if (!Number.isFinite(asnNumber)) continue;
    const match = orgs.find((org) => Array.isArray(org.asn) && org.asn.includes(asnNumber));
    if (match) {
      return {
        id: match.id,
        key: match.key,
        label: match.label || match.name,
        symbol_type: match.symbol_type || "text_badge",
        official_logo: false,
        source: "asn",
      };
    }
  }

  const haystack = [organizationText, reverseDnsText].filter(Boolean).join(" ").toLowerCase();
  if (haystack) {
    for (const org of orgs) {
      const needles = [
        org.key,
        org.label,
        org.name,
        ...(Array.isArray(org.organization_contains) ? org.organization_contains : []),
      ].filter(Boolean);
      if (needles.some((needle) => haystack.includes(String(needle).toLowerCase()))) {
        return {
          id: org.id,
          key: org.key,
          label: org.label || org.name,
          symbol_type: org.symbol_type || "text_badge",
          official_logo: false,
          source: organizationText ? "organization" : "reverse_dns",
        };
      }
    }
  }

  if (node?.is_private) {
    const privateOrg = orgs.find((org) => org.key === "private_path") || orgs.find((org) => org.id === "RB-ORG-0090");
    if (privateOrg) {
      return {
        id: privateOrg.id,
        key: privateOrg.key,
        label: privateOrg.label || privateOrg.name,
        symbol_type: privateOrg.symbol_type || "text_badge",
        official_logo: false,
        source: "private",
      };
    }
  }

  const unknownOrg = orgs.find((org) => org.key === "unknown_org") || orgs.find((org) => org.id === "RB-ORG-0100");
  return {
    id: unknownOrg?.id || "RB-ORG-0100",
    key: unknownOrg?.key || "unknown_org",
    label: unknownOrg?.label || "Unknown",
    symbol_type: unknownOrg?.symbol_type || "text_badge",
    official_logo: false,
    source: "fallback",
  };
}

function resolveNodeFlag(node) {
  const library = getSymbolLibrary();
  const flags = library.flags || [];
  const candidates = [
    node?.country,
    node?.country_code,
    node?.countryCode,
    node?.location_country,
    node?.country_name,
    node?.countryName,
    node?.geo_country,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  const upperCandidates = candidates.map((value) => value.toUpperCase());

  for (const candidate of upperCandidates) {
    for (const flag of flags) {
      const codes = Array.isArray(flag.country_codes) ? flag.country_codes : [];
      const labels = [flag.label, flag.key, flag.name].filter(Boolean).map((value) => String(value).toUpperCase());
      if (codes.map((code) => String(code).toUpperCase()).includes(candidate) || labels.includes(candidate)) {
        return {
          id: flag.id,
          key: flag.key,
          label: flag.label || flag.name || candidate,
          file: flag.file,
          source: "country",
        };
      }
    }
  }

  const unknownFlag = flags.find((flag) => flag.key === "unknown") || flags.find((flag) => flag.id === "RB-FLAG-UN");
  return {
    id: unknownFlag?.id || "RB-FLAG-UN",
    key: unknownFlag?.key || "unknown",
    label: unknownFlag?.label || "GL",
    file: unknownFlag?.file || "/static/symbols/flags/unknown.svg",
    source: "fallback",
  };
}

function resolveNodeStateBadges(node) {
  const library = getSymbolLibrary();
  const badges = [];
  const pushState = (key) => {
    const stateDef = (library.states || []).find((entry) => entry.key === key || entry.id === key);
    if (!stateDef) return;
    if (badges.some((badge) => badge.key === stateDef.key)) return;
    badges.push({
      id: stateDef.id,
      key: stateDef.key,
      label: stateDef.label || stateDef.key,
      file: stateDef.file,
    });
  };

  if (node?.is_private) pushState("private");
  if (node?.is_unknown) pushState("unknown");
  if (node?.is_ptt_candidate) pushState("ptt_candidate");
  if (node?.confirmed || node?.is_confirmed || node?.confidence === "confirmed") pushState("confirmed");
  if (!badges.some((badge) => badge.key === "confirmed") && (node?.cluster || node?.role || node?.category || node?.services_seen?.length)) {
    pushState("inferred");
  }
  if (!badges.length && !node?.is_unknown) {
    pushState("inferred");
  }

  return badges;
}

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "-")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getRoot() {
  return $("workspaceRoot") || document.body;
}

function isMobileView() {
  return window.matchMedia && window.matchMedia("(max-width: 980px)").matches;
}

function setAuthBadge(textValue, className) {
  const badge = $("authBadge");
  if (!badge) return;
  badge.textContent = textValue;
  badge.className = className;
}

function setWorkspaceStatus(textValue) {
  const el = $("workspaceStatus");
  if (el) el.textContent = textValue;
}

function syncBodyState() {
  document.body.classList.toggle("workspace-loading", state.loadStatus === "loading");
  document.body.classList.toggle("workspace-error", state.loadStatus === "error" || state.renderStatus === "error");
}

function syncShellState() {
  const root = getRoot();
  const mobile = isMobileView();
  root.classList.toggle("sidebar-collapsed", !mobile && !state.ui.sidebarVisible);
  root.classList.toggle("details-collapsed", !mobile && !state.ui.detailsVisible);
  root.classList.toggle("mobile-clusters-open", mobile && state.ui.sidebarVisible);
  root.classList.toggle("mobile-details-open", mobile && state.ui.detailsVisible);
  root.classList.toggle("fullscreen-mode", Boolean(document.fullscreenElement));

  const buttonMap = [
    ["clustersToggleButton", state.ui.sidebarVisible],
    ["detailsToggleButton", state.ui.detailsVisible],
    ["privateToggleButton", state.focusPrivate],
    ["unknownToggleButton", state.focusUnknown],
  ];
  buttonMap.forEach(([id, pressed]) => {
    const button = $(id);
    if (button) button.setAttribute("aria-pressed", pressed ? "true" : "false");
  });
}

function setWorkspaceError(source, message) {
  state.errorSource = source;
  state.errorMessage = message;
  state.renderStatus = source === "fetch" ? "idle" : "error";
  if (source === "fetch") {
    state.loadStatus = "error";
  }
  syncBodyState();
  setWorkspaceStatus(source === "fetch" ? "falha de consulta" : "falha de renderização");
}

function clearWorkspaceError() {
  state.errorSource = null;
  state.errorMessage = null;
  if (state.loadStatus !== "error") {
    state.renderStatus = "idle";
  }
  syncBodyState();
}

function logWorkspaceWarning(message, extra) {
  if (extra !== undefined) {
    console.warn(`[RouteGraph Workspace] ${message}`, extra);
    return;
  }
  console.warn(`[RouteGraph Workspace] ${message}`);
}

function getSummary() {
  return state.graph?.summary || {};
}

function getClusters() {
  const clusters = Array.isArray(state.graph?.clusters) && state.graph.clusters.length ? state.graph.clusters : FALLBACK_CLUSTERS;
  const map = new Map();
  for (const cluster of [...FALLBACK_CLUSTERS, ...clusters]) {
    if (!cluster || !cluster.id) continue;
    if (!map.has(cluster.id)) {
      map.set(cluster.id, cluster);
    } else {
      map.set(cluster.id, { ...map.get(cluster.id), ...cluster });
    }
  }
  return [...map.values()];
}

function getClusterById(clusterId) {
  return getClusters().find((cluster) => cluster.id === clusterId) || null;
}

function nodeCountsByCluster() {
  const map = new Map();
  for (const cluster of getClusters()) {
    map.set(cluster.id, cluster.node_count ?? 0);
  }
  return map;
}

function selectedServiceSummary() {
  if (state.selectedService === "all") return "Todos os serviços";
  const services = getServiceMap();
  const entry = services.find((item) => item.service === state.selectedService);
  if (!entry) return state.selectedService;
  return `${entry.service} · ${entry.count} nós`;
}

function getServiceMap() {
  const services = new Map();
  const payloadServices = Array.isArray(state.graph?.filters?.services) ? state.graph.filters.services : [];
  payloadServices.forEach((service) => {
    const key = String(service || "").trim();
    if (key) services.set(key, 0);
  });
  for (const node of state.graph?.nodes || []) {
    for (const service of node.services_seen || []) {
      const key = String(service || "").trim();
      if (!key) continue;
      services.set(key, (services.get(key) || 0) + 1);
    }
  }
  return [...services.entries()]
    .map(([service, count]) => ({ service, count }))
    .sort((a, b) => a.service.localeCompare(b.service, "pt-BR"));
}

function uniqueServicesFromGraph() {
  const services = new Map();
  for (const node of state.graph?.nodes || []) {
    for (const service of node.services_seen || []) {
      const key = String(service || "").trim();
      if (key) services.set(key, true);
    }
  }
  for (const edge of state.graph?.edges || []) {
    for (const service of edge.services || []) {
      const key = String(service || "").trim();
      if (key) services.set(key, true);
    }
  }
  return [...services.keys()].sort((a, b) => a.localeCompare(b, "pt-BR"));
}

function servicesForNodes(nodes) {
  const services = new Set();
  for (const node of nodes || []) {
    for (const service of node.services_seen || []) {
      const value = String(service || "").trim();
      if (value) services.add(value);
    }
  }
  return [...services].sort((a, b) => a.localeCompare(b, "pt-BR"));
}

function clusterOperationalExplanation(clusterId) {
  return (
    {
      local: "Rede ou host do lado do operador.",
      cpe_onu: "Provável equipamento de acesso ou transição local.",
      provider_private: "Conjunto de IPs privados observados no caminho, inferidos como trecho interno da operadora.",
      provider_public_edge: "Possível borda pública após trecho privado.",
      transit: "Trecho de trânsito sem sinal forte de CDN/PTT.",
      cdn_cloud: "Hops associados a CDN/cloud conforme serviço, ASN, organização ou evidência disponível.",
      ptt_ix: "Candidato a ponto de troca.",
      destination: "Destino final do serviço.",
      unknown: "Hops ainda sem classificação suficiente.",
    }[clusterId] || "Agrupamento visual do grafo aprendido."
  );
}

function renderSummaryCards() {
  const summary = getSummary();
  const badges = [
    ["Serviços", summary.services_count],
    ["Hops", summary.nodes_count],
    ["Edges", summary.edges_count],
    ["Privados", summary.private_hops_count],
    ["Unknown", summary.unknown_hops_count],
    ["ASNs", summary.asn_count],
  ];
  $("summaryCards").innerHTML = badges
    .map(
      ([label, value]) => `
        <div class="summary-badge">
          <span class="summary-label">${esc(label)}</span>
          <span class="summary-value">${esc(value ?? 0)}</span>
        </div>
      `,
    )
    .join("");
}

function renderClusters() {
  const clusters = getClusters();
  const counts = nodeCountsByCluster();
  const hasRealClusters = Array.isArray(state.graph?.clusters) && state.graph.clusters.length > 0;
  const status = hasRealClusters ? "clusters derivados carregados" : "clusters fallback";
  const el = $("clusterStatus");
  if (el) el.textContent = status;

  $("clusterList").innerHTML = clusters
    .map((cluster) => {
      const active = state.selectedCluster === cluster.id ? " active" : "";
      const description = cluster.description || CLUSTER_DESCRIPTIONS[cluster.id] || "—";
      const count = cluster.node_count ?? counts.get(cluster.id) ?? 0;
      return `
        <button class="cluster-item${active}" type="button" data-cluster="${esc(cluster.id)}">
          <span class="cluster-title">${esc(cluster.label || cluster.id)}</span>
          <span class="cluster-meta">
            <span class="cluster-id">${esc(cluster.id)}</span>
            <span class="cluster-count">${esc(count)} nodes</span>
          </span>
          <span class="cluster-confidence">${esc(cluster.confidence || "—")}</span>
          <span class="cluster-description">${esc(description)}</span>
        </button>
      `;
    })
    .join("");

  document.querySelectorAll(".cluster-item").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedCluster = button.dataset.cluster || "unknown";
      state.selectedElement = null;
      renderClusters();
      renderDetail();
      updateCanvasFromSelection();
    });
  });
}

function renderServices() {
  const services = getServiceMap();
  state.derivedServices = services.map((entry) => entry.service);
  const chips = [
    { service: "all", count: state.graph?.summary?.services_count ?? 0, label: "Todos" },
    ...services.map((entry) => ({ ...entry, label: entry.service })),
  ];
  $("serviceList").innerHTML = chips
    .map((entry) => {
      const active = state.selectedService === entry.service ? " active" : "";
      const count = entry.service === "all" ? "global" : `${entry.count} nós`;
      return `
        <button class="service-chip${active}" type="button" data-service="${esc(entry.service)}">
          ${esc(entry.label)}
          <span class="service-count">${esc(count)}</span>
        </button>
      `;
    })
    .join("");

  document.querySelectorAll(".service-chip").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedService = button.dataset.service || "all";
      state.selectedElement = null;
      renderServices();
      renderClusters();
      renderGraph();
      renderDetail();
      updateCanvasFromSelection();
    });
  });
}

function renderCanvasMessage() {
  const placeholder = $("canvasPlaceholder");
  if (!placeholder) return;

  if (state.loadStatus === "loading") {
    placeholder.innerHTML = `
      <p class="canvas-label">Canvas de topologia</p>
      <h2>Consultando /route-graph/global...</h2>
      <p>O workspace está preparando o mapa operacional em modo read-only.</p>
    `;
    return;
  }

  if (state.loadStatus === "error") {
    placeholder.innerHTML = `
      <p class="canvas-label">Canvas de topologia</p>
      <h2>Falha ao consultar /route-graph/global.</h2>
      <p>${esc(state.errorMessage || "Falha sanitizada ao consultar /route-graph/global.")}</p>
    `;
    return;
  }

  if (state.renderStatus === "error") {
    placeholder.innerHTML = `
      <p class="canvas-label">Canvas de topologia</p>
      <h2>Falha ao renderizar o grafo no canvas.</h2>
      <p>${esc(state.errorMessage || "Falha sanitizada ao renderizar o grafo no canvas.")}</p>
      <div class="canvas-summary">
        <div>O payload foi carregado, mas a montagem visual falhou.</div>
        <div>Sem POST, sem ação ativa e sem stack trace bruto.</div>
      </div>
    `;
    return;
  }

  if (state.loadStatus === "empty") {
    const offPathCount = state.orphanNodes?.length || 0;
    placeholder.innerHTML = `
      <p class="canvas-label">Canvas de topologia</p>
      <h2>${esc(state.emptyReason || "Nenhum elemento disponível para renderização.")}</h2>
      <p>Use o seletor de serviço ou volte para a visão global.</p>
      ${offPathCount ? `<div class="canvas-summary"><div>${esc(offPathCount)} itens fora do caminho estão disponíveis no diagnóstico recolhível.</div></div>` : ""}
    `;
    return;
  }

  const summary = getSummary();
  placeholder.innerHTML = `
    <p class="canvas-label">Canvas de topologia</p>
    <h2>Grafo carregado</h2>
    <p>${esc(summary.nodes_count ?? 0)} hops · ${esc(summary.edges_count ?? 0)} edges · ${esc(summary.private_hops_count ?? 0)} privados · ${esc(summary.unknown_hops_count ?? 0)} unknown</p>
    <div class="canvas-summary">
      <div><strong>Serviço ativo:</strong> ${esc(selectedServiceSummary())}</div>
      <div><strong>Clusters:</strong> ${esc(state.selectedCluster)}</div>
      <div><strong>Estado:</strong> ${esc(state.loadStatus)} · ${esc(state.renderStatus)}</div>
    </div>
  `;
}

function renderDiagnosticPanel() {
  const panel = $("diagnosticPanel");
  const badge = $("offPathBadge");
  const orphanNodes = Array.isArray(state.orphanNodes) ? state.orphanNodes : [];
  if (badge) {
    badge.textContent = `Itens fora do caminho: ${orphanNodes.length}`;
  }
  if (!panel) return;

  if (!state.ui.diagnosticVisible) {
    panel.classList.add("hidden");
    panel.classList.remove("visible");
    panel.innerHTML = "";
    return;
  }

  panel.classList.remove("hidden");
  panel.classList.add("visible");
  panel.innerHTML = `
    <div class="diagnostic-panel-title">
      <strong>Diagnóstico · itens fora do caminho</strong>
      <span class="toolbar-offpath">Total: ${esc(orphanNodes.length)}</span>
    </div>
    <div class="diagnostic-panel-note">
      Estes itens existem no payload/filtro atual, mas não possuem edge observada no subgrafo. Por isso não aparecem no mapa operacional.
    </div>
    <div class="diagnostic-list">
      ${
        orphanNodes.length
          ? orphanNodes
              .slice(0, 24)
              .map(
                (node) => `
                  <button class="diagnostic-item" type="button" data-offpath-id="${esc(node.id)}" title="Abrir detalhes do item fora do caminho">
                    <div class="diagnostic-item-head">
                      <span class="diagnostic-item-label">${esc(node.label || node.ip || node.id)}</span>
                      <span class="diagnostic-item-pill">${esc(node.device_icon?.id || "RB-ICON-0080")}</span>
                    </div>
                    <div class="diagnostic-item-meta">${esc(node.device_icon?.key || "unknown")} · cluster ${esc(node.cluster || "unknown")}</div>
                    <div class="diagnostic-item-meta">Motivo: ${esc(getOffPathReason(node))}</div>
                  </button>
                `,
              )
              .join("")
          : `<div class="diagnostic-panel-note">Nenhum item fora do caminho no filtro atual.</div>`
      }
    </div>
  `;

  panel.querySelectorAll(".diagnostic-item").forEach((button) => {
    button.addEventListener("click", () => {
      const orphan = orphanNodes.find((node) => node.id === button.dataset.offpathId);
      if (!orphan) return;
      state.selectedElement = { type: "diagnostic-node", data: orphan };
      renderDetail();
      if (isMobileView()) {
        state.ui.diagnosticVisible = false;
        renderDiagnosticPanel();
      }
    });
  });
}

function getOffPathReason(node) {
  if (!node) return "sem edge no subgrafo atual";
  const globalEdges = Array.isArray(state.graph?.edges) ? state.graph.edges : [];
  const hasGlobalEdge = globalEdges.some((edge) => edge.source === node.id || edge.target === node.id);
  if (state.selectedService !== "all") {
    const service = state.selectedService;
    const serviceEdges = globalEdges.filter((edge) => (edge.services || []).includes(service));
    const hasServiceEdge = serviceEdges.some((edge) => edge.source === node.id || edge.target === node.id);
    if (!hasServiceEdge && hasGlobalEdge) return "edge filtrada pelo serviço";
    if (!hasServiceEdge && !hasGlobalEdge) return "serviço sem evidência ou dado incompleto";
  }
  if (hasGlobalEdge) return "edge filtrada no subgrafo atual";
  return "sem edge no subgrafo atual";
}

function renderNodeSymbolSummary(node) {
  const device = node.device_icon || resolveNodeDeviceIcon(node);
  const org = node.org_badge || resolveNodeOrgBadge(node);
  const flag = node.flag_icon || resolveNodeFlag(node);
  const states = Array.isArray(node.state_badges) && node.state_badges.length ? node.state_badges : resolveNodeStateBadges(node);

  return `
    <div class="symbol-rail">
      <div class="symbol-card">
        <img class="symbol-preview" src="${esc(device.file)}" alt="${esc(device.name)}" />
        <div class="symbol-card-body">
          <div class="symbol-card-title">Ícone</div>
          <div class="symbol-card-line">${esc(device.id)} · ${esc(device.key)}</div>
          <div class="symbol-card-muted">${esc(device.name)} · ${esc(device.source)}</div>
        </div>
      </div>
      <div class="symbol-badge-row">
        <span class="symbol-chip">
          <span class="symbol-chip-label">Org</span>
          <span class="symbol-chip-value">${esc(org.label || org.key || "Unknown")}</span>
        </span>
        <span class="symbol-chip">
          <span class="symbol-chip-label">País</span>
          <span class="symbol-chip-value">${esc(flag.label || flag.key || "GL")}</span>
        </span>
      </div>
      <div class="symbol-badge-row">
        ${states
          .map(
            (badge) => `
              <span class="symbol-state">
                <img class="symbol-state-icon" src="${esc(badge.file)}" alt="${esc(badge.label)}" />
                <span>${esc(badge.label)}</span>
              </span>
            `,
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderDetail() {
  const detail = $("detailBody");
  if (!detail) return;

  const renderBgpDetail = (data) => {
    if (!data) return "";
    const evidence = data.bgp_evidence && typeof data.bgp_evidence === "object"
      ? data.bgp_evidence
      : (data.bgp_matched_prefix || data.bgp_origin_asn || data.bgp_source)
        ? {
            matched_prefix: data.bgp_matched_prefix || null,
            origin_asn: data.bgp_origin_asn || null,
            as_path: data.bgp_as_path || null,
            source: data.bgp_source || null,
            lookup_ip: data.bgp_lookup_ip || data.ip || null,
            confidence: data.bgp_confidence || null,
            attribution_scope: data.bgp_attribution_scope || null,
          }
        : null;
    const context = data.bgp_context && typeof data.bgp_context === "object" ? data.bgp_context : null;
    if (!evidence && !context) return "";
    if (context) {
      return `
        <div class="detail-block">
          <strong>BGP</strong>
          <p>IP privado/CGNAT: sem atribuição BGP direta.</p>
          <div class="detail-grid">
            <div class="kv"><strong>Status</strong><span>${esc(context.status || "-")}</span></div>
            <div class="kv"><strong>Motivo</strong><span>${esc(context.reason || "-")}</span></div>
          </div>
        </div>
      `;
    }
    return `
      <div class="detail-block">
        <strong>BGP LPM</strong>
        <div class="detail-grid">
          <div class="kv"><strong>Prefixo</strong><span>${esc(evidence.matched_prefix || "-")}</span></div>
          <div class="kv"><strong>ASN origem</strong><span>${esc(evidence.origin_asn ? `AS${evidence.origin_asn}` : "-")}</span></div>
          <div class="kv"><strong>AS path</strong><span>${esc(evidence.as_path || "-")}</span></div>
          <div class="kv"><strong>Fonte</strong><span>${esc(evidence.source || "-")}</span></div>
          <div class="kv"><strong>Confiança</strong><span>${esc(evidence.confidence || "-")}</span></div>
        </div>
      </div>
    `;
  };

  if (state.selectedElement) {
    if (state.selectedElement.type === "cluster") {
      const cluster = state.selectedElement.data;
      const clusterId = cluster.cluster_id || cluster.id || cluster.clusterId || "unknown";
      const clusterInfo = getClusterById(clusterId) || {
        id: clusterId,
        label: cluster.label || clusterId,
        node_count: cluster.nodeCount || 0,
        confidence: cluster.confidence || "—",
        description: cluster.description || "",
        type: cluster.type || "inferred_cluster",
      };
      const visibleChildren = state.cy
        ? state.cy.nodes(`[parent = "cluster:${clusterId}"]`).filter((node) => !node.hasClass("is-hidden") && !node.data("isCluster")).length
        : (state.graph?.nodes || []).filter((node) => (node.cluster || "unknown") === clusterId).length;
      const childNodes = state.cy
        ? state.cy
            .nodes(`[parent = "cluster:${clusterId}"]`)
            .filter((node) => !node.hasClass("is-hidden") && !node.data("isCluster"))
            .map((node) => node.data())
        : (state.graph?.nodes || []).filter((node) => (node.cluster || "unknown") === clusterId);
      const services = servicesForNodes(childNodes);
      detail.innerHTML = `
        <p class="detail-lead">${esc(clusterInfo.label || clusterId)} · ${esc(clusterId)}</p>
        <div class="detail-meta">
          <div class="detail-line"><strong>nome</strong><span>${esc(clusterInfo.label || clusterId)}</span></div>
          <div class="detail-line"><strong>id</strong><span>${esc(clusterId)}</span></div>
          <div class="detail-line"><strong>descrição</strong><span>${esc(clusterInfo.description || cluster.description || "—")}</span></div>
          <div class="detail-line"><strong>node_count</strong><span>${esc(clusterInfo.node_count ?? 0)}</span></div>
          <div class="detail-line"><strong>confidence</strong><span>${esc(clusterInfo.confidence || cluster.confidence || "—")}</span></div>
          <div class="detail-line"><strong>nós visíveis</strong><span>${esc(visibleChildren)}</span></div>
          <div class="detail-line"><strong>serviços presentes</strong><span>${esc(services.join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>estado</strong><span>${state.collapsedClusters.has(clusterId) ? "colapsado" : "expandido"}</span></div>
        </div>
        <p class="detail-lead">${esc(clusterOperationalExplanation(clusterId))}</p>
      `;
      return;
    }

    if (state.selectedElement.type === "diagnostic-node") {
      const node = state.selectedElement.data;
      const device = node.device_icon || resolveNodeDeviceIcon(node);
      const org = node.org_badge || resolveNodeOrgBadge(node);
      const flag = node.flag_icon || resolveNodeFlag(node);
      const states = Array.isArray(node.state_badges) && node.state_badges.length ? node.state_badges : resolveNodeStateBadges(node);
      const neighborhood = getNodeNeighborhoodSummary(node);
      detail.innerHTML = `
        <p class="detail-lead">${esc(node.label || node.ip || "nó")} · fora do mapa operacional</p>
        ${renderNodeSymbolSummary(node)}
        <div class="detail-meta">
          <div class="detail-line"><strong>IP/label</strong><span>${esc(node.label || node.ip || "-")}</span></div>
          <div class="detail-line"><strong>device</strong><span>${esc(device.id)} · ${esc(device.key)}</span></div>
          <div class="detail-line"><strong>org badge</strong><span>${esc(org.label || org.key || "Unknown")}</span></div>
          <div class="detail-line"><strong>flag</strong><span>${esc(flag.label || flag.key || "GL")}</span></div>
          <div class="detail-line"><strong>states</strong><span>${esc(states.map((item) => item.label).join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>cluster</strong><span>${esc(node.cluster || "-")}</span></div>
          <div class="detail-line"><strong>categoria</strong><span>${esc(node.category || "-")}</span></div>
          <div class="detail-line"><strong>papel provável</strong><span>${esc(node.role || "-")}</span></div>
          <div class="detail-line"><strong>ASN/org</strong><span>${esc(node.asn || node.organization || "—")}</span></div>
          <div class="detail-line"><strong>BGP</strong><span>${esc(node.bgp_context ? "contexto privado" : node.bgp_evidence ? node.bgp_evidence.matched_prefix || "evidência disponível" : "—")}</span></div>
          <div class="detail-line"><strong>serviços</strong><span>${esc((node.services_seen || []).join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>anterior</strong><span>${esc(neighborhood.previous || "—")}</span></div>
          <div class="detail-line"><strong>posterior</strong><span>${esc(neighborhood.next || "—")}</span></div>
          <div class="detail-line"><strong>observações</strong><span>${esc(node.observations_count ?? 0)}</span></div>
          <div class="detail-line"><strong>confiança</strong><span>${esc(node.confidence ?? "—")}</span></div>
          <div class="detail-line ${node.is_orphan ? "orphan-note" : ""}"><strong>status</strong><span>Este item está fora do mapa operacional porque não possui ligação observada no subgrafo atual.</span></div>
          <div class="detail-line"><strong>first/last seen</strong><span>${esc(node.first_seen_at || "—")} / ${esc(node.last_seen_at || "—")}</span></div>
        </div>
      `;
      return;
    }

    if (state.selectedElement.type === "node") {
      const node = state.selectedElement.data;
      const device = node.device_icon || resolveNodeDeviceIcon(node);
      const org = node.org_badge || resolveNodeOrgBadge(node);
      const flag = node.flag_icon || resolveNodeFlag(node);
      const states = Array.isArray(node.state_badges) && node.state_badges.length ? node.state_badges : resolveNodeStateBadges(node);
      const neighborhood = getNodeNeighborhoodSummary(node);
      const privateText = node.is_private
        ? "IP privado observado no caminho. A identificação é inferida pela posição no traceroute e pelos hops vizinhos."
        : node.is_unknown
          ? "Hop ainda não classificado. Pode faltar ASN, reverse DNS, evidência ou enriquecimento."
          : node.cluster === "destination"
            ? "Hop final associado ao target conhecido do serviço."
            : "Nó selecionado no grafo aprendido.";
      detail.innerHTML = `
        <p class="detail-lead">${esc(node.label || node.ip || "nó")} · ${esc(node.cluster || "unknown")}</p>
        ${renderNodeSymbolSummary(node)}
        <div class="detail-meta">
          <div class="detail-line"><strong>IP/label</strong><span>${esc(node.label || node.ip || "-")}</span></div>
          <div class="detail-line"><strong>device</strong><span>${esc(device.id)} · ${esc(device.key)}</span></div>
          <div class="detail-line"><strong>org badge</strong><span>${esc(org.label || org.key || "Unknown")}</span></div>
          <div class="detail-line"><strong>flag</strong><span>${esc(flag.label || flag.key || "GL")}</span></div>
          <div class="detail-line"><strong>states</strong><span>${esc(states.map((item) => item.label).join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>cluster</strong><span>${esc(node.cluster || "-")}</span></div>
          <div class="detail-line"><strong>categoria</strong><span>${esc(node.category || "-")}</span></div>
          <div class="detail-line"><strong>papel provável</strong><span>${esc(node.role || "-")}</span></div>
          <div class="detail-line"><strong>ASN/org</strong><span>${esc(node.asn || node.organization || "—")}</span></div>
          <div class="detail-line"><strong>BGP</strong><span>${esc(node.bgp_context ? "contexto privado" : node.bgp_evidence ? node.bgp_evidence.matched_prefix || "evidência disponível" : "—")}</span></div>
          <div class="detail-line"><strong>serviços</strong><span>${esc((node.services_seen || []).join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>anterior</strong><span>${esc(neighborhood.previous || "—")}</span></div>
          <div class="detail-line"><strong>posterior</strong><span>${esc(neighborhood.next || "—")}</span></div>
          <div class="detail-line"><strong>observações</strong><span>${esc(node.observations_count ?? 0)}</span></div>
          <div class="detail-line"><strong>confiança</strong><span>${esc(node.confidence ?? "—")}</span></div>
          <div class="detail-line"><strong>flags</strong><span>${node.is_private ? "private " : ""}${node.is_unknown ? "unknown " : ""}${node.is_ptt_candidate ? "ptt-candidate" : ""}</span></div>
          <div class="detail-line ${node.is_orphan ? "orphan-note" : ""}"><strong>ligação</strong><span>${node.is_orphan ? "Este item está fora do mapa operacional porque não possui ligação observada no subgrafo atual." : "edge observada no subgrafo atual"}</span></div>
          <div class="detail-line"><strong>first/last seen</strong><span>${esc(node.first_seen_at || "—")} / ${esc(node.last_seen_at || "—")}</span></div>
        </div>
        <p class="detail-lead">${esc(privateText)}</p>
        ${renderBgpDetail(node)}
      `;
      return;
    }

    if (state.selectedElement.type === "edge") {
      const edge = state.selectedElement.data;
      const explanation = {
        lan_to_cpe: "rede local para CPE/ONU",
        cpe_to_provider_private: "acesso local para rede privada da operadora",
        provider_private_to_provider_private: "trecho privado interno observado",
        provider_private_to_public_edge: "saída provável para borda pública",
        public_edge_to_transit: "borda pública para trânsito",
        transit_to_cdn: "trânsito para CDN/cloud",
        cdn_to_destination: "CDN/cloud para destino",
        same_ip_repeated_next_hop: "mesmo IP repetido no próximo salto",
        unknown_transition: "transição observada ainda pouco classificada",
      }[edge.transition_type || "unknown_transition"] || "transição operacional observada";
      detail.innerHTML = `
        <p class="detail-lead">${esc(edge.source)} → ${esc(edge.target)} · ${esc(edge.transition_type || "unknown_transition")}</p>
        <div class="detail-meta">
          <div class="detail-line"><strong>source → target</strong><span>${esc(edge.source)} → ${esc(edge.target)}</span></div>
          <div class="detail-line"><strong>transition_type</strong><span>${esc(edge.transition_type || "-")}</span></div>
          <div class="detail-line"><strong>services</strong><span>${esc((edge.services || []).join(", ") || "—")}</span></div>
          <div class="detail-line"><strong>observations_count</strong><span>${esc(edge.observations_count ?? 0)}</span></div>
          <div class="detail-line"><strong>rtt_delta_ms</strong><span>${esc(edge.rtt_delta_ms ?? "—")}</span></div>
          <div class="detail-line"><strong>confidence</strong><span>${esc(edge.confidence ?? "—")}</span></div>
        </div>
        <p class="detail-lead">${esc(explanation)}</p>
      `;
    }
    return;
  }

  if (state.loadStatus === "error") {
    detail.innerHTML = `
      <p class="detail-lead">Falha ao consultar /route-graph/global.</p>
      <div class="detail-meta">
        <div class="detail-line"><strong>erro</strong><span>${esc(state.errorMessage || "falha sanitizada")}</span></div>
        <div class="detail-line"><strong>próxima ação visual</strong><span>Recarregar o grafo no canvas</span></div>
      </div>
    `;
    return;
  }

  if (state.renderStatus === "error") {
    detail.innerHTML = `
      <p class="detail-lead">Falha ao renderizar o grafo no canvas.</p>
      <div class="detail-meta">
        <div class="detail-line"><strong>erro</strong><span>${esc(state.errorMessage || "falha sanitizada")}</span></div>
        <div class="detail-line"><strong>estado</strong><span>${esc(state.errorSource || "render")}</span></div>
      </div>
    `;
    return;
  }

  if (state.loadStatus === "empty") {
    detail.innerHTML = `
      <p class="detail-lead">${esc(state.emptyReason || "Nenhum elemento disponível para este filtro.")}</p>
      <div class="detail-meta">
        <div class="detail-line"><strong>serviço ativo</strong><span>${esc(selectedServiceSummary())}</span></div>
        <div class="detail-line"><strong>próxima ação visual</strong><span>Voltar para a visão global</span></div>
      </div>
    `;
    return;
  }

  const summary = getSummary();
  const limitations = Array.isArray(state.graph?.limitations) ? state.graph.limitations : [];
  const selectedCluster = getClusterById(state.selectedCluster);
  const servicesWithEvidence = getServiceMap().map((entry) => entry.service);
  detail.innerHTML = `
    <p class="detail-lead">Escopo ${esc(state.graph?.scope || "global")}. ${esc(state.graph?.graph_uid || "global")} pronto para leitura operacional.</p>
    <div class="detail-meta">
      <div class="detail-line"><strong>Escopo</strong><span>${esc(state.graph?.scope || "global")}</span></div>
      <div class="detail-line"><strong>Última geração</strong><span>${esc(state.graph?.generated_at || "—")}</span></div>
      <div class="detail-line"><strong>Serviços com evidência</strong><span>${esc(servicesWithEvidence.length ? servicesWithEvidence.join(", ") : "—")}</span></div>
      <div class="detail-line"><strong>Limitações</strong><span>${esc(limitations.length ? limitations.join("; ") : "—")}</span></div>
      <div class="detail-line"><strong>Cluster selecionado</strong><span>${esc(selectedCluster?.label || selectedCluster?.id || "—")}</span></div>
      <div class="detail-line"><strong>Serviço ativo</strong><span>${esc(selectedServiceSummary())}</span></div>
      <div class="detail-line"><strong>Contador</strong><span>${esc(summary.nodes_count ?? 0)} nodes · ${esc(summary.edges_count ?? 0)} edges</span></div>
      <div class="detail-line"><strong>Serviços derivados</strong><span>${esc(uniqueServicesFromGraph().join(", ") || "—")}</span></div>
    </div>
  `;
}

function updateCanvasFromSelection() {
  renderCanvasMessage();
  renderDiagnosticPanel();
  renderDetail();
  renderGraphStatus();
}

function getNodeNeighborhoodSummary(node) {
  const nodeId = node?.id;
  if (!nodeId) return { previous: "", next: "" };

  const previous = new Set();
  const next = new Set();

  if (state.cy) {
    state.cy.edges().forEach((edge) => {
      const data = edge.data();
      if (data.target === nodeId) {
        const sourceNode = state.cy.getElementById(data.source);
        if (sourceNode && sourceNode.length) {
          previous.add(sourceNode.data("label") || sourceNode.data("ip") || sourceNode.id());
        }
      }
      if (data.source === nodeId) {
        const targetNode = state.cy.getElementById(data.target);
        if (targetNode && targetNode.length) {
          next.add(targetNode.data("label") || targetNode.data("ip") || targetNode.id());
        }
      }
    });
  } else {
    for (const edge of state.graph?.edges || []) {
      if (edge.target === nodeId) previous.add(edge.source);
      if (edge.source === nodeId) next.add(edge.target);
    }
  }

  return {
    previous: [...previous].slice(0, 3).join(", "),
    next: [...next].slice(0, 3).join(", "),
  };
}

function renderGraphStatus() {
  const summary = getSummary();
  const visibleNodes = state.cy ? state.cy.nodes().filter((node) => !node.hasClass("is-hidden") && !node.data("isCluster")).length : 0;
  const visibleClusters = state.cy ? state.cy.nodes().filter((node) => !node.hasClass("is-hidden") && !!node.data("isCluster")).length : 0;
  const visibleEdges = state.cy ? state.cy.edges().filter((edge) => !edge.hasClass("is-hidden")).length : 0;
  const orphanNodes = Array.isArray(state.orphanNodes) ? state.orphanNodes.length : 0;
  const bits = [
    state.loadStatus,
    state.renderStatus,
    state.selectedService === "all" ? "serviço:todos" : `serviço:${state.selectedService}`,
    `global=${summary.nodes_count || 0}n/${summary.edges_count || 0}e`,
    `visíveis=${visibleNodes}n/${visibleEdges}e`,
    `clusters=${visibleClusters}`,
    `fora-do-caminho=${orphanNodes}`,
  ];
  setWorkspaceStatus(bits.join(" · "));
  const badge = $("offPathBadge");
  if (badge) badge.textContent = `Itens fora do caminho: ${orphanNodes}`;
}

function fitGraph() {
  if (!state.cy) return;
  try {
    state.cy.fit(undefined, 24);
  } catch (error) {
    logWorkspaceWarning("fit ignorado por falha do cytoscape");
  }
}

function setPanelVisibility(panel, visible) {
  if (panel === "sidebar") {
    state.ui.sidebarVisible = visible;
  } else if (panel === "details") {
    state.ui.detailsVisible = visible;
  }
  syncShellState();
  renderGraphStatus();
}

function setDiagnosticVisibility(visible) {
  state.ui.diagnosticVisible = visible;
  renderDiagnosticPanel();
}

function toggleVisualFocus(kind) {
  if (kind === "private") {
    state.focusPrivate = !state.focusPrivate;
    if (state.focusPrivate) state.focusUnknown = false;
  } else if (kind === "unknown") {
    state.focusUnknown = !state.focusUnknown;
    if (state.focusUnknown) state.focusPrivate = false;
  }
  renderGraph();
  renderDetail();
  renderGraphStatus();
}

function toggleFullscreen() {
  const root = getRoot();
  if (document.fullscreenElement) {
    document.exitFullscreen?.().catch(() => {});
    return;
  }
  if (root.requestFullscreen) {
    root.requestFullscreen().catch(() => {
      setWorkspaceStatus("fullscreen indisponível");
    });
  }
}

function bindToolbar() {
  const actions = {
    homeButton: () => {
      state.selectedElement = null;
      renderDetail();
      fitGraph();
      setWorkspaceStatus("home · foco no canvas");
    },
    fitButton: () => {
      fitGraph();
      setWorkspaceStatus("ajustado à tela");
    },
    autoLayoutButton: () => {
      renderGraph();
      renderDetail();
      setWorkspaceStatus("auto layout reaplicado");
    },
    expandClustersButton: () => {
      state.selectedElement = null;
      state.collapsedClusters = new Set();
      renderGraph();
      renderDetail();
      setWorkspaceStatus("clusters expandidos");
    },
    collapseClustersButton: () => {
      state.selectedElement = null;
      state.collapsedClusters = new Set(getClusters().map((cluster) => cluster.id));
      renderGraph();
      renderDetail();
      setWorkspaceStatus("clusters colapsados");
    },
    privateToggleButton: () => {
      toggleVisualFocus("private");
      setWorkspaceStatus(state.focusPrivate ? "private em foco" : "private normalizado");
    },
    unknownToggleButton: () => {
      toggleVisualFocus("unknown");
      setWorkspaceStatus(state.focusUnknown ? "unknown em foco" : "unknown normalizado");
    },
    resetVisualButton: () => {
      state.selectedElement = null;
      state.selectedService = "all";
      state.collapsedClusters = new Set();
      state.focusPrivate = false;
      state.focusUnknown = false;
      renderServices();
      renderClusters();
      renderGraph();
      updateCanvasFromSelection();
      setWorkspaceStatus("visual resetado");
    },
    clustersToggleButton: () => {
      const mobile = isMobileView();
      setPanelVisibility("sidebar", !state.ui.sidebarVisible);
      if (mobile) {
        setWorkspaceStatus(state.ui.sidebarVisible ? "clusters aberto" : "clusters fechado");
      }
    },
    detailsToggleButton: () => {
      const mobile = isMobileView();
      setPanelVisibility("details", !state.ui.detailsVisible);
      if (mobile) {
        setWorkspaceStatus(state.ui.detailsVisible ? "detalhes abertos" : "detalhes fechados");
      }
    },
    diagnosticToggleButton: () => {
      setDiagnosticVisibility(!state.ui.diagnosticVisible);
      setWorkspaceStatus(state.ui.diagnosticVisible ? "diagnóstico aberto" : "diagnóstico fechado");
    },
    fullscreenButton: () => {
      toggleFullscreen();
    },
  };

  Object.entries(actions).forEach(([id, handler]) => {
    const button = $(id);
    if (!button) return;
    button.addEventListener("click", handler);
  });
}

function filterNodesAndEdges() {
  const graph = state.graph || {};
  const selectedService = state.selectedService;
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const serviceEvidence =
    selectedService === "all" ||
    nodes.some((node) => (node.services_seen || []).includes(selectedService)) ||
    edges.some((edge) => (edge.services || []).includes(selectedService));

  if (!serviceEvidence) {
    return { nodes: [], edges: [], serviceEvidence: false, emptyReason: "Este serviço está seedado, mas ainda não possui rota observada no inventário." };
  }

  const filteredNodes = selectedService === "all"
    ? nodes
    : nodes.filter((node) => (node.services_seen || []).includes(selectedService));

  const nodeIds = new Set(filteredNodes.map((node) => node.id));
  const filteredEdges = [];
  for (const edge of edges) {
    const matchesService = selectedService === "all" || (edge.services || []).includes(selectedService);
    if (!matchesService) continue;
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
      logWorkspaceWarning("edge ignorada por source/target ausente", { edgeId: edge.id });
      continue;
    }
    filteredEdges.push(edge);
  }

  return { nodes: filteredNodes, edges: filteredEdges, serviceEvidence: true, emptyReason: null };
}

function explainTransition(transitionType) {
  return (
    {
      lan_to_cpe: "rede local para CPE/ONU",
      cpe_to_provider_private: "acesso local para rede privada da operadora",
      provider_private_to_provider_private: "trecho privado interno observado",
      provider_private_to_public_edge: "saída provável para borda pública",
      public_edge_to_transit: "borda pública para trânsito",
      transit_to_cdn: "trânsito para CDN/cloud",
      cdn_to_destination: "CDN/cloud para destino",
      same_ip_repeated_next_hop: "mesmo IP repetido no próximo salto",
      unknown_transition: "transição observada ainda pouco classificada",
    }[transitionType || "unknown_transition"] || "transição operacional observada"
  );
}

function buildElementsForCytoscape() {
  let result;
  try {
    result = filterNodesAndEdges();
  } catch (error) {
    logWorkspaceWarning("falha ao aplicar filtro do serviço", error);
    return { elements: [], emptyReason: null, errorSource: "filter", errorMessage: "Falha ao aplicar filtro do serviço." };
  }

  const { nodes, edges, serviceEvidence, emptyReason } = result;
  if (!serviceEvidence) return { elements: [], emptyReason };
  if (!nodes.length) return { elements: [], emptyReason: "Nenhum nó disponível para este filtro." };

  const clusters = getClusters();
  const nodesByCluster = new Map();
  for (const cluster of clusters) {
    nodesByCluster.set(cluster.id, []);
  }
  for (const node of nodes) {
    const clusterId = node.cluster || "unknown";
    if (!nodesByCluster.has(clusterId)) {
      nodesByCluster.set(clusterId, []);
    }
    nodesByCluster.get(clusterId).push(node);
  }

  const degreeByNodeId = new Map();
  const nodeIdSet = new Set(nodes.map((node) => node.id));
  for (const edge of edges) {
    if (!nodeIdSet.has(edge.source) || !nodeIdSet.has(edge.target)) {
      continue;
    }
    degreeByNodeId.set(edge.source, (degreeByNodeId.get(edge.source) || 0) + 1);
    degreeByNodeId.set(edge.target, (degreeByNodeId.get(edge.target) || 0) + 1);
  }

  const elements = [];
  const orphanNodes = [];
  const clusterIdsWithChildren = new Set();
  const connectedNodeIds = new Set();
  for (const [nodeId, degree] of degreeByNodeId.entries()) {
    if (degree > 0) connectedNodeIds.add(nodeId);
  }
  for (const cluster of clusters) {
    const clusterNodes = (nodesByCluster.get(cluster.id) || []).filter((node) => connectedNodeIds.has(node.id));
    if (!clusterNodes.length) continue;
    clusterIdsWithChildren.add(cluster.id);
    elements.push({
      group: "nodes",
      data: {
        id: `cluster:${cluster.id}`,
        label: cluster.label || cluster.id,
        cluster_id: cluster.id,
        node_count: cluster.node_count ?? clusterNodes.length,
        description: cluster.description || "",
        confidence: cluster.confidence || "—",
        type: cluster.type || "inferred_cluster",
        collapsed: state.collapsedClusters.has(cluster.id),
        isCluster: true,
        services_seen: servicesForNodes(clusterNodes),
      },
      classes: [
        "cluster-node",
        `cluster-${cluster.id}`,
        state.collapsedClusters.has(cluster.id) ? "is-collapsed" : "is-expanded",
      ].join(" "),
    });
  }

  for (const node of nodes) {
    const clusterId = node.cluster || "unknown";
    const clusterVisible = clusterIdsWithChildren.has(clusterId);
    const collapsed = state.collapsedClusters.has(clusterId);
    const degree = degreeByNodeId.get(node.id) || 0;
    const isOrphan = degree === 0;
    const focusHighlight = (state.focusPrivate && node.is_private) || (state.focusUnknown && node.is_unknown);
    const focusActive = state.focusPrivate || state.focusUnknown;
    const hidden = !clusterVisible || collapsed;
    const deviceIcon = resolveNodeDeviceIcon(node);
    const orgBadge = resolveNodeOrgBadge(node);
    const flagIcon = resolveNodeFlag(node);
    const stateBadges = resolveNodeStateBadges(node);
    if (isOrphan) {
      orphanNodes.push({
        id: node.id,
        label: node.label || node.ip || node.id,
        ip: node.ip,
        cluster: clusterId,
        role: node.role,
        category: node.category,
        asn: node.asn,
        organization: node.organization,
        services_seen: node.services_seen || [],
        confidence: node.confidence ?? null,
        is_private: !!node.is_private,
        is_unknown: !!node.is_unknown,
        is_ptt_candidate: !!node.is_ptt_candidate,
        device_icon: deviceIcon,
        org_badge: orgBadge,
        flag_icon: flagIcon,
        state_badges: stateBadges,
        degree,
        first_seen_at: node.first_seen_at || null,
        last_seen_at: node.last_seen_at || null,
        is_orphan: true,
      });
      continue;
    }

    const classes = [
      `node-${clusterId}`,
      node.is_private ? "is-private" : "",
      node.is_unknown ? "is-unknown" : "",
      node.is_ptt_candidate ? "is-ptt-candidate" : "",
      node.cluster === "destination" ? "node-destination" : "",
      node.cluster === "cdn_cloud" ? "node-cdn" : "",
      "symbolized",
      deviceIcon?.key ? `symbol-${normalizeKey(deviceIcon.key)}` : "",
      hidden ? "is-hidden" : "",
      focusActive && !focusHighlight ? "is-dimmed" : "",
      focusHighlight && node.is_private ? "focus-private" : "",
      focusHighlight && node.is_unknown ? "focus-unknown" : "",
    ].filter(Boolean).join(" ");

    elements.push({
      group: "nodes",
      data: {
        id: node.id,
        label: node.label || node.ip || node.id,
        ip: node.ip,
        cluster: clusterId,
        category: node.category,
        role: node.role,
        asn: node.asn,
        organization: node.organization,
        services_seen: node.services_seen || [],
        observations_count: node.observations_count ?? 0,
        confidence: node.confidence ?? null,
        is_private: !!node.is_private,
        is_unknown: !!node.is_unknown,
        is_ptt_candidate: !!node.is_ptt_candidate,
        is_orphan: isOrphan,
        first_seen_at: node.first_seen_at || null,
        last_seen_at: node.last_seen_at || null,
        parent: `cluster:${clusterId}`,
        device_icon_id: deviceIcon.id,
        device_icon_key: deviceIcon.key,
        device_icon_file: deviceIcon.file,
        device_icon_name: deviceIcon.name,
        device_icon_source: deviceIcon.source,
        org_badge_id: orgBadge.id,
        org_badge_key: orgBadge.key,
        org_badge_label: orgBadge.label,
        org_badge_source: orgBadge.source,
        flag_icon_id: flagIcon.id,
        flag_icon_key: flagIcon.key,
        flag_icon_label: flagIcon.label,
        flag_icon_file: flagIcon.file,
        state_badges: stateBadges,
        degree: degree,
        is_orphan: false,
      },
      classes,
    });
  }

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  for (const edge of edges) {
    const sourceNode = nodeById.get(edge.source);
    const targetNode = nodeById.get(edge.target);
    if (!sourceNode || !targetNode) {
      logWorkspaceWarning("edge ignorada por node ausente", { edgeId: edge.id });
      continue;
    }
    const sourceCluster = sourceNode.cluster || "unknown";
    const targetCluster = targetNode.cluster || "unknown";
    const sourceHidden = !clusterIdsWithChildren.has(sourceCluster) || state.collapsedClusters.has(sourceCluster);
    const targetHidden = !clusterIdsWithChildren.has(targetCluster) || state.collapsedClusters.has(targetCluster);
    if (sourceHidden || targetHidden) continue;
    elements.push({
      group: "edges",
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: "",
        transition_type: edge.transition_type || "unknown_transition",
        services: edge.services || [],
        observations_count: edge.observations_count ?? 0,
        rtt_delta_ms: edge.rtt_delta_ms ?? null,
        confidence: edge.confidence ?? null,
      },
      classes: [
        edge.transition_type === "unknown_transition" ? "edge-unknown" : "",
        edge.transition_type?.includes("provider_private") ? "edge-private" : "",
        edge.transition_type?.includes("cdn_to_destination") ? "edge-cdn" : "",
      ].filter(Boolean).join(" "),
    });
  }

  return { elements, orphanNodes, emptyReason: null };
}

function renderGraph() {
  const canvas = $("routeGraphWorkspaceCanvas");
  const placeholder = $("canvasPlaceholder");
  if (!canvas) {
    setWorkspaceError("render", "Falha ao renderizar o grafo no canvas.");
    renderCanvasMessage();
    renderDetail();
    return;
  }
  if (!window.cytoscape) {
    setWorkspaceError("render", "Falha ao renderizar o grafo no canvas.");
    renderCanvasMessage();
    renderDetail();
    return;
  }

  clearWorkspaceError();
  let buildResult;
  try {
    buildResult = buildElementsForCytoscape();
  } catch (error) {
    logWorkspaceWarning("falha inesperada ao montar elementos", error);
    setWorkspaceError("filter", "Falha ao aplicar filtro do serviço.");
    renderCanvasMessage();
    renderDetail();
    return;
  }

  if (buildResult.errorSource) {
    setWorkspaceError(buildResult.errorSource, buildResult.errorMessage || "Falha ao aplicar filtro do serviço.");
    renderCanvasMessage();
    renderDetail();
    return;
  }

  if (state.cy) {
    try {
      state.cy.destroy();
    } catch (error) {
      logWorkspaceWarning("falha ao destruir instancia anterior do cytoscape", error);
    }
    state.cy = null;
  }

  if (!buildResult.elements.length) {
    state.loadStatus = "empty";
    state.renderStatus = "ok";
    state.emptyReason = buildResult.emptyReason || "Nenhum elemento disponível para este filtro.";
    state.orphanNodes = Array.isArray(buildResult.orphanNodes) ? buildResult.orphanNodes : [];
    syncBodyState();
    if (placeholder) placeholder.classList.remove("hidden");
    canvas.classList.add("hidden");
    canvas.innerHTML = "";
    renderGraphStatus();
    renderCanvasMessage();
    renderDiagnosticPanel();
    renderDetail();
    return;
  }

  state.loadStatus = "loaded";
  state.renderStatus = "ok";
  state.emptyReason = null;
  syncBodyState();
  if (placeholder) placeholder.classList.add("hidden");
  canvas.classList.remove("hidden");
  canvas.innerHTML = "";
  state.orphanNodes = Array.isArray(buildResult.orphanNodes) ? buildResult.orphanNodes : [];

  const visibleLeafNodes = buildResult.elements.filter((el) => el.group === "nodes" && !el.data.isCluster && !String(el.classes).includes("is-hidden"));
  const visibleClusterNodes = buildResult.elements.filter((el) => el.group === "nodes" && !!el.data.isCluster && !String(el.classes).includes("is-hidden"));
  const inboundTargets = new Set(
    buildResult.elements
      .filter((el) => el.group === "edges")
      .map((el) => el.data.target)
      .filter((targetId) => visibleLeafNodes.some((node) => node.data.id === targetId)),
  );
  let roots = visibleLeafNodes.filter((node) => !inboundTargets.has(node.data.id)).map((node) => node.data.id);
  if (!roots.length) {
    roots = (visibleLeafNodes.length ? visibleLeafNodes : visibleClusterNodes).slice(0, 4).map((node) => node.data.id);
  }

  try {
  state.cy = window.cytoscape({
      container: canvas,
      elements: buildResult.elements,
      layout: {
        name: "breadthfirst",
        directed: true,
        roots,
        circle: false,
        spacingFactor: 1.25,
        avoidOverlap: true,
        nodeDimensionsIncludeLabels: true,
        padding: 24,
        animate: false,
        fit: true,
        direction: "rightward",
      },
      style: [
        {
          selector: "node.cluster-node",
          style: {
            shape: "round-rectangle",
            label: "data(label)",
            "font-size": 10,
            "font-weight": 800,
            color: "#dbeafe",
            "text-valign": "top",
            "text-halign": "center",
            "text-margin-y": 7,
            "text-wrap": "wrap",
            "text-max-width": 160,
            "background-opacity": 0.18,
            "background-color": "rgba(15, 23, 42, 0.32)",
            "border-width": 1.4,
            "border-color": "#475569",
            "border-style": "solid",
            padding: 18,
            "compound-sizing-wrt-label": "include",
            "transition-property": "opacity, background-color, border-color",
            "transition-duration": "0.18s",
          },
        },
        { selector: "node.cluster-node.is-collapsed", style: { "border-style": "dashed", "background-opacity": 0.12 } },
        { selector: "node.cluster-node.cluster-local", style: { "background-color": "rgba(96,165,250,0.12)", "border-color": "#60a5fa" } },
        { selector: "node.cluster-node.cluster-cpe_onu", style: { "background-color": "rgba(52,211,153,0.10)", "border-color": "#34d399" } },
        { selector: "node.cluster-node.cluster-provider_private", style: { "background-color": "rgba(37,99,235,0.12)", "border-color": "#2563eb" } },
        { selector: "node.cluster-node.cluster-provider_public_edge", style: { "background-color": "rgba(249,115,22,0.10)", "border-color": "#f59e0b" } },
        { selector: "node.cluster-node.cluster-transit", style: { "background-color": "rgba(71,85,105,0.12)", "border-color": "#94a3b8" } },
        { selector: "node.cluster-node.cluster-cdn_cloud", style: { "background-color": "rgba(14,165,233,0.12)", "border-color": "#38bdf8" } },
        { selector: "node.cluster-node.cluster-ptt_ix", style: { "background-color": "rgba(124,58,237,0.12)", "border-color": "#a855f7" } },
        { selector: "node.cluster-node.cluster-destination", style: { "background-color": "rgba(226,232,240,0.10)", "border-color": "#e2e8f0" } },
        { selector: "node.cluster-node.cluster-unknown", style: { "background-color": "rgba(107,114,128,0.10)", "border-color": "#9ca3af", "border-style": "dashed" } },
        {
          selector: "node",
          style: {
            label: "data(label)",
            color: "#e5e7eb",
            "font-size": 10,
            "font-weight": 700,
            "text-valign": "center",
            "text-halign": "center",
            "background-color": "#111827",
            "border-width": 2,
            "border-color": "#475569",
            width: 34,
            height: 34,
            "text-outline-color": "#0b1120",
            "text-outline-width": 2,
            "text-wrap": "wrap",
            "text-max-width": 82,
            "transition-property": "opacity, background-color, border-color, width, height",
            "transition-duration": "0.18s",
          },
        },
        {
          selector: "node.symbolized",
          style: {
            "background-image": "data(device_icon_file)",
            "background-fit": "contain",
            "background-position-x": "50%",
            "background-position-y": "44%",
            "background-width": "78%",
            "background-height": "78%",
            "background-image-opacity": 1,
            shape: "rectangle",
            "background-color": "rgba(2, 6, 23, 0.06)",
            width: 44,
            height: 44,
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 6,
            "font-size": 8,
            "text-max-width": 76,
            "border-width": 1.2,
            "border-color": "rgba(148, 163, 184, 0.34)",
          },
        },
        { selector: "node.node-local", style: { "background-color": "rgba(59,130,246,0.18)", "border-color": "#60a5fa" } },
        { selector: "node.node-cpe_onu", style: { "background-color": "rgba(15,118,110,0.18)", "border-color": "#34d399" } },
        { selector: "node.node-provider_private", style: { "background-color": "rgba(37,99,235,0.18)", "border-color": "#2563eb" } },
        { selector: "node.node-provider_public_edge", style: { "background-color": "rgba(194,65,12,0.18)", "border-color": "#f59e0b" } },
        { selector: "node.node-transit", style: { "background-color": "rgba(71,85,105,0.18)", "border-color": "#94a3b8" } },
        { selector: "node.node-cdn_cloud", style: { "background-color": "rgba(14,165,233,0.18)", "border-color": "#38bdf8" } },
        { selector: "node.node-ptt_ix", style: { "background-color": "rgba(124,58,237,0.18)", "border-color": "#a855f7" } },
        { selector: "node.node-destination", style: { shape: "diamond", "background-color": "rgba(17,24,39,0.3)", "border-color": "#e2e8f0", width: 40, height: 40 } },
        { selector: "node.node-unknown", style: { "background-color": "rgba(107,114,128,0.12)", "border-color": "#9ca3af", "border-style": "dashed" } },
        { selector: "node.symbol-provider_router", style: { "border-color": "#60a5fa" } },
        { selector: "node.symbol-cdn_edge", style: { "border-color": "#38bdf8" } },
        { selector: "node.symbol-local_gateway", style: { "border-color": "#34d399" } },
        { selector: "node.symbol-destination", style: { "border-color": "#e2e8f0" } },
        { selector: "node.symbol-unknown", style: { "border-color": "#9ca3af", "border-style": "dashed" } },
        { selector: "node.is-private", style: { "border-width": 3 } },
        { selector: "node.is-unknown", style: { opacity: 0.86 } },
        { selector: "node.is-ptt-candidate", style: { "border-style": "dotted" } },
        { selector: "node.is-dimmed", style: { opacity: 0.14 } },
        { selector: "node.focus-private", style: { "border-width": 4, "background-color": "#dbeafe" } },
        { selector: "node.focus-unknown", style: { "border-width": 4, "background-color": "#fde68a", "border-color": "#fbbf24" } },
        { selector: "node:selected", style: { "border-width": 4, "background-color": "#f8fafc" } },
        {
          selector: "edge",
          style: {
            width: 2.1,
            "line-color": "#93a4b8",
            "target-arrow-color": "#93a4b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            opacity: 0.88,
            label: "",
            "font-size": 0,
            color: "#94a3b8",
            "text-opacity": 0,
          },
        },
        { selector: "edge.edge-private", style: { "line-color": "#60a5fa", "target-arrow-color": "#60a5fa", opacity: 0.94 } },
        { selector: "edge.edge-cdn", style: { "line-color": "#38bdf8", "target-arrow-color": "#38bdf8", opacity: 0.94 } },
        { selector: "edge.edge-unknown", style: { "line-style": "dashed", opacity: 0.74 } },
        { selector: "edge:selected", style: { width: 3.8, opacity: 1, "line-color": "#f8fafc", "target-arrow-color": "#f8fafc" } },
        { selector: ".is-dimmed", style: { opacity: 0.18 } },
        { selector: ".is-hidden", style: { display: "none" } },
      ],
    });
  } catch (error) {
    logWorkspaceWarning("falha ao montar instancia do cytoscape", error);
    state.cy = null;
    setWorkspaceError("render", "Falha ao renderizar o grafo no canvas.");
    renderCanvasMessage();
    renderDetail();
    return;
  }

  state.cy.on("tap", "node", (event) => {
    const data = event.target.data();
    if (data.isCluster) {
      const clusterId = data.cluster_id || data.id.replace(/^cluster:/, "") || "unknown";
      state.selectedCluster = clusterId;
      state.selectedElement = { type: "cluster", data };
      if (event.originalEvent && Number(event.originalEvent.detail || 0) >= 2) {
        if (state.collapsedClusters.has(clusterId)) {
          state.collapsedClusters.delete(clusterId);
        } else {
          state.collapsedClusters.add(clusterId);
        }
        renderClusters();
        renderGraph();
        renderDetail();
        updateCanvasFromSelection();
        return;
      }
      renderClusters();
      renderDetail();
      renderGraphStatus();
      return;
    }
    state.selectedElement = { type: "node", data };
    renderDetail();
    renderGraphStatus();
  });

  state.cy.on("tap", "edge", (event) => {
    state.selectedElement = { type: "edge", data: event.target.data() };
    renderDetail();
    renderGraphStatus();
  });

  state.cy.on("tap", (event) => {
    if (event.target === state.cy) {
      state.selectedElement = null;
      renderDetail();
      renderGraphStatus();
    }
  });

  state.cy.ready(() => {
    fitGraph();
  });

  renderGraphStatus();
  renderCanvasMessage();
  renderDiagnosticPanel();
}

async function loadAuth() {
  const badge = $("authBadge");
  try {
    const response = await fetch("/auth/me", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      badge.textContent = "não autenticado";
      badge.className = "auth-pill auth-error";
      return;
    }
    const payload = await response.json();
    const role = payload.role || "desconhecido";
    const username = payload.username || "usuário";
    const suffix = role === "admin" ? "operador" : "leitura";
    badge.textContent = `${username} · ${suffix}`;
    badge.className = `auth-pill ${role === "admin" ? "auth-admin" : "auth-viewer"}`;
  } catch {
    badge.textContent = "não autenticado";
    badge.className = "auth-pill auth-error";
  }
}

async function loadGraph() {
  state.loadStatus = "loading";
  state.renderStatus = "idle";
  state.errorSource = null;
  state.errorMessage = null;
  state.emptyReason = null;
  syncBodyState();
  setWorkspaceStatus("carregando grafo global...");
  renderCanvasMessage();
  renderDetail();
  try {
    const response = await fetch("/route-graph/global", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    state.graph = await response.json();
    await loadSymbolLibrary();
    state.loadStatus = "loaded";
    state.renderStatus = "idle";
    state.collapsedClusters = new Set();
    syncBodyState();
    renderSummaryCards();
    renderClusters();
    renderServices();
    state.selectedElement = null;
    renderGraph();
    updateCanvasFromSelection();
  } catch (error) {
    logWorkspaceWarning("falha ao consultar /route-graph/global", error);
    state.graph = null;
    state.loadStatus = "error";
    state.renderStatus = "idle";
    state.errorSource = "fetch";
    state.errorMessage = "Falha ao consultar /route-graph/global.";
    syncBodyState();
    renderCanvasMessage();
    renderDetail();
    renderGraphStatus();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  bindToolbar();
  if (isMobileView()) {
    state.ui.sidebarVisible = false;
    state.ui.detailsVisible = false;
  }
  syncShellState();
  window.addEventListener("resize", syncShellState);
  document.addEventListener("fullscreenchange", syncShellState);
  loadSymbolLibrary().catch(() => {});
  loadAuth().catch(() => {
    const badge = $("authBadge");
    if (badge) {
      badge.textContent = "não autenticado";
      badge.className = "auth-pill auth-error";
    }
  });
  loadGraph().catch((error) => {
    logWorkspaceWarning("falha inesperada no carregamento inicial", error);
    state.loadStatus = "error";
    state.renderStatus = "idle";
    state.errorSource = "fetch";
    state.errorMessage = "Falha ao consultar /route-graph/global.";
    syncBodyState();
    renderCanvasMessage();
    renderDetail();
  });
});
