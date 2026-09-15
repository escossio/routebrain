(function () {
  "use strict";

  const ROOT_ID = "root";
  const BOOT_ID = "bootState";
  let ReactGlobal = null;
  let ReactDOMGlobal = null;
  let CytoscapeGlobal = null;
  let h = null;
  let useEffect = null;
  let useMemo = null;
  let useRef = null;
  let useState = null;

  function getRoot() {
    return document.getElementById(ROOT_ID);
  }

  function setBootMessage(text) {
    const boot = document.getElementById(BOOT_ID);
    if (boot) boot.textContent = text;
  }

  function renderBootError(error) {
    const root = getRoot();
    if (!root) return;
    const message = formatRuntimeError(error).message;
    root.innerHTML = `
      <div class="boot-error" role="alert">
        <strong>Erro ao carregar UI</strong>
        <div>${message.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]))}</div>
        <button id="retryBootButton" type="button" class="primary">Tentar novamente</button>
      </div>
    `;
    const retryButton = document.getElementById("retryBootButton");
    if (retryButton) {
      retryButton.addEventListener("click", () => window.location.reload());
    }
  }

  function formatRuntimeError(error) {
    if (!error) {
      return { message: "Script error.", detail: "Sem detalhes do erro." };
    }
    if (typeof error === "string") {
      return { message: error, detail: error };
    }
    const message = error.message || "Script error.";
    const detailParts = [
      message,
      error.filename ? `arquivo: ${error.filename}` : null,
      error.lineno ? `linha: ${error.lineno}` : null,
      error.colno ? `coluna: ${error.colno}` : null,
      error.stack ? `stack: ${error.stack}` : null,
    ].filter(Boolean);
    return { message, detail: detailParts.join(" | ") || message };
  }

  function renderBootErrorDetails(stage, error) {
    const root = getRoot();
    if (!root) return;
    const runtime = formatRuntimeError(error);
    root.innerHTML = `
      <div class="boot-error" role="alert">
        <strong>Erro ao carregar UI</strong>
        <div>${stage ? `${stage}: ` : ""}${runtime.message.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]))}</div>
        <pre>${runtime.detail.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]))}</pre>
        <button id="retryBootButton" type="button" class="primary">Tentar novamente</button>
      </div>
    `;
    const retryButton = document.getElementById("retryBootButton");
    if (retryButton) {
      retryButton.addEventListener("click", () => window.location.reload());
    }
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    });
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) throw new Error(payload && payload.detail ? payload.detail : response.statusText);
    return payload;
  }

  function fmt(value, fallback = "-") {
    if (value === null || value === undefined || value === "") return fallback;
    if (Array.isArray(value)) return value.join(", ");
    return String(value);
  }

  function detailRow(label, value) {
    return h("div", { className: "detail-row", key: label }, h("dt", null, label), h("dd", null, fmt(value)));
  }

  function getBgpEvidence(data) {
    if (!data) return null;
    if (data.bgp_evidence && typeof data.bgp_evidence === "object") return data.bgp_evidence;
    const raw = data.raw && typeof data.raw === "object" ? data.raw : null;
    if (raw?.bgp_evidence && typeof raw.bgp_evidence === "object") return raw.bgp_evidence;
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

  function renderBgpEvidenceDetail(data) {
    const evidence = getBgpEvidence(data);
    const context = data?.bgp_context && typeof data.bgp_context === "object"
      ? data.bgp_context
      : data?.raw?.bgp_context && typeof data.raw.bgp_context === "object"
        ? data.raw.bgp_context
        : null;
    if (!evidence && !context) return null;
    if (context) {
      return h(
        "div",
        { className: "detail-block" },
        h("strong", null, "BGP"),
        h("p", null, "IP privado/CGNAT: sem atribuição BGP direta."),
        h("div", { className: "detail-list" }, detailRow("Status", context.status), detailRow("Motivo", context.reason)),
      );
    }
    return h(
      "div",
      { className: "detail-block" },
      h("strong", null, "BGP LPM"),
      h(
        "div",
        { className: "detail-list" },
        detailRow("Prefixo", evidence.matched_prefix),
        detailRow("ASN origem", evidence.origin_asn ? `AS${evidence.origin_asn}` : "-"),
        detailRow("AS path", evidence.as_path),
        detailRow("Fonte", evidence.source),
        detailRow("Confiança", evidence.confidence),
      ),
    );
  }

  function legendItem(className, title, subtitle) {
    return h("div", { className: "legend-item", key: title }, h("span", { className: `legend-swatch ${className}` }), h("div", null, h("strong", null, title), h("span", null, subtitle)));
  }

  function sanitizeCyStyle(styleArray) {
    const blockedProperties = new Set([
      ["label", "margin", "y"].join("-"),
      ["background", "image", "containment"].join("-"),
    ]);
    const removed = [];
    const safe = [];
    for (const rule of styleArray || []) {
      if (!rule || typeof rule !== "object") continue;
      const selector = typeof rule.selector === "string" && rule.selector.trim() ? rule.selector.trim() : null;
      const style = rule.style && typeof rule.style === "object" ? rule.style : null;
      if (!selector || !style) continue;
      const nextStyle = {};
      for (const [property, value] of Object.entries(style)) {
        if (value === null || value === undefined || value === "") {
          removed.push({ selector, property, value });
          continue;
        }
        if (blockedProperties.has(property)) {
          removed.push({ selector, property, value });
          continue;
        }
        nextStyle[property] = value;
      }
      safe.push({ selector, style: nextStyle });
    }
    if (removed.length) console.warn("Cytoscape style sanitizado:", removed);
    return safe;
  }

  function buildNodeClasses(node) {
    const classes = [];
    if (node.is_cluster_summary) classes.push("cluster-summary", "cluster-container", "route-summary");
    else classes.push("hop");
    if (node.status === "origin") classes.push("origin");
    if (node.status === "destination") classes.push("destination");
    if (node.status === "timeout") classes.push("timeout");
    if (node.status === "unknown") classes.push("unknown");
    if (node.is_inferred) classes.push("inferred");
    if (node.status === "private") classes.push("private");
    if (node.status === "asn_enriched") classes.push("enriched");
    if (node.status === "high_latency") classes.push("high-latency");
    if (node.loss_percent) classes.push("packet-loss");
    if (!node.is_cluster_summary && node.cluster_id) classes.push("cluster-container");
    classes.push(`role-${resolveVisualRole(node, { summary: Boolean(node.is_cluster_summary) })}`);
    if (node.is_cluster_summary) {
      const kind = node.status || node.cluster_kind || node.summary?.type || "cluster";
      if (kind === "origin") classes.push("route-origin");
      else if (kind === "private") classes.push("route-private");
      else if (kind === "unknown" || kind === "anomaly") classes.push("route-unknown");
      else if (kind === "destination") classes.push("route-destination");
      else classes.push("route-cluster");
      if (node.has_high_latency) classes.push("route-high-latency");
      if (node.has_loss) classes.push("route-loss");
      if ((node.timeout_count ?? 0) > 0) classes.push("route-timeout");
    }
    return classes.join(" ");
  }

  function buildEdgeClasses(edge) {
    const classes = ["route-edge"];
    if (edge.latency_jump) classes.push("latency-jump");
    if (edge.status === "timeout") classes.push("timeout-edge");
    if (edge.status === "high_latency") classes.push("packet-loss");
    if (edge.is_inferred) classes.push("inferred-edge");
    return classes.join(" ");
  }

  function clusterRouteRank(cluster) {
    const kind = cluster?.type || cluster?.visual_state?.status || "cluster";
    if (kind === "origin") return 0;
    if (kind === "private") return 1;
    if (kind === "upstream" || kind === "ix" || kind === "ptt") return 2;
    if (kind === "unknown" || kind === "anomaly") return 3;
    if (kind === "destination") return 4;
    return 4;
  }

  function clusterRouteTitle(cluster) {
    return cluster?.name || (cluster?.asn ? `AS${cluster.asn}` : "Cluster");
  }

  function clusterRouteSubtitle(cluster) {
    return clusterRouteStatus(cluster);
  }

  function clusterRouteDescriptor(cluster) {
    const kind = cluster?.type || cluster?.cluster_kind || cluster?.visual_state?.status || "cluster";
    if (kind === "origin") return "Gateway de saída";
    if (kind === "private") return "Rede privada";
    if (kind === "unknown" || kind === "anomaly") return "ASN desconhecido";
    if (kind === "destination") return "Servidor / alvo";
    if (kind === "ix" || kind === "ptt") return "IX / PTT";
    if (kind === "upstream") return "Upstream / Internet";
    return cluster?.asn ? `AS${cluster.asn}` : cluster?.organization || "Cluster agregado";
  }

  function clusterRouteMetrics(cluster) {
    const bits = [`${cluster?.hops_count ?? 0} hops`];
    if ((cluster?.timeout_count ?? 0) > 0) bits.push(`${cluster.timeout_count} timeout${cluster.timeout_count === 1 ? "" : "s"}`);
    if ((cluster?.unknown_count ?? 0) > 0) bits.push(`${cluster.unknown_count} unknown`);
    if ((cluster?.inferred_count ?? 0) > 0) bits.push(`${cluster.inferred_count} inferido${cluster.inferred_count === 1 ? "" : "s"}`);
    if (cluster?.has_high_latency) bits.push("latência alta");
    if (cluster?.has_loss) bits.push("perda");
    return bits;
  }

  function clusterRouteClasses(cluster) {
    const kind = cluster?.type || cluster?.cluster_kind || cluster?.visual_state?.status || "cluster";
    const classes = ["route-summary", "cluster-summary", "cluster-container"];
    if (kind === "origin") classes.push("route-origin");
    else if (kind === "private") classes.push("route-private");
    else if (kind === "unknown" || kind === "anomaly") classes.push("route-unknown");
    else if (kind === "destination") classes.push("route-destination");
    else classes.push("route-cluster");
    if (cluster?.has_high_latency) classes.push("route-high-latency");
    if (cluster?.has_loss) classes.push("route-loss");
    if ((cluster?.timeout_count ?? 0) > 0) classes.push("route-timeout");
    return classes.join(" ");
  }

  function sanitizeCyElements(elements) {
    const nodes = new Set();
    const safe = [];
    for (const element of elements || []) {
      const data = element && element.data && typeof element.data === "object" ? element.data : null;
      if (!data || typeof data.id !== "string" || !data.id.trim()) continue;
      const isEdge = typeof data.source === "string" && data.source.trim() && typeof data.target === "string" && data.target.trim();
      if (isEdge) continue;
      const id = data.id.trim();
      const nextData = { ...data, id, label: typeof data.label === "string" ? data.label : "" };
      if (typeof nextData.parent === "string" && !nextData.parent.trim()) delete nextData.parent;
      if (nextData.kind === "cluster-summary") nextData.parent = null;
      safe.push({ data: nextData, classes: typeof element.classes === "string" ? element.classes : "" });
      nodes.add(id);
    }
    for (const element of elements || []) {
      const data = element && element.data && typeof element.data === "object" ? element.data : null;
      if (!data || typeof data.id !== "string" || !data.id.trim()) continue;
      const isEdge = typeof data.source === "string" && data.source.trim() && typeof data.target === "string" && data.target.trim();
      if (!isEdge) continue;
      const id = data.id.trim();
      const source = String(data.source).trim();
      const target = String(data.target).trim();
      if (!source || !target || !nodes.has(source) || !nodes.has(target)) continue;
      safe.push({ data: { ...data, id, source, target }, classes: typeof element.classes === "string" ? element.classes : "" });
    }
    return safe;
  }

  function svgDataUri(svg) {
    return `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(String(svg || "").replace(/\s+/g, " ").trim())}`;
  }

  function iconFrame({ bg0, bg1, stroke, accent, glyph, viewBox = "0 0 240 160" }) {
    return svgDataUri(`
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}">
        <defs>
          <linearGradient id="frame" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="${bg0}" />
            <stop offset="100%" stop-color="${bg1}" />
          </linearGradient>
          <radialGradient id="glow" cx="50%" cy="30%" r="70%">
            <stop offset="0%" stop-color="${accent}" stop-opacity="0.34" />
            <stop offset="100%" stop-color="${accent}" stop-opacity="0" />
          </radialGradient>
        </defs>
        <rect x="12" y="12" width="216" height="136" rx="24" fill="url(#frame)" stroke="${stroke}" stroke-width="3" />
        <rect x="20" y="20" width="200" height="44" rx="16" fill="url(#glow)" />
        ${glyph}
      </svg>
    `);
  }

  const NETWORK_ICON_SVGS = {
    gateway: iconFrame({
      bg0: "#0b2a2f",
      bg1: "#123b44",
      stroke: "#5eead4",
      accent: "#5eead4",
      glyph: `
        <rect x="38" y="48" width="84" height="42" rx="14" fill="#16313a" stroke="#7dd3fc" stroke-width="3" />
        <path d="M16 69h18" stroke="#a7f3d0" stroke-width="5" stroke-linecap="round" />
        <path d="M22 61l12 8-12 8" fill="none" stroke="#a7f3d0" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" />
        <path d="M122 61h18" stroke="#a7f3d0" stroke-width="5" stroke-linecap="round" />
        <path d="M122 77h18" stroke="#a7f3d0" stroke-width="5" stroke-linecap="round" />
        <circle cx="78" cy="69" r="8" fill="#a7f3d0" />
        <path d="M66 34h24" stroke="#7dd3fc" stroke-width="4" stroke-linecap="round" />
        <path d="M66 24h24" stroke="#7dd3fc" stroke-width="4" stroke-linecap="round" opacity=".75" />
      `,
    }),
    router: iconFrame({
      bg0: "#0d1d3b",
      bg1: "#162b55",
      stroke: "#60a5fa",
      accent: "#60a5fa",
      glyph: `
        <path d="M84 34l34 28-34 28-34-28 34-28z" fill="#12284e" stroke="#93c5fd" stroke-width="3" />
        <circle cx="84" cy="62" r="9" fill="#dbeafe" />
        <path d="M50 62H24" stroke="#93c5fd" stroke-width="5" stroke-linecap="round" />
        <path d="M118 62h26" stroke="#93c5fd" stroke-width="5" stroke-linecap="round" />
        <path d="M84 34V18" stroke="#93c5fd" stroke-width="5" stroke-linecap="round" />
        <path d="M84 90v16" stroke="#93c5fd" stroke-width="5" stroke-linecap="round" />
        <circle cx="42" cy="48" r="6" fill="#7dd3fc" />
        <circle cx="42" cy="76" r="6" fill="#7dd3fc" />
        <circle cx="126" cy="48" r="6" fill="#7dd3fc" />
        <circle cx="126" cy="76" r="6" fill="#7dd3fc" />
      `,
    }),
    private: iconFrame({
      bg0: "#1d2430",
      bg1: "#2a3444",
      stroke: "#94a3b8",
      accent: "#cbd5e1",
      glyph: `
        <path d="M84 26l42 16v24c0 24-16 38-42 52-26-14-42-28-42-52V42l42-16z" fill="#273244" stroke="#cbd5e1" stroke-width="3" />
        <path d="M84 52c-10 0-18 8-18 18v20h36V70c0-10-8-18-18-18z" fill="none" stroke="#e2e8f0" stroke-width="5" stroke-linecap="round" />
        <rect x="68" y="88" width="32" height="18" rx="6" fill="#cbd5e1" opacity=".9" />
      `,
    }),
    upstream: iconFrame({
      bg0: "#102647",
      bg1: "#173b64",
      stroke: "#7dd3fc",
      accent: "#38bdf8",
      glyph: `
        <path d="M54 86c-10 0-18-8-18-18 0-11 8-20 19-20 3-17 17-28 34-28 16 0 29 9 34 24 11 1 19 10 19 21 0 12-9 21-21 21H54z" fill="#152c4d" stroke="#7dd3fc" stroke-width="3" />
        <circle cx="83" cy="59" r="17" fill="none" stroke="#dbeafe" stroke-width="3" />
        <path d="M83 42v34M66 59h34" stroke="#dbeafe" stroke-width="3" stroke-linecap="round" />
        <path d="M83 24v16" stroke="#38bdf8" stroke-width="5" stroke-linecap="round" />
        <path d="M73 34l10-10 10 10" fill="none" stroke="#38bdf8" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" />
      `,
    }),
    asnKnown: iconFrame({
      bg0: "#10263b",
      bg1: "#17304f",
      stroke: "#38bdf8",
      accent: "#38bdf8",
      glyph: `
        <rect x="42" y="36" width="72" height="52" rx="14" fill="#152845" stroke="#7dd3fc" stroke-width="3" />
        <path d="M60 52h36M60 68h24" stroke="#e0f2fe" stroke-width="5" stroke-linecap="round" />
        <circle cx="128" cy="50" r="7" fill="#7dd3fc" />
        <circle cx="148" cy="50" r="7" fill="#7dd3fc" />
        <circle cx="128" cy="72" r="7" fill="#7dd3fc" />
        <circle cx="148" cy="72" r="7" fill="#7dd3fc" />
        <path d="M106 62h22" stroke="#7dd3fc" stroke-width="5" stroke-linecap="round" />
        <path d="M84 92l12 12 22-24" fill="none" stroke="#a7f3d0" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" />
      `,
    }),
    asnUnknown: iconFrame({
      bg0: "#2a1d12",
      bg1: "#3c2917",
      stroke: "#f59e0b",
      accent: "#fb923c",
      glyph: `
        <rect x="42" y="36" width="72" height="52" rx="14" fill="#43290f" stroke="#f59e0b" stroke-width="3" />
        <path d="M74 52c2-6 7-10 14-10 8 0 14 5 14 13 0 11-10 12-10 20" fill="none" stroke="#fde68a" stroke-width="6" stroke-linecap="round" />
        <circle cx="88" cy="76" r="4" fill="#fde68a" />
        <path d="M130 38l34 56h-68l34-56z" fill="#fdba74" fill-opacity=".14" stroke="#f59e0b" stroke-width="3" stroke-linejoin="round" />
      `,
    }),
    ix: iconFrame({
      bg0: "#1d1735",
      bg1: "#2b2150",
      stroke: "#c4b5fd",
      accent: "#a78bfa",
      glyph: `
        <rect x="34" y="46" width="172" height="46" rx="16" fill="#2a2246" stroke="#c4b5fd" stroke-width="3" />
        <path d="M52 68h136" stroke="#ddd6fe" stroke-width="5" stroke-linecap="round" />
        <path d="M84 52l-18 16 18 16" fill="none" stroke="#c4b5fd" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" />
        <path d="M156 52l18 16-18 16" fill="none" stroke="#c4b5fd" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" />
        <circle cx="68" cy="68" r="8" fill="#a78bfa" />
        <circle cx="172" cy="68" r="8" fill="#a78bfa" />
        <circle cx="120" cy="68" r="8" fill="#ddd6fe" />
      `,
    }),
    destination: iconFrame({
      bg0: "#2a1648",
      bg1: "#441f71",
      stroke: "#c4b5fd",
      accent: "#c084fc",
      glyph: `
        <rect x="44" y="34" width="80" height="22" rx="7" fill="#24124a" stroke="#c4b5fd" stroke-width="3" />
        <rect x="44" y="62" width="120" height="18" rx="7" fill="#24124a" stroke="#c4b5fd" stroke-width="3" />
        <rect x="44" y="86" width="120" height="18" rx="7" fill="#24124a" stroke="#c4b5fd" stroke-width="3" />
        <circle cx="178" cy="45" r="10" fill="none" stroke="#ddd6fe" stroke-width="4" />
        <circle cx="178" cy="45" r="4" fill="#ddd6fe" />
        <path d="M180 63l18 0" stroke="#ddd6fe" stroke-width="5" stroke-linecap="round" />
        <path d="M192 55l8 8-8 8" fill="none" stroke="#ddd6fe" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" />
      `,
    }),
    timeout: iconFrame({
      bg0: "#1b2432",
      bg1: "#273246",
      stroke: "#94a3b8",
      accent: "#f59e0b",
      glyph: `
        <circle cx="86" cy="70" r="34" fill="#1f2937" stroke="#94a3b8" stroke-width="3" stroke-dasharray="7 6" />
        <path d="M86 46v26" stroke="#e5e7eb" stroke-width="6" stroke-linecap="round" />
        <path d="M86 72l16 10" stroke="#e5e7eb" stroke-width="6" stroke-linecap="round" />
        <circle cx="86" cy="70" r="5" fill="#f59e0b" />
        <path d="M142 52h38M142 66h28M142 80h38" stroke="#cbd5e1" stroke-width="5" stroke-linecap="round" opacity=".7" />
      `,
    }),
    unknown: iconFrame({
      bg0: "#111827",
      bg1: "#1c2533",
      stroke: "#64748b",
      accent: "#94a3b8",
      glyph: `
        <circle cx="86" cy="70" r="34" fill="#111827" stroke="#64748b" stroke-width="3" />
        <path d="M74 54c1-7 7-12 16-12 10 0 17 6 17 16 0 12-10 13-10 22" fill="none" stroke="#e5e7eb" stroke-width="6" stroke-linecap="round" />
        <circle cx="86" cy="88" r="5" fill="#e5e7eb" />
        <path d="M140 52h34M140 66h22M140 80h34" stroke="#94a3b8" stroke-width="5" stroke-linecap="round" opacity=".55" />
      `,
    }),
    clusterCollapsed: iconFrame({
      bg0: "#081423",
      bg1: "#11253f",
      stroke: "#7dd3fc",
      accent: "#60a5fa",
      glyph: `
        <rect x="38" y="34" width="108" height="70" rx="18" fill="#0f1c2f" stroke="#7dd3fc" stroke-width="3" />
        <rect x="54" y="46" width="108" height="70" rx="18" fill="#12223a" stroke="#38bdf8" stroke-width="3" opacity=".92" />
        <path d="M76 64h64M76 82h44" stroke="#dbeafe" stroke-width="5" stroke-linecap="round" />
        <path d="M170 58h22M181 47v22" stroke="#7dd3fc" stroke-width="5" stroke-linecap="round" />
        <circle cx="160" cy="78" r="7" fill="#38bdf8" />
      `,
    }),
    clusterExpanded: iconFrame({
      bg0: "#08131d",
      bg1: "#0f1f31",
      stroke: "#94a3b8",
      accent: "#7dd3fc",
      glyph: `
        <rect x="28" y="24" width="184" height="112" rx="20" fill="#0b1422" stroke="#94a3b8" stroke-width="3" />
        <rect x="44" y="40" width="152" height="20" rx="8" fill="#13253f" />
        <rect x="44" y="70" width="152" height="16" rx="8" fill="#13253f" />
        <rect x="44" y="94" width="152" height="16" rx="8" fill="#13253f" />
        <circle cx="60" cy="50" r="6" fill="#7dd3fc" />
        <circle cx="76" cy="50" r="6" fill="#7dd3fc" />
        <circle cx="92" cy="50" r="6" fill="#7dd3fc" />
        <path d="M170 43h18M179 34v18" stroke="#7dd3fc" stroke-width="5" stroke-linecap="round" />
        <path d="M170 101h18M179 92v18" stroke="#7dd3fc" stroke-width="5" stroke-linecap="round" />
      `,
    }),
  };

  function normalizeRoleText(value) {
    return String(value || "").toLowerCase();
  }

  function resolveVisualRole(item, { summary = false, expanded = false } = {}) {
    const kind = normalizeRoleText(item?.type || item?.cluster_kind || item?.status || item?.visual_state?.status || item?.classification || "");
    const text = normalizeRoleText([item?.name, item?.organization, item?.asn_label, item?.label, item?.org].filter(Boolean).join(" "));
    if (summary) {
      if (kind === "origin") return "gateway";
      if (kind === "private") return "private";
      if (kind === "destination") return "destination";
      if (kind === "timeout") return "timeout";
      if (kind === "unknown" || kind === "anomaly") return "asn-unknown";
      if (kind === "ix" || kind === "ptt" || /(^|[^a-z0-9])(ix|ptt|ixp)([^a-z0-9]|$)/i.test(text)) return "ix";
      if (kind === "upstream" || /upstream|internet|transit|backbone|carrier/i.test(text)) return "upstream";
      if (kind === "asn_enriched" || kind === "asn" || item?.asn != null || item?.org) return "asn-known";
      return "unknown";
    }
    if (expanded) {
      return "cluster-expanded";
    }
    if (kind === "origin") return "gateway";
    if (kind === "destination") return "destination";
    if (kind === "timeout") return "timeout";
    if (kind === "unknown") return "unknown";
    if (kind === "private") return "private";
    if (kind === "asn_enriched" || kind === "asn" || item?.asn != null || item?.org) {
      if (kind === "ix" || kind === "ptt" || /(^|[^a-z0-9])(ix|ptt|ixp)([^a-z0-9]|$)/i.test(text)) return "ix";
      if (kind === "upstream" || /upstream|internet|transit|backbone|carrier/i.test(text)) return "upstream";
      return "asn-known";
    }
    return "router";
  }

  function hopCountLabel(count) {
    const total = Number(count || 0);
    return `${total} hop${total === 1 ? "" : "s"}`;
  }

  function clusterRouteStatus(cluster) {
    const role = resolveVisualRole(cluster, { summary: true });
    if (role === "gateway") return "Gateway local";
    if (role === "private") return "Rede privada";
    if (role === "destination") return "Destino final";
    if (role === "timeout") return "Timeout";
    if (role === "ix") return "IX / PTT";
    if (role === "upstream") return "Upstream / Internet";
    if (role === "asn-unknown") return "ASN desconhecido";
    if (role === "asn-known") return "ASN conhecido";
    return "Cluster agregado";
  }

  function clusterRouteLabel(cluster) {
    return `${clusterRouteTitle(cluster)}\n${hopCountLabel(cluster?.hops_count)}\n${clusterRouteStatus(cluster)}`;
  }

  function App() {
    const [payload, setPayload] = useState(null);
    const [status, setStatus] = useState("carregando...");
    const [selectedNodeId, setSelectedNodeId] = useState(null);
    const [selectedClusterId, setSelectedClusterId] = useState(null);
    const [selectedMode, setSelectedMode] = useState("operational");
    const [topologyMode, setTopologyMode] = useState(true);
    const [fullscreen, setFullscreen] = useState(false);
    const [clusterExpanded, setClusterExpanded] = useState({});
    const [visualizationName, setVisualizationName] = useState("Visual Traceroute");
    const [visualizations, setVisualizations] = useState([]);
    const [saveStatus, setSaveStatus] = useState("");
    const [bootError, setBootError] = useState("");
    const [debugInfo, setDebugInfo] = useState(null);
    const [topologyPreset, setTopologyPreset] = useState("clean");
    const cyRef = useRef(null);
    const canvasRef = useRef(null);
    const rafRef = useRef([]);

    const selectedNode = useMemo(() => payload?.nodes?.find((node) => node.id === selectedNodeId) || null, [payload, selectedNodeId]);
    const selectedCluster = useMemo(() => payload?.clusters?.find((cluster) => cluster.id === selectedClusterId) || null, [payload, selectedClusterId]);
    const clusterExpandedState = useMemo(() => {
      const next = {};
      for (const cluster of payload?.clusters || []) {
        next[cluster.id] = clusterExpanded[cluster.id] !== false;
      }
      return next;
    }, [payload, clusterExpanded]);

    const summary = useMemo(() => {
      if (!payload) return [];
      const destination = payload.nodes?.find((node) => node.status === "destination");
      return [
        ["Target", payload.metadata?.target_label || payload.metadata?.target || "-"],
        ["Measurement", payload.metadata?.measurement_id ?? "-"],
        ["Hops", payload.nodes?.length || 0],
        ["Clusters", payload.clusters?.length || 0],
        ["Timeouts", payload.nodes?.filter((node) => node.status === "timeout").length || 0],
        ["Maior latência", payload.clusters?.reduce((max, cluster) => Math.max(max, Number(cluster.max_latency_ms || 0)), 0) || 0],
        ["ASN destino", destination?.asn_label || destination?.asn || "-"],
        ["Status", payload.metadata?.status || "-"],
      ];
    }, [payload]);

    function fitGraph() {
      safeResizeFitCenter(cyRef.current, "button", 0);
    }

    function zoom(delta) {
      const cy = cyRef.current;
      if (!isCyReady(cy)) return;
      try {
        const next = Math.max(0.25, Math.min(2.25, cy.zoom() + delta));
        if (!cy.destroyed()) cy.zoom(next);
      } catch (error) {
        console.warn("Zoom ignorado: Cytoscape não está pronto", formatRuntimeError(error).detail);
      }
    }

    function toggleFullscreen() {
      setFullscreen((value) => !value);
    }

    function toggleCluster(clusterId) {
      setClusterExpanded((current) => ({ ...current, [clusterId]: current[clusterId] === false }));
    }

    function isClusterExpanded(clusterId) {
      return clusterExpandedState[clusterId] !== false;
    }

    function setHighlightState(cy, selectedId = null) {
      if (!isCyReady(cy)) return;
      cy.elements().removeClass("dimmed focused-path");
      if (!selectedId) return;
      const selected = cy.getElementById(selectedId);
      if (!selected || !selected.length) return;
      cy.elements().not(selected).addClass("dimmed");
      selected.addClass("focused-path");
      selected.connectedEdges().addClass("focused-path");
      selected.connectedEdges().connectedNodes().addClass("focused-path");
    }

    function clearPendingFrames() {
      for (const frameId of rafRef.current) {
        cancelAnimationFrame(frameId);
      }
      rafRef.current = [];
    }

    function scheduleFitCenter(cy, reason) {
      clearPendingFrames();
      const firstFrame = requestAnimationFrame(() => {
        const secondFrame = requestAnimationFrame(() => {
          rafRef.current = rafRef.current.filter((id) => id !== firstFrame && id !== secondFrame);
          safeResizeFitCenter(cy, reason, 0);
        });
        rafRef.current.push(secondFrame);
      });
      rafRef.current.push(firstFrame);
    }

    function isCyReady(cy) {
      if (!cy || typeof cy.destroyed !== "function" || cy.destroyed()) return false;
      if (typeof cy.container !== "function") return false;
      const container = cy.container();
      if (!container || !container.offsetWidth || !container.offsetHeight) return false;
      if (typeof cy.elements !== "function" || !cy.elements().length) return false;
      return true;
    }

    function safeResizeFitCenter(cy, reason, attempt = 0) {
      try {
        if (!cy || (typeof cy.destroyed === "function" && cy.destroyed())) {
          console.warn("Cytoscape não pronto para centralizar", { reason, attempt, state: "destroyed-or-missing" });
          return;
        }
        const container = typeof cy.container === "function" ? cy.container() : null;
        if (!container || !container.offsetWidth || !container.offsetHeight) {
          if (attempt < 3) {
            window.setTimeout(() => safeResizeFitCenter(cy, reason, attempt + 1), 100);
            return;
          }
          console.warn("Container do grafo sem dimensão válida", { reason, attempt });
          setDebugInfo((current) => ({ ...(current || {}), fitWarning: "Container do grafo sem dimensão válida", fitReason: reason }));
          return;
        }
        if (!isCyReady(cy)) {
          console.warn("Cytoscape ainda não está pronto para centralizar", { reason, attempt });
          return;
        }
        cy.resize();
        const elements = cy.elements();
        if (!elements.length) return;
        const padding = topologyPreset === "clean" ? 100 : topologyMode ? 90 : 110;
        cy.fit(elements, padding);
        const zoomFloor = topologyPreset === "clean" ? 0.92 : topologyMode ? 0.78 : 0.68;
        if (!cy.destroyed() && cy.zoom() < zoomFloor) cy.zoom(zoomFloor);
        if (!cy.destroyed()) cy.center(elements);
        if (!cy.destroyed() && (!Number.isFinite(cy.zoom()) || cy.zoom() <= 0.05)) {
          cy.zoom(topologyPreset === "clean" ? 0.92 : 0.9);
          cy.center(elements);
        }
        setDebugInfo((current) => ({ ...(current || {}), ...getCyDiagnostics(cy), fitReason: reason }));
      } catch (error) {
        const runtime = formatRuntimeError(error);
        console.warn("Falha não fatal ao centralizar Cytoscape", { reason, attempt, error: runtime.detail });
        setDebugInfo((current) => ({ ...(current || {}), fitWarning: runtime.message, fitReason: reason }));
      }
    }

    function getCyDiagnostics(cy) {
      if (!cy || (typeof cy.destroyed === "function" && cy.destroyed())) return {};
      try {
        const elements = typeof cy.elements === "function" ? cy.elements() : null;
        return {
          cyElements: elements ? elements.length : 0,
          cyNodes: typeof cy.nodes === "function" ? cy.nodes().length : 0,
          cyEdges: typeof cy.edges === "function" ? cy.edges().length : 0,
          boundingBox: elements && elements.length ? elements.boundingBox() : null,
          extent: typeof cy.extent === "function" ? cy.extent() : null,
          zoom: typeof cy.zoom === "function" ? cy.zoom() : null,
          pan: typeof cy.pan === "function" ? cy.pan() : null,
        };
      } catch (error) {
        return { diagnosticError: formatRuntimeError(error).message };
      }
    }

    function applyTopologyPreset(preset) {
      setTopologyPreset(preset);
      if (!payload?.clusters?.length) return;
      if (preset === "complete") {
        const next = {};
        for (const cluster of payload.clusters) next[cluster.id] = true;
        setClusterExpanded(next);
        setTopologyMode(true);
        return;
      }
      const next = {};
      for (const cluster of payload.clusters) next[cluster.id] = false;
      setClusterExpanded(next);
      setTopologyMode(true);
    }

    function clusterSummary(cluster) {
      const stateBits = [];
      if (cluster.visual_state?.has_timeout) stateBits.push(`timeouts ${cluster.timeout_count}`);
      if (cluster.visual_state?.has_anomaly) stateBits.push("anomalia");
      if (cluster.visual_state?.has_loss) stateBits.push("perda");
      if (cluster.visual_state?.has_inferred) stateBits.push("inferido");
      return {
        id: cluster.id,
        name: cluster.name,
        type: cluster.type,
        label: `${cluster.asn ? `AS${cluster.asn}` : cluster.name} · ${cluster.hops_count} hops${stateBits.length ? ` · ${stateBits.join(" · ")}` : ""}`,
        kind: "cluster",
        cluster_kind: cluster.type,
        organization: cluster.organization,
        visual_state: cluster.visual_state,
        color: cluster.color,
        expanded: isClusterExpanded(cluster.id),
        hops_count: cluster.hops_count,
        timeout_count: cluster.timeout_count,
        unknown_count: cluster.unknown_count,
        inferred_count: cluster.inferred_count,
        has_high_latency: cluster.has_high_latency,
        has_loss: cluster.has_loss,
      };
    }

    function visibleClusterNodes(cluster) {
      return (payload?.nodes || []).filter((node) => node.cluster_id === cluster.id);
    }

    function getRouteClusters() {
      const clusters = [...(payload?.clusters || [])];
      const nodes = payload?.nodes || [];
      const stats = new Map(clusters.map((cluster, index) => [cluster.id, { cluster, minHop: Number.POSITIVE_INFINITY, firstIndex: index }]));
      nodes.forEach((node, index) => {
        if (!node?.cluster_id || !stats.has(node.cluster_id)) return;
        const entry = stats.get(node.cluster_id);
        const hop = Number(node.hop);
        if (Number.isFinite(hop)) entry.minHop = Math.min(entry.minHop, hop);
        entry.firstIndex = Math.min(entry.firstIndex, index);
      });
      return clusters.sort((a, b) => {
        const left = stats.get(a.id);
        const right = stats.get(b.id);
        const leftHop = left?.minHop ?? Number.POSITIVE_INFINITY;
        const rightHop = right?.minHop ?? Number.POSITIVE_INFINITY;
        return leftHop - rightHop || clusterRouteRank(a) - clusterRouteRank(b) || (left?.firstIndex ?? 0) - (right?.firstIndex ?? 0) || String(a.id).localeCompare(String(b.id));
      });
    }

    function buildVisibleGraphModel() {
      const visibleNodes = [];
      const visibleClusters = [];
      const visibleEdges = [];
      const nodePositions = payload?.node_positions || {};
      const orderedClusters = getRouteClusters();

      if (topologyPreset === "clean") {
        const orderedClusterIds = orderedClusters.map((cluster) => cluster.id);
        orderedClusters.forEach((cluster, index) => {
          const summaryLabel = [
            clusterRouteTitle(cluster),
            hopCountLabel(cluster.hops_count),
            clusterRouteStatus(cluster),
          ].filter(Boolean).join("\n");
          visibleClusters.push({
            ...clusterSummary(cluster),
            route_index: index,
            route_title: clusterRouteTitle(cluster),
            route_subtitle: clusterRouteSubtitle(cluster),
            route_descriptor: clusterRouteDescriptor(cluster),
            route_metrics: clusterRouteMetrics(cluster),
            visual_role: resolveVisualRole(cluster, { summary: true }),
          });
          visibleNodes.push({
            id: `cluster:${cluster.id}`,
            hop: (visibleClusterNodes(cluster)[0] || {}).hop || 0,
            ip: null,
            hostname: null,
            asn: cluster.asn,
            asn_label: cluster.name,
            org: cluster.organization,
            latency_ms: cluster.avg_latency_ms,
            loss_percent: cluster.avg_loss_percent,
            status: cluster.type || cluster.visual_state?.status || "cluster",
            classification: "cluster_summary",
            cluster_id: cluster.id,
            visual_state: { ...cluster.visual_state, status: cluster.type || cluster.visual_state?.status || "normal" },
            source: "aggregated",
            is_inferred: true,
            is_cluster_summary: true,
            summary: cluster,
            node_positions: { x: 220 + index * 460, y: 330 },
            label: summaryLabel,
            classes: `${clusterRouteClasses(cluster)} role-${resolveVisualRole(cluster, { summary: true })}`,
          });
        });

        const summaryEdgeState = new Map();
        for (const edge of payload?.edges || []) {
          const sourceNode = (payload?.nodes || []).find((node) => node.id === edge.source);
          const targetNode = (payload?.nodes || []).find((node) => node.id === edge.target);
          if (!sourceNode || !targetNode) continue;
          const sourceIndex = orderedClusterIds.indexOf(sourceNode.cluster_id);
          const targetIndex = orderedClusterIds.indexOf(targetNode.cluster_id);
          if (sourceIndex < 0 || targetIndex < 0) continue;
          const prevIndex = Math.min(sourceIndex, targetIndex);
          const nextIndex = Math.max(sourceIndex, targetIndex);
          if (nextIndex !== prevIndex + 1) continue;
          const key = `${orderedClusterIds[prevIndex]}->${orderedClusterIds[nextIndex]}`;
          const current = summaryEdgeState.get(key) || { latency_jump: false, is_inferred: false, status: "normal", rtt_delta_ms: null };
          current.latency_jump = current.latency_jump || Boolean(edge.latency_jump);
          current.is_inferred = current.is_inferred || Boolean(edge.is_inferred);
          current.status = current.status === "timeout" || edge.status === "timeout" ? "timeout" : current.status;
          current.rtt_delta_ms = current.rtt_delta_ms ?? edge.rtt_delta_ms ?? null;
          summaryEdgeState.set(key, current);
        }

        for (let index = 0; index < orderedClusters.length - 1; index += 1) {
          const left = orderedClusters[index];
          const right = orderedClusters[index + 1];
          const aggregate = summaryEdgeState.get(`${left.id}->${right.id}`) || { status: "normal", latency_jump: false, is_inferred: false, rtt_delta_ms: null };
          visibleEdges.push({
            id: `summary:${left.id}->${right.id}`,
            source: `cluster:${left.id}`,
            target: `cluster:${right.id}`,
            kind: "edge",
            latency_jump: aggregate.latency_jump,
            rtt_delta_ms: aggregate.rtt_delta_ms,
            status: aggregate.status,
            is_inferred: aggregate.is_inferred,
            label: `${clusterRouteTitle(left)} → ${clusterRouteTitle(right)}`,
            classes: `${buildEdgeClasses(aggregate)} summary-route-edge`,
          });
        }

        return { visibleNodes, visibleClusters, visibleEdges, nodePositions };
      }

      for (const cluster of payload?.clusters || []) {
        const expanded = isClusterExpanded(cluster.id);
          visibleClusters.push({
            ...clusterSummary(cluster),
            route_title: clusterRouteTitle(cluster),
            route_subtitle: clusterRouteSubtitle(cluster),
            route_metrics: clusterRouteMetrics(cluster),
            visual_role: resolveVisualRole(cluster, { expanded: true }),
          });
          if (expanded) {
          for (const node of visibleClusterNodes(cluster)) {
            visibleNodes.push(node);
          }
        } else {
          const firstNode = visibleClusterNodes(cluster)[0] || null;
          const clusterIndex = (payload?.clusters || []).findIndex((item) => item.id === cluster.id);
          const positions = visibleClusterNodes(cluster).map((node) => nodePositions[node.id]).filter(Boolean);
          const fallbackX = 220 + Math.max(0, clusterIndex) * 280;
          const fallbackY = 260;
          const x = positions.length ? positions.reduce((sum, pos) => sum + pos.x, 0) / positions.length : fallbackX;
          const y = positions.length ? positions.reduce((sum, pos) => sum + pos.y, 0) / positions.length : fallbackY;
          visibleNodes.push({
            id: `cluster:${cluster.id}`,
            hop: firstNode?.hop || 0,
            ip: null,
            hostname: null,
            asn: cluster.asn,
            asn_label: cluster.name,
            org: cluster.organization,
            latency_ms: cluster.avg_latency_ms,
            loss_percent: cluster.avg_loss_percent,
            status: cluster.visual_state?.status || "cluster",
            classification: "cluster_summary",
            cluster_id: cluster.id,
            visual_state: { ...cluster.visual_state, status: cluster.visual_state?.status || "normal" },
            source: "aggregated",
            is_inferred: true,
            is_cluster_summary: true,
            summary: cluster,
            node_positions: { x, y },
            label: clusterRouteLabel(cluster),
            classes: `${clusterRouteClasses(cluster)} role-${resolveVisualRole(cluster, { summary: true })}`,
          });
        }
      }
      const edges = payload?.edges || [];
      const nodesById = new Map((payload?.nodes || []).map((node) => [node.id, node]));

      for (const edge of edges) {
        const sourceNode = nodesById.get(edge.source);
        const targetNode = nodesById.get(edge.target);
        if (!sourceNode || !targetNode) continue;
        const sourceVisible = isClusterExpanded(sourceNode.cluster_id) ? sourceNode.id : `cluster:${sourceNode.cluster_id}`;
        const targetVisible = isClusterExpanded(targetNode.cluster_id) ? targetNode.id : `cluster:${targetNode.cluster_id}`;
        if (sourceVisible === targetVisible) continue;
        visibleEdges.push({
          id: `${edge.source}->${edge.target}->${sourceVisible}->${targetVisible}`,
          source: sourceVisible,
          target: targetVisible,
          kind: "edge",
          latency_jump: edge.latency_jump,
          rtt_delta_ms: edge.rtt_delta_ms,
          status: edge.status,
          is_inferred: edge.is_inferred,
        });
      }

      const dedupedEdges = [];
      const seen = new Set();
      for (const edge of visibleEdges) {
        const key = `${edge.source}->${edge.target}`;
        if (seen.has(key)) continue;
        seen.add(key);
        dedupedEdges.push(edge);
      }

      return { visibleNodes, visibleClusters, visibleEdges: dedupedEdges, nodePositions };
    }

    function load() {
      setBootMessage("Carregando RouteBrain Visual Traceroute...");
      setStatus("carregando...");
      api("/traceroute-visual/latest")
        .then((data) => {
          setPayload(data);
          setStatus(data.source === "fixture" ? "usando fixture local" : "dado real do banco");
          setTopologyMode(true);
          setVisualizationName(data.metadata?.visualization_name || "Visual Traceroute");
          setSelectedMode(data.selected_view_mode || "operational");
          setClusterExpanded(data.cluster_state || {});
          setTopologyPreset("clean");
          if (!selectedNodeId && data.nodes?.length) {
            const first = data.nodes.find((node) => node.status === "origin") || data.nodes[0];
            setSelectedNodeId(first.id);
            setSelectedClusterId(first.cluster_id);
          }
          loadSavedVisualizations();
        })
          .catch((error) => {
            console.error(error);
            setStatus("falha ao carregar");
            setBootError(error instanceof Error ? error.message : String(error || "Erro inesperado."));
          });
    }

    function loadSavedVisualizations() {
      api("/traceroute-visual/visualizations")
        .then((items) => setVisualizations(Array.isArray(items) ? items : []))
        .catch((error) => {
          console.error(error);
          setSaveStatus("não foi possível carregar visualizações salvas");
        });
    }

    function buildSavePayload() {
      if (!payload) return null;
      const visible = buildVisibleGraphModel();
      return {
        name: visualizationName || payload.metadata?.visualization_name || "Visual Traceroute",
        description: payload.notes || null,
        measurement_id: payload.metadata?.measurement_id ?? null,
        target: payload.metadata?.target ?? null,
        source_label: payload.metadata?.measurement?.source_label ?? null,
        graph_version: payload.metadata?.graph_version || "traceroute-visual-v2",
        layout_algorithm: payload.metadata?.layout_algorithm || "deterministic-asn-columns",
        selected_view_mode: topologyMode ? "topology" : "operational",
        payload: {
          ...payload,
          selected_view_mode: topologyMode ? "topology" : "operational",
          cluster_state: clusterExpandedState,
          node_positions: visible.nodePositions || payload.node_positions || {},
          filters: payload.filters || {},
        },
        node_positions: visible.nodePositions || payload.node_positions || {},
        cluster_state: clusterExpandedState,
        filters: payload.filters || {},
        notes: {
          saved_from_ui: true,
          mode: topologyMode ? "topology" : "operational",
          selected_node_id: selectedNodeId,
          selected_cluster_id: selectedClusterId,
          source: payload.source,
        },
      };
    }

    function saveVisualization() {
      const body = buildSavePayload();
      if (!body) return;
      setSaveStatus("salvando...");
      api("/traceroute-visual/visualizations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
        .then((saved) => {
          setSaveStatus(`visualização salva: ${saved.visualization_uid}`);
          setVisualizationName(saved.name || visualizationName);
          loadSavedVisualizations();
        })
        .catch((error) => {
          console.error(error);
          setSaveStatus(`erro ao salvar: ${error.message}`);
        });
    }

    function openVisualization(visualizationUid) {
      setSaveStatus("abrindo visualização...");
      api(`/traceroute-visual/visualizations/${encodeURIComponent(visualizationUid)}`)
        .then((data) => {
          const nextPayload = data.payload || data;
          setPayload({
            ...nextPayload,
            node_positions: data.node_positions || nextPayload.node_positions || {},
            cluster_state: data.cluster_state || nextPayload.cluster_state || {},
            filters: data.filters || nextPayload.filters || {},
            selected_view_mode: data.selected_view_mode || nextPayload.selected_view_mode || "operational",
          });
          setVisualizationName(data.name || "Visual Traceroute");
          setTopologyMode(true);
          setSelectedMode(data.selected_view_mode || "operational");
          setClusterExpanded(data.cluster_state || {});
          setTopologyPreset("clean");
          setStatus(`visualização carregada: ${data.visualization_uid}`);
          setSaveStatus(`aberta: ${data.visualization_uid}`);
        })
        .catch((error) => {
          console.error(error);
          setSaveStatus(`erro ao abrir: ${error.message}`);
        });
    }

    useEffect(() => {
      loadSavedVisualizations();
      load();
    }, []);

    useEffect(() => {
      document.body.classList.toggle("topology-mode", topologyMode);
      document.body.classList.toggle("fullscreen-topology", fullscreen);
    }, [topologyMode, fullscreen]);

    useEffect(() => {
      if (!payload?.clusters?.length) return;
      if (topologyPreset === "complete") {
        const next = {};
        for (const cluster of payload.clusters) next[cluster.id] = true;
        setClusterExpanded(next);
      } else if (topologyPreset === "clean") {
        const next = {};
        for (const cluster of payload.clusters) next[cluster.id] = false;
        setClusterExpanded(next);
      }
    }, [payload, topologyPreset]);

    useEffect(() => {
      if (!payload || !canvasRef.current || !CytoscapeGlobal) return;
      try {
        clearPendingFrames();
        if (cyRef.current && typeof cyRef.current.destroyed === "function" && !cyRef.current.destroyed()) cyRef.current.destroy();

        const visible = buildVisibleGraphModel();
        const elements = [];
        if (topologyPreset !== "clean") {
          for (const cluster of visible.visibleClusters) {
            elements.push({
              classes: `${clusterRouteClasses(cluster)} role-${resolveVisualRole(cluster, { expanded: true })}`,
              data: {
                id: String(cluster.id || "").trim(),
                label: clusterRouteLabel(cluster),
                kind: "cluster",
                cluster_kind: cluster.type,
                organization: cluster.organization,
                visual_state: cluster.visual_state,
                color: cluster.color,
                expanded: cluster.expanded,
                hops_count: cluster.hops_count,
                timeout_count: cluster.timeout_count,
                unknown_count: cluster.unknown_count,
                inferred_count: cluster.inferred_count,
                has_high_latency: cluster.has_high_latency,
                has_loss: cluster.has_loss,
                visual_role: resolveVisualRole(cluster, { expanded: true }),
              },
            });
          }
        }
        for (const node of visible.visibleNodes) {
        elements.push({
          classes: buildNodeClasses(node),
          data: {
              id: String(node.id || "").trim(),
              label: node.label || (node.is_cluster_summary ? `${node.summary?.name || node.cluster_id || "Cluster"}` : node.ip || `TTL ${node.hop ?? "-"}`),
              parent: node.is_cluster_summary ? null : String(node.cluster_id || "").trim() || null,
              kind: node.is_cluster_summary ? "cluster-summary" : "hop",
              hop: node.hop,
              ip: node.ip,
              hostname: node.hostname,
              asn: node.asn,
              asn_label: node.asn_label,
              org: node.org,
              latency_ms: node.latency_ms,
              loss_percent: node.loss_percent,
              status: node.status,
              classification: node.classification,
              cluster_id: node.cluster_id,
              visual_state: node.visual_state,
              source: node.source,
              is_inferred: node.is_inferred,
              is_cluster_summary: node.is_cluster_summary,
              visual_role: node.is_cluster_summary ? resolveVisualRole(node, { summary: true }) : resolveVisualRole(node),
              summary: node.summary ? JSON.stringify(node.summary) : "",
            },
          });
        }
        for (const edge of visible.visibleEdges) {
          elements.push({
            classes: buildEdgeClasses(edge),
            data: {
              id: edge.id,
              source: edge.source,
              target: edge.target,
              kind: "edge",
              latency_jump: edge.latency_jump,
              rtt_delta_ms: edge.rtt_delta_ms,
              status: edge.status,
              is_inferred: edge.is_inferred,
            },
          });
        }

        const container = canvasRef.current;
        const containerWidth = container.offsetWidth;
        const containerHeight = container.offsetHeight;
        if (!containerWidth || !containerHeight) {
          throw new Error("Container do grafo sem dimensão válida.");
        }
        console.debug("Traceroute graph bootstrap", {
          payloadNodes: payload.nodes?.length || 0,
          payloadEdges: payload.edges?.length || 0,
          payloadClusters: payload.clusters?.length || 0,
          visibleNodes: visible.visibleNodes.length,
          visibleEdges: visible.visibleEdges.length,
          visibleClusters: visible.visibleClusters.length,
          elementsNodes: elements.filter((element) => !(element.data.source && element.data.target)).length,
          elementsEdges: elements.filter((element) => element.data.source && element.data.target).length,
          containerWidth,
          containerHeight,
          topologyMode,
          topologyPreset,
          expandedClusters: Object.values(clusterExpandedState).filter(Boolean).length,
          collapsedClusters: Object.values(clusterExpandedState).filter((value) => value === false).length,
          firstNodes: elements.filter((element) => !(element.data.source && element.data.target)).slice(0, 3).map((element) => ({ data: element.data, classes: element.classes })),
          firstEdges: elements.filter((element) => element.data.source && element.data.target).slice(0, 3).map((element) => ({ data: element.data, classes: element.classes })),
        });

        const cy = CytoscapeGlobal({
          container,
          elements: sanitizeCyElements(elements),
          layout: { name: "preset" },
          style: sanitizeCyStyle([
          {
            selector: "node",
            style: {
              label: "data(label)",
              color: "#e5e7eb",
              "font-size": 12,
              "text-wrap": "wrap",
              "text-max-width": 170,
              "text-valign": "center",
              "text-halign": "center",
              width: 96,
              height: 96,
              "background-color": "#111827",
              "border-width": 2,
              "border-color": "#334155",
            },
          },
          {
            selector: "node[kind = 'cluster']",
            style: {
              shape: "round-rectangle",
              "background-color": "data(color)",
              "background-opacity": 0.22,
              "border-color": "data(color)",
              "border-width": 3,
              label: "data(label)",
              "font-size": 13,
              "text-valign": "top",
              "text-halign": "center",
              "text-margin-y": 10,
              padding: "22px",
              width: 320,
              height: 240,
            },
          },
          {
            selector: "node[kind = 'hop']",
            style: {
              shape: "round-rectangle",
              "background-opacity": 0.98,
              "text-margin-y": 20,
              "text-background-color": "#06101c",
              "text-background-opacity": 0.54,
              "text-background-padding": "2px",
              "text-border-width": 0,
              width: 112,
              height: 100,
            },
          },
          {
            selector: "node[kind = 'cluster-summary']",
            style: {
              shape: "round-rectangle",
              "background-color": "#0b1220",
              "background-opacity": 0.98,
              "border-color": "data(color)",
              "border-width": 3,
              "font-size": 15,
              width: 340,
              height: 214,
              label: "data(label)",
              "text-valign": "top",
              "text-halign": "center",
              "text-wrap": "wrap",
              "text-max-width": 230,
              "text-margin-y": 14,
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'origin']",
            style: {
              "background-color": "#0f766e",
              "border-color": "#5eead4",
              shape: "round-rectangle",
              width: 142,
              height: 110,
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='128' height='96' viewBox='0 0 128 96'><rect x='8' y='10' rx='18' ry='18' width='112' height='76' fill='%230f766e' stroke='%235eead4' stroke-width='3'/><rect x='26' y='28' rx='8' width='44' height='18' fill='%2315333b'/><circle cx='88' cy='31' r='5' fill='%23a7f3d0'/><circle cx='88' cy='47' r='5' fill='%23a7f3d0'/><circle cx='88' cy='63' r='5' fill='%23a7f3d0'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'destination']",
            style: {
              "background-color": "#6d28d9",
              "border-color": "#c4b5fd",
              shape: "round-rectangle",
              width: 146,
              height: 112,
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='132' height='98' viewBox='0 0 132 98'><rect x='8' y='10' rx='18' ry='18' width='116' height='78' fill='%236d28d9' stroke='%23c4b5fd' stroke-width='3'/><path d='M44 24h44v22H44z' fill='%2324174d'/><path d='M44 52h44v18H44z' fill='%2324174d'/><circle cx='96' cy='30' r='6' fill='%23ddd6fe'/><circle cx='96' cy='48' r='6' fill='%23ddd6fe'/><circle cx='96' cy='66' r='6' fill='%23ddd6fe'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'timeout']",
            style: {
              "background-color": "#1f2937",
              "border-color": "#94a3b8",
              "border-style": "dashed",
              width: 104,
              height: 104,
              shape: "ellipse",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='92' height='92' viewBox='0 0 92 92'><circle cx='46' cy='46' r='36' fill='%231f2937' stroke='%2394a3b8' stroke-width='3'/><path d='M46 25v26' stroke='%23f8fafc' stroke-width='5' stroke-linecap='round'/><circle cx='46' cy='60' r='4' fill='%23f59e0b'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'unknown']",
            style: {
              "background-color": "#111827",
              "border-color": "#64748b",
              width: 104,
              height: 104,
              shape: "ellipse",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='92' height='92' viewBox='0 0 92 92'><circle cx='46' cy='46' r='36' fill='%23111827' stroke='%2364748b' stroke-width='3'/><path d='M38 36c1-6 6-10 13-10 8 0 14 5 14 13 0 10-11 11-11 20' stroke='%23e5e7eb' stroke-width='5' stroke-linecap='round' fill='none'/><circle cx='46' cy='66' r='4' fill='%23e5e7eb'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'high_latency']",
            style: {
              "background-color": "#3f2c10",
              "border-color": "#f59e0b",
              width: 116,
              height: 104,
              shape: "round-rectangle",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'asn_enriched']",
            style: {
              "background-color": "#10253a",
              "border-color": "#38bdf8",
              width: 116,
              height: 104,
              shape: "round-rectangle",
            },
          },
          {
            selector: "node[kind = 'hop'][status = 'private']",
            style: {
              "background-color": "#1e293b",
              "border-color": "#94a3b8",
              width: 112,
              height: 100,
              shape: "round-rectangle",
            },
          },
          {
            selector: "node[kind = 'cluster-summary']",
            style: {
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='160' viewBox='0 0 240 160'><rect x='10' y='10' width='220' height='140' rx='22' fill='%230b1220' stroke='%2394a3b8' stroke-width='2'/><rect x='24' y='24' width='192' height='26' rx='10' fill='%23111c33'/><circle cx='40' cy='72' r='8' fill='%237dd3fc'/><circle cx='64' cy='72' r='8' fill='%237dd3fc'/><circle cx='88' cy='72' r='8' fill='%237dd3fc'/><circle cx='112' cy='72' r='8' fill='%237dd3fc'/><circle cx='136' cy='72' r='8' fill='%237dd3fc'/><circle cx='160' cy='72' r='8' fill='%237dd3fc'/><circle cx='184' cy='72' r='8' fill='%237dd3fc'/><path d='M34 110h172' stroke='%23304a6e' stroke-width='4' stroke-linecap='round'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary",
            style: {
              shape: "round-rectangle",
              "background-color": "#0b1220",
              "background-opacity": 0.98,
              "border-width": 4,
              "border-color": "#7dd3fc",
              width: 392,
              height: 236,
              label: "data(label)",
              color: "#f8fafc",
              "font-size": 16,
              "font-weight": 800,
              "text-wrap": "wrap",
              "text-max-width": 300,
              "text-valign": "center",
              "text-halign": "center",
              "text-margin-y": 0,
              "text-background-color": "#06101c",
              "text-background-opacity": 0.72,
              "text-background-padding": "4px",
              padding: "26px",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary.route-origin",
            style: {
              "background-color": "#0f766e",
              "border-color": "#5eead4",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='160' viewBox='0 0 240 160'><rect x='16' y='18' width='208' height='124' rx='24' fill='%230f766e' stroke='%235eead4' stroke-width='3'/><rect x='42' y='44' width='58' height='26' rx='8' fill='%2315333b'/><rect x='42' y='78' width='106' height='16' rx='8' fill='%2315333b'/><circle cx='164' cy='56' r='8' fill='%23a7f3d0'/><circle cx='164' cy='80' r='8' fill='%23a7f3d0'/><circle cx='164' cy='104' r='8' fill='%23a7f3d0'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary.route-private",
            style: {
              "background-color": "#1e293b",
              "border-color": "#94a3b8",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='160' viewBox='0 0 240 160'><rect x='16' y='18' width='208' height='124' rx='24' fill='%231e293b' stroke='%2394a3b8' stroke-width='3'/><rect x='38' y='44' width='164' height='20' rx='8' fill='%232f3f53'/><circle cx='56' cy='92' r='10' fill='%2394a3b8'/><circle cx='92' cy='92' r='10' fill='%2394a3b8'/><circle cx='128' cy='92' r='10' fill='%2394a3b8'/><circle cx='164' cy='92' r='10' fill='%2394a3b8'/><path d='M56 92h108' stroke='%23cbd5e1' stroke-width='4' stroke-linecap='round'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary.route-unknown",
            style: {
              "background-color": "#3f2c10",
              "border-color": "#f59e0b",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='160' viewBox='0 0 240 160'><rect x='16' y='18' width='208' height='124' rx='24' fill='%233f2c10' stroke='%23f59e0b' stroke-width='3'/><path d='M120 42l34 58H86l34-58z' fill='%23fb923c' fill-opacity='.32' stroke='%23f59e0b' stroke-width='4' stroke-linejoin='round'/><path d='M120 66v20' stroke='%23fef3c7' stroke-width='6' stroke-linecap='round'/><circle cx='120' cy='94' r='4' fill='%23fef3c7'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary.route-destination",
            style: {
              "background-color": "#4c1d95",
              "border-color": "#c4b5fd",
              "background-image": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='240' height='160' viewBox='0 0 240 160'><rect x='16' y='18' width='208' height='124' rx='24' fill='%234c1d95' stroke='%23c4b5fd' stroke-width='3'/><rect x='42' y='40' width='74' height='28' rx='8' fill='%2324174d'/><rect x='42' y='78' width='132' height='18' rx='8' fill='%2324174d'/><rect x='42' y='104' width='132' height='18' rx='8' fill='%2324174d'/><circle cx='178' cy='58' r='7' fill='%23ddd6fe'/><circle cx='178' cy='86' r='7' fill='%23ddd6fe'/><circle cx='178' cy='114' r='7' fill='%23ddd6fe'/></svg>",
              "background-fit": "cover",
            },
          },
          {
            selector: "node.route-summary.route-high-latency",
            style: { "border-style": "dashed" },
          },
          {
            selector: "node.route-summary.route-loss",
            style: { "border-style": "solid", "border-width": 5 },
          },
          {
            selector: "node.route-summary.route-timeout",
            style: { "border-style": "dashed" },
          },
          {
            selector: "node.inferred",
            style: { "border-style": "dotted", "border-width": 3 },
          },
          {
            selector: "node[kind = 'cluster'][visual_state = 'destination']",
            style: { "background-color": "#4c1d95", "border-color": "#c084fc" },
          },
          {
            selector: "node[kind = 'cluster'][visual_state = 'origin']",
            style: { "background-color": "#064e3b", "border-color": "#2dd4bf" },
          },
          {
            selector: "node[kind = 'cluster'][visual_state = 'anomaly']",
            style: { "background-color": "#431407", "border-color": "#fb7185" },
          },
          {
            selector: "node[kind = 'cluster'][visual_state = 'timeout']",
            style: { "background-color": "#1e293b", "border-color": "#94a3b8" },
          },
          {
            selector: "node[kind = 'cluster'][visual_state = 'inferred']",
            style: { "background-color": "#1e1b4b", "border-color": "#818cf8" },
          },
          {
            selector: "node.role-router, node.role-gateway, node.role-private, node.role-upstream, node.role-asn-known, node.role-asn-unknown, node.role-ix, node.role-destination, node.role-timeout, node.role-unknown",
            style: {
              shape: "round-rectangle",
              "background-color": "#0f172a",
              "background-opacity": 0.96,
              "background-fit": "contain",
              "background-position-x": "50%",
              "background-position-y": "34%",
              "background-repeat": "no-repeat",
              "text-valign": "bottom",
              "text-halign": "center",
              "text-wrap": "wrap",
              "text-max-width": 170,
              "text-margin-y": 14,
              "font-size": 12,
              "font-weight": 800,
              "color": "#f8fafc",
              "text-background-color": "#08111f",
              "text-background-opacity": 0.78,
              "text-background-padding": "4px",
              "border-width": 3,
              padding: "18px",
            },
          },
          {
            selector: "node.role-router",
            style: {
              width: 122,
              height: 108,
              "border-color": "#60a5fa",
              "background-image": NETWORK_ICON_SVGS.router,
            },
          },
          {
            selector: "node.role-gateway",
            style: {
              width: 166,
              height: 122,
              "border-color": "#5eead4",
              "background-image": NETWORK_ICON_SVGS.gateway,
            },
          },
          {
            selector: "node.role-private",
            style: {
              width: 156,
              height: 116,
              "border-color": "#94a3b8",
              "background-image": NETWORK_ICON_SVGS.private,
            },
          },
          {
            selector: "node.role-upstream",
            style: {
              width: 160,
              height: 118,
              "border-color": "#38bdf8",
              "background-image": NETWORK_ICON_SVGS.upstream,
            },
          },
          {
            selector: "node.role-asn-known",
            style: {
              width: 156,
              height: 116,
              "border-color": "#38bdf8",
              "background-image": NETWORK_ICON_SVGS.asnKnown,
            },
          },
          {
            selector: "node.role-asn-unknown",
            style: {
              width: 150,
              height: 114,
              "border-color": "#f59e0b",
              "background-image": NETWORK_ICON_SVGS.asnUnknown,
            },
          },
          {
            selector: "node.role-ix",
            style: {
              width: 162,
              height: 116,
              "border-color": "#c4b5fd",
              "background-image": NETWORK_ICON_SVGS.ix,
            },
          },
          {
            selector: "node.role-destination",
            style: {
              width: 166,
              height: 122,
              "border-color": "#c4b5fd",
              "background-image": NETWORK_ICON_SVGS.destination,
            },
          },
          {
            selector: "node.role-timeout",
            style: {
              width: 146,
              height: 114,
              "border-color": "#94a3b8",
              "border-style": "dashed",
              "background-image": NETWORK_ICON_SVGS.timeout,
            },
          },
          {
            selector: "node.role-unknown",
            style: {
              width: 146,
              height: 114,
              "border-color": "#64748b",
              "background-image": NETWORK_ICON_SVGS.unknown,
            },
          },
          {
            selector: "node.role-cluster-collapsed",
            style: {
              width: 400,
              height: 246,
              "border-color": "#7dd3fc",
              "background-image": NETWORK_ICON_SVGS.clusterCollapsed,
              "text-valign": "center",
              "text-halign": "center",
              "text-margin-y": 0,
              "text-max-width": 300,
              "font-size": 15,
            },
          },
          {
            selector: "node.role-cluster-expanded",
            style: {
              width: 408,
              height: 258,
              "background-image": NETWORK_ICON_SVGS.clusterExpanded,
              "text-valign": "top",
              "text-halign": "center",
              "text-margin-y": 16,
              "text-max-width": 300,
              "font-size": 15,
            },
          },
          {
            selector: "edge.route-edge",
            style: {
              width: 6,
              "line-color": "#a5b4fc",
              "target-arrow-shape": "triangle",
              "target-arrow-color": "#a5b4fc",
              "curve-style": "bezier",
              "arrow-scale": 1.25,
              "line-cap": "round",
            },
          },
          {
            selector: "edge.summary-route-edge",
            style: {
              width: 12,
              "line-color": "#7dd3fc",
              "target-arrow-color": "#7dd3fc",
              "source-arrow-shape": "none",
              "target-arrow-shape": "triangle",
              "arrow-scale": 1.45,
              opacity: 0.96,
              "line-style": "solid",
              "curve-style": "straight",
              "z-index": 999,
            },
          },
          {
            selector: "edge.latency-jump",
            style: { width: 5, "line-color": "#fb7185", "target-arrow-color": "#fb7185" },
          },
          {
            selector: "edge.packet-loss",
            style: { width: 5, "line-color": "#f59e0b", "target-arrow-color": "#f59e0b" },
          },
          {
            selector: "edge.timeout-edge",
            style: { width: 4, "line-color": "#64748b", "target-arrow-color": "#64748b", "line-style": "dashed" },
          },
          {
            selector: ".dimmed",
            style: { opacity: 0.15, "text-opacity": 0.2 },
          },
          {
            selector: ".focused-path",
            style: { opacity: 1, "text-opacity": 1, "border-width": 5 },
          },
          { selector: ":selected", style: { "border-width": 5, "border-color": "#7dd3fc" } },
          ]),
          wheelSensitivity: 0.14,
          minZoom: 0.15,
          maxZoom: 2.5,
        });

        cyRef.current = cy;
        setDebugInfo({
          payloadNodes: payload.nodes?.length || 0,
          payloadEdges: payload.edges?.length || 0,
          payloadClusters: payload.clusters?.length || 0,
          visibleNodes: visible.visibleNodes.length,
          visibleEdges: visible.visibleEdges.length,
          visibleClusters: visible.visibleClusters.length,
          elementsNodes: elements.filter((element) => !element.data.source).length,
          elementsEdges: elements.filter((element) => element.data.source).length,
          firstNodes: elements.filter((element) => !element.data.source).slice(0, 3).map((element) => ({ data: element.data, classes: element.classes })),
          firstEdges: elements.filter((element) => element.data.source).slice(0, 3).map((element) => ({ data: element.data, classes: element.classes })),
          ...getCyDiagnostics(cy),
          containerWidth,
          containerHeight,
          preset: topologyPreset,
          mode: topologyMode ? "topology" : "operational",
          topologyMode,
          expandedClusters: Object.values(clusterExpandedState).filter(Boolean).length,
          collapsedClusters: Object.values(clusterExpandedState).filter((value) => value === false).length,
          routeClusters: topologyPreset === "clean" ? visible.visibleClusters.map((cluster) => cluster.route_title || cluster.name || cluster.id) : undefined,
        });

        const positions = payload.node_positions || {};
        for (const node of visible.visibleNodes) {
          const position = positions[node.id] || node.node_positions;
          const ele = cy.getElementById(node.id);
          if (ele && ele.length && position) ele.position({ x: position.x, y: position.y });
        }

        for (const cluster of visible.visibleClusters) {
          const clusterEle = cy.getElementById(cluster.id);
          const members = visible.visibleNodes.filter((node) => node.cluster_id === cluster.id && !node.is_cluster_summary);
          if (!clusterEle.length || !members.length) continue;
          const xs = members.map((node) => (positions[node.id] ? positions[node.id].x : 0));
          const ys = members.map((node) => (positions[node.id] ? positions[node.id].y : 0));
          const minX = Math.min(...xs) - 90;
          const maxX = Math.max(...xs) + 90;
          const minY = Math.min(...ys) - 72;
          const maxY = Math.max(...ys) + 72;
          clusterEle.position({ x: (minX + maxX) / 2, y: (minY + maxY) / 2 });
          clusterEle.style({ width: Math.max(250, Math.min(460, maxX - minX)), height: Math.max(220, Math.min(380, maxY - minY)) });
        }

        setHighlightState(cy, selectedMode === "cluster" ? selectedClusterId : selectedNodeId);

        cy.on("tap", "node[kind = 'hop']", (evt) => {
          setSelectedMode("hop");
          setSelectedNodeId(evt.target.data("id"));
          setSelectedClusterId(evt.target.data("cluster_id"));
          setHighlightState(cy, evt.target.data("id"));
        });
        cy.on("tap", "node[kind = 'cluster-summary']", (evt) => {
          setSelectedMode("cluster");
          setSelectedClusterId(evt.target.data("cluster_id"));
          setHighlightState(cy, evt.target.data("id"));
        });
        cy.on("tap", "node[kind = 'cluster']", (evt) => {
          setSelectedMode("cluster");
          setSelectedClusterId(evt.target.data("id"));
          setHighlightState(cy, evt.target.data("id"));
        });
        cy.on("dblclick", "node[kind = 'cluster']", (evt) => {
          toggleCluster(evt.target.data("id"));
        });
        cy.on("tap", (evt) => {
          if (evt.target === cy) {
            setSelectedMode("operational");
            setHighlightState(cy, null);
          }
        });

        cy.ready(() => {
          scheduleFitCenter(cy, "ready");
        });
      } catch (error) {
        console.error("Falha ao renderizar Cytoscape:", error);
        setBootError(`mountCytoscape: ${formatRuntimeError(error).message}`);
      }

      return () => {
        if (cyRef.current) {
          clearPendingFrames();
          if (typeof cyRef.current.destroyed !== "function" || !cyRef.current.destroyed()) cyRef.current.destroy();
          cyRef.current = null;
        }
      };
    }, [payload, topologyMode, clusterExpanded]);

    useEffect(() => {
      if (cyRef.current) {
        scheduleFitCenter(cyRef.current, "mode-change");
      }
    }, [topologyMode, payload]);

    useEffect(() => {
      document.body.classList.toggle("topology-mode", topologyMode);
      document.body.classList.toggle("fullscreen-topology", fullscreen);
    }, [topologyMode, fullscreen]);

    if (bootError) {
      return h(
        "div",
        { className: "boot-error", role: "alert" },
        h("strong", null, "Erro ao carregar UI"),
        h("div", null, bootError),
        h("button", {
          id: "retryBootButton",
          type: "button",
          className: "primary",
          onClick: () => window.location.reload(),
        }, "Tentar novamente"),
      );
    }

    if (!CytoscapeGlobal) {
      return h(
        React.Fragment,
        null,
        h(
          "header",
          { className: "hero" },
          h("div", null, h("p", { className: "eyebrow" }, "RouteBrain / Route Map"), h("h1", null, "Visual Traceroute"), h("p", { className: "subtitle" }, "Modo lista simples temporário. Cytoscape indisponível.")),
        ),
        h("section", { className: "panel" }, h("strong", null, "Cytoscape indisponível"), h("div", null, "O navegador não carregou o grafo interativo. O restante da UI continua funcional.")),
      );
    }

    return h(
      React.Fragment,
      null,
      h(
        "header",
        { className: "hero" },
        h(
          "div",
          null,
          h("p", { className: "eyebrow" }, "RouteBrain / Route Map"),
          h("h1", null, "Visual Traceroute"),
          h(
            "p",
            { className: "subtitle" },
            "Topologia operacional com caminho da esquerda para a direita, clusters ASN em blocos visuais e leitura imediata de anomalias.",
          ),
        ),
        h(
          "div",
          { className: "hero-actions" },
          h("input", {
            className: "visualization-name",
            type: "text",
            value: visualizationName,
            placeholder: "Nome da visualização",
            onChange: (event) => setVisualizationName(event.target.value),
          }),
          h("button", { className: "secondary", type: "button", onClick: () => setTopologyMode((value) => !value) }, topologyMode ? "Alternar para Operacional" : "Alternar para Topologia"),
          h("button", { className: "secondary", type: "button", onClick: () => applyTopologyPreset("complete") }, "Topologia completa"),
          h("button", { className: "secondary", type: "button", onClick: () => applyTopologyPreset("clean") }, "Topologia limpa"),
          h("button", { className: "secondary", type: "button", onClick: fitGraph }, "Centralizar rota"),
          h("button", { className: "secondary", type: "button", onClick: () => zoom(0.15) }, "Zoom +"),
          h("button", { className: "secondary", type: "button", onClick: () => zoom(-0.15) }, "Zoom -"),
          h("button", { className: "secondary", type: "button", onClick: toggleFullscreen }, fullscreen ? "Restaurar" : "Expandir"),
          h("button", { className: "primary", type: "button", onClick: saveVisualization }, "Salvar visualização"),
          h("a", { className: "ghost-link", href: "/route-graph/ui" }, "RouteGraph"),
          h("a", { className: "ghost-link", href: "/questions/ui" }, "Perguntas"),
          h("button", { className: "primary", type: "button", onClick: load }, "Recarregar"),
        ),
      ),
      h("section", { className: "summary-strip" }, summary.map(([label, value]) => h("article", { className: "summary-card", key: label }, h("span", { className: "summary-label" }, label), h("strong", { className: "summary-value" }, fmt(value))))),
      h(
        "section",
        { className: "workspace" },
        h(
          "aside",
          { id: "sidebarPanel", className: "panel sidebar" },
          h(
            "div",
            { className: "panel-head" },
            h("div", null, h("p", { className: "panel-kicker" }, "Legenda"), h("h2", null, "Leitura operacional")),
          ),
          h(
            "div",
            { className: "legend" },
            legendItem("sw-origin", "Origem", "Primeiro hop / gateway de saída"),
            legendItem("sw-normal", "Hop normal", "Elemento de trânsito legível"),
            legendItem("sw-cluster", "Cluster expandido", "Bloco ASN aberto com hops internos"),
            legendItem("sw-asn", "Cluster recolhido", "Bloco resumido do ASN"),
            legendItem("sw-ptt", "IX / PTT", "Quando houver sinal desse tipo"),
            legendItem("sw-timeout", "Timeout / unknown", "Sem resposta ou sem leitura"),
            legendItem("sw-high", "Cluster com anomalia", "RTT alto ou salto grande"),
            legendItem("sw-loss", "Cluster com perda", "Perda observada no cluster"),
            legendItem("sw-destination", "Destino", "Último hop do caminho"),
            legendItem("sw-inferred", "Dados inferidos", "Dado resolvido por contexto"),
          ),
          h(
            "div",
            { className: "note" },
            payload?.source === "fixture"
              ? "Sem medição real disponível no momento. A tela está usando fixture local."
              : `Dado real do banco. measurement_id ${payload?.metadata?.measurement_id ?? "-"} · target ${payload?.metadata?.target ?? "-"}.`,
          ),
          h(
            "div",
            { className: "note" },
            saveStatus || "Pronto para salvar a visualização atual.",
          ),
          h(
            "div",
            null,
            h("div", { className: "panel-kicker" }, "Visualizações salvas"),
            h(
              "div",
              { className: "saved-visualizations" },
              visualizations.length
                ? visualizations.map((item) =>
                    h(
                      "button",
                      {
                        key: item.visualization_uid,
                        type: "button",
                        className: `saved-visualization ${item.visualization_uid === payload?.visualization_uid ? "active" : ""}`,
                        onClick: () => openVisualization(item.visualization_uid),
                      },
                      h("strong", null, item.name),
                      h("span", null, `${fmt(item.target)} · ${fmt(item.selected_view_mode)} · ${fmt(item.updated_at)}`),
                    ),
                  )
                : h("div", { className: "note" }, "Nenhuma visualização salva ainda."),
            ),
          ),
          h(
            "div",
            { className: "cluster-list" },
            (payload?.clusters || []).map((cluster) =>
              h(
                "div",
                {
                  key: cluster.id,
                  className: `cluster-card ${selectedClusterId === cluster.id ? "active" : ""} ${cluster.visual_state?.status ? `cluster-${cluster.visual_state.status}` : ""}`,
                  role: "button",
                  tabIndex: 0,
                  onClick: () => {
                    setSelectedMode("cluster");
                    setSelectedClusterId(cluster.id);
                  },
                  onKeyDown: (event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setSelectedMode("cluster");
                      setSelectedClusterId(cluster.id);
                    }
                  },
                },
                h("div", { className: "cluster-title" }, `${isClusterExpanded(cluster.id) ? "▾" : "▸"} ${cluster.asn ? `AS${cluster.asn}` : cluster.name}`),
                h("div", { className: "cluster-meta" }, `${cluster.hops_count} hops · ${fmt(cluster.organization)} · ${fmt(cluster.avg_latency_ms)} ms média`),
                h("div", { className: "cluster-meta" }, `timeouts ${cluster.timeout_count} · unknown ${cluster.unknown_count} · inferidos ${cluster.inferred_count}`),
                h("button", { type: "button", className: "secondary small cluster-toggle", onClick: (event) => { event.stopPropagation(); toggleCluster(cluster.id); } }, isClusterExpanded(cluster.id) ? "Recolher cluster" : "Expandir cluster"),
              ),
            ),
          ),
        ),
        h(
          "section",
          { className: "panel graph-panel" },
          h(
            "div",
            { className: "panel-head" },
            h("div", null, h("p", { className: "panel-kicker" }, "Traceroute"), h("h2", null, payload?.metadata?.target_label || payload?.metadata?.target || "Carregando...")),
            h(
              "div",
              { className: "status-stack" },
              h("span", { id: "graphStatus", className: "status-pill" }, status),
              h("span", { id: "modeStatus", className: "mode-pill" }, topologyMode ? "Modo atual: Topologia" : "Modo atual: Operacional"),
              h("span", { className: "mode-pill subtle" }, `Preset: ${topologyPreset === "complete" ? "Topologia completa" : "Topologia limpa"}`),
            ),
          ),
          h("div", { ref: canvasRef, className: "graph-canvas" }),
          debugInfo
            ? h(
                "details",
                { className: "raw-toggle" },
                h("summary", null, "Debug grafo"),
                h("pre", null, JSON.stringify(debugInfo, null, 2)),
              )
            : null,
        ),
        h(
          "aside",
          { className: "panel detail-panel" },
          h("div", { className: "panel-head" }, h("div", null, h("p", { className: "panel-kicker" }, "Detalhes"), h("h2", null, selectedMode === "cluster" ? "Cluster selecionado" : "Hop selecionado"))),
          selectedMode === "cluster" && selectedCluster
            ? h(
                "div",
                { className: "detail-box" },
                h("dl", { className: "detail-list" }, detailRow("Nome", selectedCluster.name), detailRow("Tipo", selectedCluster.type), detailRow("ASN", selectedCluster.asn || "-"), detailRow("Organização", selectedCluster.organization || "-"), detailRow("Quantidade", selectedCluster.hops_count), detailRow("Latência média", `${fmt(selectedCluster.avg_latency_ms)} ms`), detailRow("Maior latência", `${fmt(selectedCluster.max_latency_ms)} ms`), detailRow("Perda média", `${fmt(selectedCluster.avg_loss_percent)} %`), detailRow("Timeouts", selectedCluster.timeout_count), detailRow("Unknown", selectedCluster.unknown_count)),
                h("div", { className: "detail-row" }, h("dt", null, "Estado"), h("dd", null, isClusterExpanded(selectedCluster.id) ? "expandido" : "recolhido")),
                h("div", { className: "cluster-actions" }, h("button", { type: "button", className: "secondary", onClick: () => toggleCluster(selectedCluster.id) }, isClusterExpanded(selectedCluster.id) ? "Recolher cluster" : "Expandir cluster")),
                h("div", { className: "detail-callout" }, fmt(selectedCluster.operational_note)),
                h(
                  "div",
                  { className: "detail-subsection" },
                  h("strong", null, "Hops resumidos"),
                  h("ul", null, selectedCluster.nodes.slice(0, 8).map((node) => h("li", { key: node.id }, `${node.hop} ${node.ip || "timeout"} ${node.hostname ? `· ${node.hostname}` : ""}`))),
                ),
              )
          : selectedNode
              ? h(
                  "div",
                  { className: "detail-box" },
                  h("dl", { className: "detail-list" }, detailRow("Hop index", selectedNode.hop), detailRow("IP", selectedNode.ip), detailRow("Hostname", selectedNode.hostname), detailRow("ASN", selectedNode.asn_label || selectedNode.asn || "-"), detailRow("Organização", selectedNode.org || "-"), detailRow("Latência média", `${fmt(selectedNode.latency_ms)} ms`), detailRow("Perda", `${fmt(selectedNode.loss_percent)} %`), detailRow("Status", selectedNode.status), detailRow("Tipo/classificação", selectedNode.classification), detailRow("Cluster", selectedNode.cluster_id), detailRow("Origem do dado", selectedNode.source)),
                  h("div", { className: "detail-callout" }, selectedNode.is_inferred ? "Hop inferido por contexto operacional." : "Hop resolvido a partir da medição/metadata."),
                  renderBgpEvidenceDetail(selectedNode),
                  h(
                    "details",
                    { className: "raw-toggle" },
                    h("summary", null, "Raw / debug"),
                    h("pre", null, JSON.stringify(selectedNode.raw || {}, null, 2)),
                  ),
                )
              : h("div", { className: "detail-box" }, "Clique em um hop ou cluster."),
        ),
      ),
    );
  }

  function bootstrap() {
    try {
      const root = getRoot();
      if (!root) throw new Error('Elemento raiz "#root" não encontrado.');
      ReactGlobal = window.React;
      ReactDOMGlobal = window.ReactDOM;
      CytoscapeGlobal = window.cytoscape;
      if (!ReactGlobal || !ReactDOMGlobal) throw new Error("React ou ReactDOM não estão disponíveis.");
      if (!CytoscapeGlobal) throw new Error("Cytoscape não está disponível.");
      h = ReactGlobal.createElement;
      ({ useEffect, useMemo, useRef, useState } = ReactGlobal);
      setBootMessage("Carregando RouteBrain Visual Traceroute...");
      ReactDOMGlobal.createRoot(root).render(h(App));
    } catch (error) {
      console.error("Falha ao inicializar RouteBrain Visual Traceroute:", error);
      renderBootErrorDetails("bootstrap", error);
    }
  }

  window.addEventListener("error", (event) => {
    const runtime = formatRuntimeError(event.error || event.message);
    console.error("Erro global da UI:", runtime.detail);
    renderBootErrorDetails("window.onerror", {
      message: runtime.message,
      stack: runtime.detail,
      filename: event.filename,
      lineno: event.lineno,
      colno: event.colno,
    });
  });

  window.addEventListener("unhandledrejection", (event) => {
    const runtime = formatRuntimeError(event.reason);
    console.error("Promise rejeitada na UI:", runtime.detail);
    renderBootErrorDetails("unhandledrejection", runtime);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
