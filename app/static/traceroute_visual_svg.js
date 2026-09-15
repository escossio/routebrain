(function () {
  "use strict";

  const state = {
    payload: null,
    routeGraphShadow: null,
    routeGraphShadowError: null,
    experimental: {
      cy: null,
      loading: false,
      available: false,
      error: null,
      scriptPromise: null,
      graph: null,
    },
    mode: "clean",
    selectedClusterId: null,
    layout: [],
    links: [],
    scale: 1,
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
  }

  function api(path) {
    const url = new URL(path, window.location.origin).toString();
    return fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    }).then(async (response) => {
      const contentType = response.headers.get("content-type") || "";
      const body = contentType.includes("application/json") ? await response.json() : await response.text();
      if (!response.ok) throw new Error(body && body.detail ? body.detail : response.statusText);
      return body;
    });
  }

  function isRouteGraphObject(value) {
    return Boolean(value && typeof value === "object" && !Array.isArray(value));
  }

  function safeCount(value) {
    return Array.isArray(value) ? value.length : 0;
  }

  function routeGraphMeasurementId() {
    const raw = state.payload?.metadata?.measurement_id;
    const text = raw === null || raw === undefined ? "" : String(raw).trim();
    return text ? text : null;
  }

  function routeGraphRunPath(measurementId) {
    if (!measurementId) return null;
    const encoded = encodeURIComponent(String(measurementId));
    return `/route-graph/runs/${encoded}`;
  }

  function routeGraphCytoscapePath(measurementId) {
    const runPath = routeGraphRunPath(measurementId);
    return runPath ? `${runPath}?format=cytoscape` : null;
  }

  function routeGraphUrls(measurementId) {
    if (!measurementId) return null;
    return {
      json: routeGraphRunPath(measurementId),
      cytoscape: routeGraphCytoscapePath(measurementId),
      cli: `python -m app.cli routegraph-report ${String(measurementId)}`,
    };
  }

  function routeGraphExperimentalMeasurementId() {
    return routeGraphMeasurementId();
  }

  function setShadowActionState(enabled, measurementId) {
    const urls = routeGraphUrls(measurementId);
    const openJson = $("routeGraphShadowOpenJson");
    const openCytoscape = $("routeGraphShadowOpenCytoscape");
    const copyCli = $("routeGraphShadowCopyCli");
    const panel = $("routeGraphShadowPanel");
    if (openJson) {
      openJson.href = urls ? urls.json : "#";
      openJson.setAttribute("aria-disabled", enabled ? "false" : "true");
      openJson.classList.toggle("is-disabled", !enabled);
    }
    if (openCytoscape) {
      openCytoscape.href = urls ? urls.cytoscape : "#";
      openCytoscape.setAttribute("aria-disabled", enabled ? "false" : "true");
      openCytoscape.classList.toggle("is-disabled", !enabled);
    }
    if (copyCli) {
      copyCli.dataset.command = urls ? urls.cli : "";
      copyCli.disabled = !enabled;
    }
    if (panel) {
      panel.open = false;
    }
  }

  async function copyShadowCliCommand() {
    const measurementId = routeGraphMeasurementId();
    const urls = routeGraphUrls(measurementId);
    if (!urls) {
      throw new Error("measurement_id indisponível.");
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(urls.cli);
      return;
    }
    const textarea = document.createElement("textarea");
    textarea.value = urls.cli;
    textarea.setAttribute("readonly", "readonly");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(textarea);
    if (!copied) {
      throw new Error("Falha ao copiar o comando.");
    }
  }

  function setExperimentalStatus(text) {
    const status = $("routeGraphExperimentalStatus");
    if (status) status.textContent = text;
  }

  function setExperimentalMessage(text, kind = "info") {
    const box = $("routeGraphExperimentalMessage");
    if (!box) return;
    box.className = kind === "error" ? "footer-note experimental-error" : "footer-note";
    box.textContent = text;
  }

  function setExperimentalControls(enabled, loading = false) {
    const loadButton = $("routeGraphExperimentalLoad");
    const openJson = $("routeGraphExperimentalOpenJson");
    if (loadButton) {
      loadButton.disabled = !enabled || loading;
      loadButton.textContent = loading ? "Carregando..." : "Carregar visualização";
    }
    if (openJson) {
      openJson.setAttribute("aria-disabled", enabled ? "false" : "true");
      openJson.classList.toggle("is-disabled", !enabled);
    }
  }

  function experimentalCanvas() {
    return $("routeGraphExperimentalCanvas");
  }

  function experimentalOpenJsonLink(measurementId) {
    const link = $("routeGraphExperimentalOpenJson");
    if (!link) return;
    const urls = routeGraphUrls(measurementId);
    if (!urls) {
      link.href = "#";
      link.classList.add("is-disabled");
      return;
    }
    link.href = urls.cytoscape;
    link.classList.remove("is-disabled");
  }

  function ensureCytoscapeScript() {
    if (window.cytoscape) return Promise.resolve(true);
    if (state.experimental.scriptPromise) return state.experimental.scriptPromise;
    state.experimental.scriptPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js";
      script.crossOrigin = "anonymous";
      script.referrerPolicy = "no-referrer";
      script.onload = () => resolve(true);
      script.onerror = () => reject(new Error("Cytoscape indisponível."));
      document.head.appendChild(script);
    });
    return state.experimental.scriptPromise;
  }

  function destroyExperimentalCy() {
    if (state.experimental.cy && typeof state.experimental.cy.destroy === "function") {
      try {
        state.experimental.cy.destroy();
      } catch (error) {
        // Shadow/experimental: never block the main UI.
      }
    }
    state.experimental.cy = null;
  }

  function buildExperimentalElements(payload) {
    const elements = [];
    const nodes = Array.isArray(payload?.elements)
      ? payload.elements.filter((item) => isRouteGraphObject(item?.data) && item.data.id)
      : [];
    const edges = nodes.filter((item) => item.data.source && item.data.target);
    const nodeList = nodes.filter((item) => !item.data.source && !item.data.target);
    for (const node of nodeList) {
      elements.push({
        data: {
          id: String(node.data.id),
          label: String(node.data.label || node.data.id || ""),
          kind: String(node.data.kind || "unknown"),
          ip: node.data.ip ?? null,
          asn: node.data.asn ?? null,
          as_name: node.data.as_name ?? null,
          hop_index: node.data.hop_index ?? null,
          latency_ms: node.data.latency_ms ?? null,
          is_private: Boolean(node.data.is_private),
          is_silent: Boolean(node.data.is_silent),
          is_destination: Boolean(node.data.is_destination),
          confidence: String(node.data.confidence || "unknown"),
          warnings: Array.isArray(node.data.warnings) ? node.data.warnings : [],
          badges: Array.isArray(node.data.badges) ? node.data.badges : [],
          evidence_count: Number(node.data.evidence_count || 0),
        },
      });
    }
    for (const edge of edges) {
      elements.push({
        data: {
          id: String(edge.data.id || `${edge.data.source}->${edge.data.target}`),
          source: String(edge.data.source),
          target: String(edge.data.target),
          kind: String(edge.data.kind || "logical_next_hop"),
        },
      });
    }
    return { nodes: nodeList, edges, elements };
  }

  function experimentalDetailText(nodeData) {
    if (!nodeData) return "Selecione um nó para ver detalhes.";
    const warnings = Array.isArray(nodeData.warnings) ? nodeData.warnings : [];
    const badges = Array.isArray(nodeData.badges) ? nodeData.badges : [];
    const lines = [
      `<div><strong>Hop:</strong> ${escapeHtml(nodeData.hop_index ?? "-")}</div>`,
      `<div><strong>IP:</strong> ${escapeHtml(nodeData.ip ?? "—")}</div>`,
      `<div><strong>Kind:</strong> ${escapeHtml(nodeData.kind || "unknown")}</div>`,
      `<div><strong>Latency:</strong> ${escapeHtml(nodeData.latency_ms ?? "—")}</div>`,
      `<div><strong>ASN:</strong> ${escapeHtml(nodeData.asn ?? "null")}</div>`,
      `<div><strong>AS name:</strong> ${escapeHtml(nodeData.as_name ?? "null")}</div>`,
      `<div><strong>Confidence:</strong> ${escapeHtml(nodeData.confidence || "unknown")}</div>`,
      `<div><strong>Flags:</strong> ${[
        nodeData.is_private ? "private" : null,
        nodeData.is_silent ? "silent" : null,
        nodeData.is_destination ? "destination" : null,
      ].filter(Boolean).join(", ") || "none"}</div>`,
      `<div><strong>Evidence:</strong> ${escapeHtml(nodeData.evidence_count ?? 0)}</div>`,
      badges.length ? `<div><strong>Badges:</strong> ${escapeHtml(badges.join(", "))}</div>` : "",
      warnings.length ? `<div><strong>Warnings:</strong> ${escapeHtml(warnings.join(" | "))}</div>` : "",
    ];
    return lines.filter(Boolean).join("");
  }

  function renderExperimentalFallback(message) {
    destroyExperimentalCy();
    state.experimental.available = false;
    state.experimental.loading = false;
    setExperimentalStatus("indisponível");
    setExperimentalMessage(message || "visualização experimental indisponível", "error");
    setExperimentalControls(false, false);
    const canvas = experimentalCanvas();
    if (canvas) {
      canvas.classList.add("hidden");
      canvas.innerHTML = "";
    }
  }

  function renderExperimentalGraph(routeGraph) {
    const canvas = experimentalCanvas();
    if (!canvas) return;
    const normalized = buildExperimentalElements(routeGraph);
    if (!normalized.elements.length) {
      renderExperimentalFallback("visualização experimental indisponível");
      return;
    }
    if (!window.cytoscape) {
      renderExperimentalFallback("visualização experimental indisponível");
      return;
    }
    destroyExperimentalCy();
    canvas.classList.remove("hidden");
    canvas.innerHTML = "";
    const nodeDetail = $("routeGraphExperimentalDetail");
    try {
      state.experimental.cy = window.cytoscape({
        container: canvas,
        elements: normalized.elements,
        layout: { name: "breadthfirst", directed: true, padding: 20 },
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)",
              "background-color": "#eff6ff",
              "border-width": 2,
              "border-color": "#0f62fe",
              color: "#102033",
              "font-size": 11,
              "text-wrap": "wrap",
              "text-max-width": 110,
              width: 50,
              height: 50,
              shape: "round-rectangle",
            },
          },
          { selector: "node.kind-source, node.kind-local_gateway", style: { "border-color": "#0f766e", "background-color": "#e6fffb" } },
          { selector: "node.kind-private_hop, node.kind-private", style: { "border-color": "#475569", "background-color": "#f8fafc" } },
          { selector: "node.kind-public_hop, node.kind-public", style: { "border-color": "#1d4ed8", "background-color": "#eff6ff" } },
          { selector: "node.kind-silent_hop, node.kind-silent", style: { "border-style": "dashed", "background-color": "#fff7ed", "border-color": "#b45309" } },
          { selector: "node.kind-destination", style: { "border-color": "#7c3aed", "background-color": "#f3e8ff" } },
          { selector: "node.kind-unknown", style: { "border-color": "#64748b", "background-color": "#f8fafc" } },
          { selector: "node.confidence-low", style: { "border-style": "dotted", "opacity": 0.92 } },
          { selector: "node.confidence-partial", style: { "border-width": 3 } },
          { selector: "node.has-warning", style: { "border-color": "#b42318", "background-color": "#fff1f2" } },
          { selector: "node.is-destination", style: { "border-color": "#7c3aed", "background-color": "#f3e8ff" } },
          {
            selector: "edge",
            style: {
              width: 2,
              "line-color": "#5f7190",
              "target-arrow-color": "#5f7190",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              label: "data(kind)",
              "font-size": 10,
              color: "#334155",
            },
          },
        ],
      });
      for (const node of normalized.nodes) {
        const cyNode = state.experimental.cy.getElementById(String(node.data.id));
        if (!cyNode || typeof cyNode.addClass !== "function") continue;
        const kind = String(node.data.kind || "unknown");
        cyNode.addClass(`kind-${kind}`);
        cyNode.addClass(`confidence-${String(node.data.confidence || "unknown").replace(/[^a-z0-9_-]/gi, "-")}`);
        if (node.data.is_private) cyNode.addClass("is-private");
        if (node.data.is_silent) cyNode.addClass("is-silent");
        if (node.data.is_destination) cyNode.addClass("is-destination");
        if ((node.data.evidence_count || 0) > 0) cyNode.addClass("has-evidence");
        if ((node.data.warnings || []).length > 0) cyNode.addClass("has-warning");
      }
      if (nodeDetail) nodeDetail.innerHTML = "Selecione um nó para ver detalhes.";
      state.experimental.cy.on("tap", "node", (event) => {
        const data = event.target?.data ? event.target.data() : null;
        if (nodeDetail) nodeDetail.innerHTML = experimentalDetailText(data);
      });
      state.experimental.available = true;
      state.experimental.error = null;
      state.experimental.loading = false;
      state.experimental.graph = routeGraph;
      setExperimentalStatus("ativo");
      setExperimentalMessage(`RouteGraph experimental carregado: ${normalized.nodes.length} nodes, ${normalized.edges.length} edges.`);
      setExperimentalControls(true, false);
    } catch (error) {
      renderExperimentalFallback(error.message || "falha ao montar grafo experimental");
    }
  }

  function loadExperimentalGraph() {
    const measurementId = routeGraphExperimentalMeasurementId();
    const openJsonLink = $("routeGraphExperimentalOpenJson");
    const loadButton = $("routeGraphExperimentalLoad");
    const nodeDetail = $("routeGraphExperimentalDetail");
    if (!measurementId) {
      renderExperimentalFallback("measurement_id indisponível.");
      return Promise.resolve(false);
    }
    if (state.experimental.loading) {
      return Promise.resolve(false);
    }
    state.experimental.loading = true;
    if (nodeDetail) nodeDetail.textContent = "Carregando detalhes da visualização experimental...";
    experimentalOpenJsonLink(measurementId);
    setExperimentalStatus("carregando...");
    setExperimentalMessage("Carregando visualização experimental do RouteGraph...", "info");
    setExperimentalControls(true, true);
    if (openJsonLink) {
      openJsonLink.href = routeGraphUrls(measurementId)?.cytoscape || "#";
    }
    if (loadButton) {
      loadButton.blur();
    }
    return api(routeGraphCytoscapePath(measurementId))
      .then((routeGraph) => {
        const elements = Array.isArray(routeGraph?.elements) ? routeGraph.elements : [];
        const layout = isRouteGraphObject(routeGraph?.layout) ? routeGraph.layout : null;
        if (!elements.length || !layout) {
          throw new Error("payload Cytoscape inválido.");
        }
        state.experimental.error = null;
        return ensureCytoscapeScript()
          .then(() => renderExperimentalGraph(routeGraph))
          .catch((error) => {
            renderExperimentalFallback(error.message || "visualização experimental indisponível");
            return false;
          });
      })
      .catch((error) => {
        state.experimental.error = error;
        renderExperimentalFallback(error.message || "visualização experimental indisponível");
        return false;
      });
  }

  function renderRouteGraphShadow(report) {
    const status = $("routeGraphShadowStatus");
    const body = $("routeGraphShadowBody");
    if (!status || !body) return;
    if (!isRouteGraphObject(report)) {
      status.textContent = "indisponível";
      body.innerHTML = `<div class="footer-note">RouteGraph indisponível.</div>`;
      setShadowActionState(false, null);
      return;
    }
    const summary = isRouteGraphObject(report.summary) ? report.summary : {};
    const warnings = Array.isArray(report.warnings) ? report.warnings : [];
    status.textContent = report.schema_version || "routegraph";
    const rows = [
      ["schema_version", report.schema_version || "unknown"],
      ["total_nodes", safeCount(report.nodes)],
      ["total_edges", safeCount(report.edges)],
      ["logical_hop_count", summary.logical_hop_count ?? "unknown"],
      ["silent_hop_count", summary.silent_hop_count ?? "unknown"],
      ["private_hop_count", summary.private_hop_count ?? "unknown"],
      ["public_hop_count", summary.public_hop_count ?? "unknown"],
      ["destination_reached", summary.destination_reached ?? "unknown"],
      ["confidence", summary.confidence || "unknown"],
      ["warnings_total", warnings.length],
    ];
    const warningList = warnings.slice(0, 5).map((warning) => `<li>${escapeHtml(warning)}</li>`).join("");
    body.innerHTML = `
      <div class="shadow-grid">
        ${rows.map(([label, value]) => `<div class="shadow-kv"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}
      </div>
      <div class="shadow-warnings-wrap">
        <div class="footer-note">Warnings</div>
        ${warnings.length ? `<ul class="shadow-warnings">${warningList}</ul>` : `<div class="footer-note">Nenhum warning.</div>`}
      </div>
    `;
    setShadowActionState(true, routeGraphMeasurementId());
  }

  function fetchRouteGraphShadow(payload) {
    const measurementId = payload?.metadata?.measurement_id;
    if (!measurementId) {
      state.routeGraphShadow = null;
      state.routeGraphShadowError = null;
      renderRouteGraphShadow(null);
      setShadowActionState(false, null);
      return;
    }
    // Shadow read: never blocks the SVG UI and never becomes a hard dependency.
    api(routeGraphRunPath(measurementId))
      .then((routeGraph) => {
        const nodes = Array.isArray(routeGraph?.nodes) ? routeGraph.nodes : [];
        const edges = Array.isArray(routeGraph?.edges) ? routeGraph.edges : [];
        state.routeGraphShadow = isRouteGraphObject(routeGraph) ? routeGraph : null;
        state.routeGraphShadowError = null;
        renderRouteGraphShadow(state.routeGraphShadow);
        $("debugPill").textContent = `${$("debugPill").textContent} · routegraph nodes=${nodes.length} edges=${edges.length}`;
      })
      .catch((error) => {
        state.routeGraphShadow = null;
        state.routeGraphShadowError = error;
        const status = $("routeGraphShadowStatus");
        const body = $("routeGraphShadowBody");
        if (status) status.textContent = "shadow error";
        if (body) {
          body.innerHTML = `<div class="footer-note">Consulta shadow falhou: ${escapeHtml(error.message || String(error))}</div>`;
        }
        setShadowActionState(false, measurementId);
      });
  }

  function equipmentSvg() {
    return `<svg viewBox="0 0 64 64" aria-hidden="true"><rect x="8" y="18" width="48" height="28" rx="8" fill="#eff6ff" stroke="#0f62fe" stroke-width="3"/><path d="M18 26h28M18 34h28" stroke="#0f62fe" stroke-width="4" stroke-linecap="round"/><circle cx="18" cy="42" r="2.5" fill="#0f62fe"/><circle cx="26" cy="42" r="2.5" fill="#0f62fe"/><circle cx="34" cy="42" r="2.5" fill="#0f62fe"/><circle cx="42" cy="42" r="2.5" fill="#0f62fe"/><circle cx="50" cy="42" r="2.5" fill="#0f62fe"/></svg>`;
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function routerSvg() {
    return `<svg viewBox="0 0 64 64" aria-hidden="true"><rect x="8" y="18" width="48" height="28" rx="8" fill="#eff6ff" stroke="#0f62fe" stroke-width="3"/><path d="M18 26h28M18 34h28" stroke="#0f62fe" stroke-width="4" stroke-linecap="round"/><circle cx="18" cy="42" r="2.5" fill="#0f62fe"/><circle cx="26" cy="42" r="2.5" fill="#0f62fe"/><circle cx="34" cy="42" r="2.5" fill="#0f62fe"/><circle cx="42" cy="42" r="2.5" fill="#0f62fe"/><circle cx="50" cy="42" r="2.5" fill="#0f62fe"/></svg>`;
  }

  function buildModel(payload) {
    const nodes = (payload?.nodes || []).slice().sort((a, b) => Number(a.hop || 0) - Number(b.hop || 0));
    const canvas = $("canvas");
    const width = canvas.clientWidth || 1200;
    const isMobile = window.matchMedia("(max-width: 760px)").matches;
    const cardW = 200;
    const cardH = 124;
    const gapX = 28;
    const startX = 32;
    const topMargin = isMobile ? 28 : 52;
    const bottomMargin = isMobile ? 56 : 88;
    const y = topMargin;
    const layout = nodes.map((node, index) => ({
      ...node,
      x: startX + index * (cardW + gapX),
      y,
      w: cardW,
      h: cardH,
    }));
    const links = [];
    for (let i = 0; i < layout.length - 1; i += 1) {
      const a = layout[i];
      const b = layout[i + 1];
      links.push({
        id: `${a.id}->${b.id}`,
        x1: a.x + a.w,
        y1: a.y + a.h / 2,
        x2: b.x,
        y2: b.y + b.h / 2,
        kind: "link-track",
        label: `${a.hop} → ${b.hop}`,
      });
    }
    const contentW = layout.length ? layout[layout.length - 1].x + cardW + startX : width;
    const contentH = cardH + topMargin + bottomMargin;
    return { nodes: layout, links, isMobile, contentW, contentH };
  }

  function renderDetails(node) {
    if (!node) {
      $("detailPanel").innerHTML = "Clique em um bloco.";
      return;
    }
    const ipText = node.ip || (node.status === "timeout" ? "Timeout" : node.status === "unknown" ? "?" : "?");
    const asText = node.asn !== null ? `AS${node.asn}` : (node.role === "local_gateway" ? "Local" : node.role === "destination" ? "Destino" : node.ip ? "AS?" : "AS?");
    const lines = [
      `<strong>Hop ${escapeHtml(node.hop)}</strong>`,
      `<div class="footer-note">IP: ${escapeHtml(ipText)}</div>`,
      `<div class="footer-note">ASN: ${escapeHtml(asText)}</div>`,
      node.hostname ? `<div class="footer-note">${escapeHtml(node.hostname)}</div>` : "",
    ];
    $("detailPanel").innerHTML = lines.join("");
  }

  function renderNotes(payload, model) {
    const items = [
      ["payload.nodes.length", payload?.nodes?.length ?? 0],
      ["payload.edges.length", payload?.edges?.length ?? 0],
      ["clusters.length", payload?.clusters?.length ?? 0],
      ["hops renderizados", model.nodes.length],
      ["links renderizados", model.links.length],
        ["measurement_id", payload?.metadata?.measurement_id ?? "-"],
        ["routegraph_shadow", isRouteGraphObject(state.routeGraphShadow) ? "ok" : state.routeGraphShadowError ? "erro" : "pendente"],
      ];
    $("techNotes").innerHTML = items.map(([label, value]) => `<div class="spec-item"><strong>${escapeHtml(label)}</strong><div>${escapeHtml(value)}</div></div>`).join("");
  }

  function renderCanvas(model) {
    const nodesLayer = $("nodesLayer");
    const linksLayer = $("linksLayer");
    const canvas = $("canvas");
    const width = canvas.clientWidth || 1200;
    const height = Math.max(280, model.contentH || 280);
    const contentW = Math.max(width, model.contentW);
    canvas.style.height = `${height}px`;
    linksLayer.setAttribute("viewBox", `0 0 ${contentW} ${height}`);
    linksLayer.style.transform = "none";
    nodesLayer.style.transform = "none";
    linksLayer.innerHTML = `
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#5f7190"></path>
        </marker>
      </defs>
      ${model.links.map((link) => `
        <g>
          <path d="M ${link.x1} ${link.y1} C ${link.x1 + 40} ${link.y1}, ${link.x2 - 40} ${link.y2}, ${link.x2} ${link.y2}"
                fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" marker-end="url(#arrow)"
                class="${link.kind}"></path>
          <text x="${Math.round((link.x1 + link.x2) / 2)}" y="${Math.round((link.y1 + link.y2) / 2) - 12}" text-anchor="middle" class="link-label">${escapeHtml(link.label)}</text>
        </g>`).join("")}
    `;
    nodesLayer.innerHTML = model.nodes.map((node) => {
      const selected = state.selectedClusterId === node.id ? "selected" : "";
      const ipText = node.ip || (node.status === "timeout" ? "Timeout" : node.status === "unknown" ? "?" : "?");
      return `
        <article class="topology-node ${selected}" data-id="${escapeHtml(node.id)}" style="left:${node.x}px; top:${node.y}px; width:${node.w}px; min-height:${node.h}px; --node-color:#0f62fe">
          <div class="node-icon">${equipmentSvg()}</div>
          <div class="node-copy">
            <div class="node-ip">${escapeHtml(ipText)}</div>
          </div>
        </article>
      `;
    }).join("");
    for (const nodeEl of nodesLayer.querySelectorAll(".topology-node")) {
      nodeEl.addEventListener("click", () => {
        state.selectedClusterId = nodeEl.getAttribute("data-id");
        render();
      });
    }
    $("debugPill").textContent = `payload.nodes.length=${state.payload?.nodes?.length ?? 0} payload.edges.length=${state.payload?.edges?.length ?? 0} clusters.length=${state.payload?.clusters?.length ?? 0} hops=${model.nodes.length} links=${model.links.length}`;
    $("canvasTitle").textContent = state.mode === "clean" ? "Topologia limpa" : "Topologia completa";
    $("statusChip").textContent = state.payload?.source === "fixture" ? "fixture" : "payload real";
  }

  function applyCentering() {
    const canvas = $("canvas");
    const rect = canvas.getBoundingClientRect();
    const nodes = canvas.querySelectorAll(".topology-node");
    if (!nodes.length) return;
    const isMobile = window.matchMedia("(max-width: 760px)").matches;
    const bounds = Array.from(nodes).reduce((acc, node) => {
      const left = parseFloat(node.style.left) || 0;
      const top = parseFloat(node.style.top) || 0;
      const width = parseFloat(node.style.width) || 0;
      const height = parseFloat(node.style.minHeight) || 0;
      return {
        minX: Math.min(acc.minX, left),
        minY: Math.min(acc.minY, top),
        maxX: Math.max(acc.maxX, left + width),
        maxY: Math.max(acc.maxY, top + height),
      };
    }, { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity });
    const contentW = bounds.maxX - bounds.minX;
    const contentH = bounds.maxY - bounds.minY;
    const fitX = rect.width / (contentW + 80);
    const fitY = rect.height / (contentH + 120);
    state.scale = isMobile ? 1 : clamp(Math.min(fitX, fitY), 0.82, 1.03);
    canvas.style.setProperty("--scale", state.scale.toFixed(3));
    const offsetX = Math.round((rect.width - contentW * state.scale) / 2);
    const offsetY = Math.max(16, Math.round((rect.height - contentH * state.scale) / 2));
    const translateY = offsetY - Math.min(18, bounds.minY * state.scale);
    $("nodesLayer").style.transform = `translate(${offsetX}px, ${translateY}px) scale(${state.scale})`;
    $("linksLayer").style.transform = $("nodesLayer").style.transform;
  }

  function render() {
    if (!state.payload) return;
    const model = buildModel(state.payload);
    renderCanvas(model);
    renderDetails(model.nodes.find((node) => node.id === state.selectedClusterId) || model.nodes[0] || null);
    renderNotes(state.payload, model);
    if (!state.selectedClusterId && model.nodes[0]) {
      state.selectedClusterId = model.nodes[0].id;
      renderDetails(model.nodes[0]);
    }
  }

  function setMode(mode) {
    state.mode = mode;
    $("cleanButton").classList.toggle("active", mode === "clean");
    $("completeButton").classList.toggle("active", mode === "complete");
    $("canvasTitle").textContent = mode === "clean" ? "Topologia limpa" : "Topologia completa (variação)";
    render();
    window.requestAnimationFrame(() => applyCentering());
  }

  function bootstrap() {
    $("reloadButton").addEventListener("click", () => window.location.reload());
    $("cleanButton").addEventListener("click", () => setMode("clean"));
    $("completeButton").addEventListener("click", () => setMode("complete"));
    $("centerButton").addEventListener("click", () => applyCentering());
    const copyButton = $("routeGraphShadowCopyCli");
    if (copyButton) {
      copyButton.addEventListener("click", () => {
        copyShadowCliCommand()
          .then(() => {
            copyButton.textContent = "Copiado";
            window.setTimeout(() => {
              copyButton.textContent = "Copiar CLI";
            }, 1500);
          })
          .catch((error) => {
            copyButton.textContent = "Falha";
            window.setTimeout(() => {
              copyButton.textContent = "Copiar CLI";
            }, 1500);
            const body = $("routeGraphShadowBody");
            if (body) {
              body.insertAdjacentHTML("beforeend", `<div class="footer-note">Clipboard indisponível: ${escapeHtml(error.message || String(error))}</div>`);
            }
          });
      });
    }
    const experimentalPanel = $("routeGraphExperimentalPanel");
    const experimentalLoad = $("routeGraphExperimentalLoad");
    if (experimentalLoad) {
      experimentalLoad.addEventListener("click", () => {
        if (experimentalPanel) experimentalPanel.open = true;
        loadExperimentalGraph().catch((error) => {
          renderExperimentalFallback(error.message || "visualização experimental indisponível");
        });
      });
    }
    window.addEventListener("resize", () => {
      if (state.payload) {
        render();
        window.requestAnimationFrame(() => applyCentering());
      }
    });
    api("/traceroute-visual/latest")
      .then((payload) => {
        state.payload = payload;
        $("measurementId").textContent = payload?.metadata?.measurement_id ?? "-";
        $("nodesCount").textContent = payload?.nodes?.length ?? 0;
        $("edgesCount").textContent = payload?.edges?.length ?? 0;
        $("clustersCount").textContent = payload?.clusters?.length ?? 0;
        $("statusChip").textContent = `measurement ${payload?.metadata?.measurement_id ?? "-"}`;
        setShadowActionState(Boolean(routeGraphMeasurementId()), routeGraphMeasurementId());
        experimentalOpenJsonLink(routeGraphMeasurementId());
        setExperimentalStatus(routeGraphMeasurementId() ? "sob demanda" : "indisponível");
        setExperimentalMessage("Sem carregamento ativo.");
        setExperimentalControls(Boolean(routeGraphMeasurementId()), false);
        setMode("clean");
        if (payload?.nodes?.length) state.selectedClusterId = "node:1";
        render();
        window.requestAnimationFrame(() => applyCentering());
        fetchRouteGraphShadow(payload);
      })
      .catch((error) => {
        $("detailPanel").innerHTML = `<div class="footer-note">Falha ao consultar /traceroute-visual/latest: ${escapeHtml(error.message || String(error))}</div>`;
        $("statusChip").textContent = "erro ao carregar";
        $("debugPill").textContent = "falha de carregamento";
        setShadowActionState(false, null);
        setExperimentalStatus("indisponível");
        setExperimentalMessage("visualização experimental indisponível", "error");
        setExperimentalControls(false, false);
      });
  }

  bootstrap();
})();
