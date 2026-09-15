(function () {
  "use strict";

  const SESSION_DEMO_URL = "/route-learning/sessions/demo/8.8.8.8/visual";
  const DEMO_URL = "/route-learning/demo/8.8.8.8/visual";
  const SESSION_OPTIONS = {
    google: [SESSION_DEMO_URL, DEMO_URL],
    cloudflare: ["/route-learning/sessions/demo/cloudflare/visual", SESSION_DEMO_URL, DEMO_URL],
  };
  const IMAGE_CACHE = new Map();

  const DEVICE_ICON_FILES = {
    "RB-ICON-0010": "/static/symbols/device/rb-icon-0010-router.svg",
    "RB-ICON-0020": "/static/symbols/device/rb-icon-0020-switch.svg",
    "RB-ICON-0030": "/static/symbols/device/rb-icon-0030-firewall.svg",
    "RB-ICON-0040": "/static/symbols/device/rb-icon-0040-server.svg",
    "RB-ICON-0050": "/static/symbols/device/rb-icon-0050-cloud.svg",
    "RB-ICON-0060": "/static/symbols/device/rb-icon-0060-cpe-onu.svg",
    "RB-ICON-0070": "/static/symbols/device/rb-icon-0070-ptt-ix.svg",
    "RB-ICON-0080": "/static/symbols/device/rb-icon-0080-unknown.svg",
    "RB-ICON-0090": "/static/symbols/device/rb-icon-0090-destination.svg",
    "RB-ICON-0100": "/static/symbols/device/rb-icon-0100-provider-router.svg",
    "RB-ICON-0110": "/static/symbols/device/rb-icon-0110-local-gateway.svg",
    "RB-ICON-0120": "/static/symbols/device/rb-icon-0120-cdn-edge.svg",
  };

  const FLAG_LABELS = {
    "RB-FLAG-BR": "BR",
    "RB-FLAG-US": "US",
    "RB-FLAG-UN": "GL",
  };

  const STATE_STYLE = {
    known: { fill: "#0f172a", stroke: "#22c55e", text: "#e5f7ef", accent: "#22c55e" },
    observed_now: { fill: "#11263d", stroke: "#4cc9f0", text: "#e0f9ff", accent: "#4cc9f0" },
    partially_known: { fill: "#2a1f13", stroke: "#f59e0b", text: "#fff2d4", accent: "#f59e0b" },
    queued_for_inventory: { fill: "#2a1d0f", stroke: "#f97316", text: "#ffe9c8", accent: "#f97316" },
    enriching: { fill: "#08273a", stroke: "#14b8a6", text: "#d7fff7", accent: "#14b8a6" },
    learned_now: { fill: "#0f2b1f", stroke: "#10b981", text: "#dcfce7", accent: "#10b981" },
    limited: { fill: "#111827", stroke: "#94a3b8", text: "#e2e8f0", accent: "#94a3b8" },
    inferred: { fill: "#1a2233", stroke: "#60a5fa", text: "#dbeafe", accent: "#60a5fa" },
    icmp_silent_forwarding_ok: { fill: "#122126", stroke: "#2dd4bf", text: "#e3fffb", accent: "#2dd4bf" },
    suspected_failure: { fill: "#2a1218", stroke: "#fb7185", text: "#ffe4e8", accent: "#fb7185" },
    unreachable: { fill: "#2c0d0d", stroke: "#ef4444", text: "#ffe4e4", accent: "#ef4444" },
    skipped: { fill: "#111827", stroke: "#64748b", text: "#cbd5e1", accent: "#64748b" },
  };

  const state = {
    payload: null,
    stage: null,
    layers: null,
    nodeGroups: new Map(),
    edgeGroups: new Map(),
    nodeLookup: new Map(),
    edgeLookup: new Map(),
    selected: null,
    packet: null,
    packetNodeId: null,
    timelineIndex: 0,
    playing: false,
    timer: null,
    autoFit: true,
  };

  const refs = {
    canvasHost: null,
    canvasLoading: null,
    sessionStatusBadge: null,
    targetBadge: null,
    sessionSummary: null,
    playbackBadge: null,
    frameBadge: null,
    statusLine: null,
    summaryStrip: null,
    detailPanel: null,
    ignorancePanel: null,
    queuePanel: null,
    dedicatedPlanSection: null,
    dedicatedPlanPanel: null,
    playButton: null,
    pauseButton: null,
    restartButton: null,
    fitButton: null,
    demoModeBadge: null,
    sessionPicker: null,
  };

  function esc(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function prettyKey(value) {
    if (value === null || value === undefined || value === "") return "-";
    if (Array.isArray(value)) return value.map(prettyKey).join(", ");
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function humanizeState(value) {
    return String(value || "unknown")
      .replaceAll("_", " ")
      .replace(/\b\w/g, (m) => m.toUpperCase());
  }

  function formatConfidence(value) {
    if (typeof value !== "number") return "-";
    return `${Math.round(value * 100)}%`;
  }

  function stateStyle(value) {
    return STATE_STYLE[value] || STATE_STYLE.limited;
  }

  function getDeviceIconFile(deviceIconId) {
    return DEVICE_ICON_FILES[deviceIconId] || DEVICE_ICON_FILES["RB-ICON-0080"];
  }

  function getFlagLabel(flagId) {
    return FLAG_LABELS[flagId] || "GL";
  }

  function loadImage(src) {
    if (!src) return Promise.resolve(null);
    if (IMAGE_CACHE.has(src)) return IMAGE_CACHE.get(src);
    const promise = new Promise((resolve) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => resolve(null);
      img.src = src;
    });
    IMAGE_CACHE.set(src, promise);
    return promise;
  }

  function setStatus(text) {
    if (refs.statusLine) refs.statusLine.textContent = text;
  }

  function setPlaybackBadge(text) {
    if (refs.playbackBadge) refs.playbackBadge.textContent = text;
  }

  function setFrameBadge(text) {
    if (refs.frameBadge) refs.frameBadge.textContent = text;
  }

  function setSessionBadge(text, kind) {
    if (!refs.sessionStatusBadge) return;
    refs.sessionStatusBadge.textContent = text;
    refs.sessionStatusBadge.className = `pill ${kind || "pill-loading"}`;
  }

  function summarizeMetadata(metadata) {
    if (!metadata || typeof metadata !== "object") return "-";
    const entries = Object.entries(metadata).slice(0, 6);
    if (!entries.length) return "-";
    return entries
      .map(([key, value]) => `${key}=${prettyKey(value)}`)
      .join(" · ");
  }

  function renderSummary(payload) {
    const items = [
      ["Steps", payload.summary?.total_steps],
      ["Known", payload.summary?.known_count],
      ["Observed", payload.summary?.observed_now_count],
      ["Unknown", payload.summary?.unknown_count],
      ["Queued", payload.summary?.queued_count],
      ["Enriching", payload.summary?.enriching_count],
      ["Learned", payload.summary?.learned_now_count],
      ["Limited", payload.summary?.limited_count],
      ["Bifurcações", payload.summary?.branch_count],
      ["Fontes", (payload.summary?.evidence_sources || []).length],
    ];
    refs.summaryStrip.innerHTML = items
      .map(
        ([label, value]) => `
          <article class="summary-chip">
            <span class="summary-chip-label">${esc(label)}</span>
            <span class="summary-chip-value">${esc(prettyKey(value))}</span>
          </article>
        `,
      )
      .join("");
    refs.sessionSummary.textContent = `session ${payload.session_uid} · ${payload.session_type} · ${payload.target?.label || "target"} · ${payload.status}`;
    setSessionBadge(payload.status, payload.status === "partial" ? "pill-loading" : "pill-target");
    refs.targetBadge.textContent = payload.target?.selected_ip || payload.target?.value || "8.8.8.8";
    refs.demoModeBadge.textContent = payload.metadata?.demo_mode ? "demo_mode=true" : "demo_mode=false";
  }

  function buildLayout(nodes) {
    const maxLevel = Math.max(...nodes.map((node) => Number(node.position_hint?.level ?? 0)));
    const maxOrder = Math.max(...nodes.map((node) => Number(node.position_hint?.order ?? 0)));
    const width = 260 + maxLevel * 190;
    const height = Math.max(760, 220 + maxOrder * 42);
    const positions = new Map();
    const buckets = new Map();
    for (const node of nodes) {
      const level = Number(node.position_hint?.level ?? 0);
      if (!buckets.has(level)) buckets.set(level, []);
      buckets.get(level).push(node);
    }
    for (const [level, levelNodes] of buckets.entries()) {
      levelNodes.sort((a, b) => Number(a.position_hint?.order ?? 0) - Number(b.position_hint?.order ?? 0));
      for (let index = 0; index < levelNodes.length; index += 1) {
        const node = levelNodes[index];
        const order = Number(node.position_hint?.order ?? index);
        const branch = Number(node.position_hint?.branch ?? 0);
        const x = 140 + level * 182;
        const y = 110 + branch * 150 + order * 22;
        positions.set(node.id, { x, y, level, branch, order });
      }
    }
    return { width, height, positions };
  }

  function createStage() {
    refs.canvasHost.innerHTML = "";
    const stage = new Konva.Stage({
      container: "canvasHost",
      width: refs.canvasHost.clientWidth,
      height: refs.canvasHost.clientHeight,
    });
    const backgroundLayer = new Konva.Layer({ listening: false });
    const edgeLayer = new Konva.Layer();
    const nodeLayer = new Konva.Layer();
    const overlayLayer = new Konva.Layer();
    stage.add(backgroundLayer);
    stage.add(edgeLayer);
    stage.add(nodeLayer);
    stage.add(overlayLayer);
    state.stage = stage;
    state.layers = { backgroundLayer, edgeLayer, nodeLayer, overlayLayer };
  }

  function fitStageToHost() {
    if (!state.stage || !refs.canvasHost) return;
    const hostWidth = refs.canvasHost.clientWidth;
    const hostHeight = refs.canvasHost.clientHeight;
    const stageWidth = state.stage.width();
    const stageHeight = state.stage.height();
    if (!stageWidth || !stageHeight) return;
    const scale = Math.min(hostWidth / stageWidth, hostHeight / stageHeight, 1);
    const x = Math.max((hostWidth - stageWidth * scale) / 2, 0);
    const y = Math.max((hostHeight - stageHeight * scale) / 2, 0);
    state.stage.scale({ x: scale, y: scale });
    state.stage.position({ x, y });
    state.stage.batchDraw();
  }

  function drawBackgroundGrid(width, height) {
    const layer = state.layers.backgroundLayer;
    layer.destroyChildren();
    const columns = Math.ceil(width / 120);
    const rows = Math.ceil(height / 120);
    for (let i = 0; i <= columns; i += 1) {
      layer.add(
        new Konva.Line({
          points: [i * 120, 0, i * 120, height],
          stroke: "rgba(148,163,184,0.08)",
          strokeWidth: 1,
          listening: false,
        }),
      );
    }
    for (let i = 0; i <= rows; i += 1) {
      layer.add(
        new Konva.Line({
          points: [0, i * 120, width, i * 120],
          stroke: "rgba(148,163,184,0.08)",
          strokeWidth: 1,
          listening: false,
        }),
      );
    }
    layer.draw();
  }

  function registerNode(node, position) {
    const styles = stateStyle(node.visual_state);
    const group = new Konva.Group({
      x: position.x,
      y: position.y,
      id: node.id,
      name: `route-node route-node-${node.visual_state}`,
    });
    const body = new Konva.Rect({
      x: 0,
      y: 0,
      width: 172,
      height: 96,
      cornerRadius: 18,
      fill: styles.fill,
      stroke: styles.stroke,
      strokeWidth: 2,
      shadowColor: styles.stroke,
      shadowBlur: 0,
      shadowOpacity: 0.18,
    });
    const iconFrame = new Konva.Rect({
      x: 12,
      y: 12,
      width: 42,
      height: 42,
      cornerRadius: 12,
      fill: "rgba(4, 10, 20, 0.8)",
      stroke: "rgba(255,255,255,0.12)",
      strokeWidth: 1,
    });
    const deviceFile = getDeviceIconFile(node.symbol?.device_icon);
    const icon = new Konva.Image({
      x: 12,
      y: 12,
      width: 42,
      height: 42,
      image: null,
      visible: false,
      listening: false,
    });
    loadImage(deviceFile).then((image) => {
      if (!image) return;
      icon.image(image);
      icon.visible(true);
      state.layers.nodeLayer.batchDraw();
    });
    const label = new Konva.Text({
      x: 64,
      y: 13,
      width: 96,
      text: node.label || node.id,
      fill: styles.text,
      fontSize: 16,
      fontStyle: "700",
      ellipsis: true,
    });
    const short = new Konva.Text({
      x: 64,
      y: 35,
      width: 96,
      text: node.short_label || node.ip || "-",
      fill: "rgba(226,232,240,0.85)",
      fontSize: 12,
      ellipsis: true,
    });
    const statePill = new Konva.Label({ x: 110, y: 12, opacity: 0.96 });
    statePill.add(
      new Konva.Tag({
        fill: "rgba(15, 23, 42, 0.85)",
        stroke: styles.stroke,
        strokeWidth: 1,
        cornerRadius: 999,
        shadowColor: styles.stroke,
        shadowBlur: 0,
      }),
    );
    statePill.add(
      new Konva.Text({
        text: humanizeState(node.visual_state),
        fontSize: 9.5,
        fill: styles.text,
        padding: 5,
      }),
    );
    const meta = new Konva.Text({
      x: 12,
      y: 63,
      width: 148,
      text: `conf ${formatConfidence(node.confidence)} · ${node.cluster || "unknown"}`,
      fill: "rgba(203, 213, 225, 0.9)",
      fontSize: 10.5,
    });
    group.add(body, iconFrame, icon, label, short, statePill, meta);
    group.on("mouseenter", () => {
      document.body.style.cursor = "pointer";
      body.strokeWidth(3);
      state.layers.nodeLayer.batchDraw();
    });
    group.on("mouseleave", () => {
      document.body.style.cursor = "default";
      body.strokeWidth(2);
      state.layers.nodeLayer.batchDraw();
    });
    group.on("click", () => selectElement({ type: "node", id: node.id }));
    state.layers.nodeLayer.add(group);
    state.nodeGroups.set(node.id, { group, body, iconFrame, icon, label, short, statePill, meta, node, position });
  }

  function registerEdge(edge) {
    const src = state.nodeLookup.get(edge.source);
    const dst = state.nodeLookup.get(edge.target);
    if (!src || !dst) return;
    const srcPos = state.nodeGroups.get(edge.source)?.position;
    const dstPos = state.nodeGroups.get(edge.target)?.position;
    if (!srcPos || !dstPos) return;
    const startX = srcPos.x + 86;
    const startY = srcPos.y + 48;
    const endX = dstPos.x + 86;
    const endY = dstPos.y + 48;
    const styles = edge.edge_type === "synthetic_dependency"
      ? { stroke: "rgba(148,163,184,0.45)", dash: [8, 8], width: 2.5 }
      : edge.visual_state === "unknown"
        ? { stroke: "rgba(251,191,36,0.65)", dash: [10, 6], width: 3 }
        : edge.visual_state === "limited"
          ? { stroke: "rgba(148,163,184,0.7)", dash: [7, 7], width: 2.5 }
          : { stroke: "rgba(76,201,240,0.78)", dash: [], width: 3.5 };
    const group = new Konva.Group({
      id: edge.id,
      name: `route-edge route-edge-${edge.visual_state}`,
    });
    const arrow = new Konva.Arrow({
      points: [startX, startY, endX, endY],
      pointerLength: 9,
      pointerWidth: 9,
      stroke: styles.stroke,
      fill: styles.stroke,
      strokeWidth: styles.width,
      dash: styles.dash,
      lineCap: "round",
      lineJoin: "round",
      opacity: 0.92,
    });
    const hitLine = new Konva.Line({
      points: [startX, startY, endX, endY],
      stroke: "rgba(0,0,0,0.001)",
      strokeWidth: 16,
      lineCap: "round",
      lineJoin: "round",
    });
    const midX = (startX + endX) / 2;
    const midY = (startY + endY) / 2;
    const label = new Konva.Text({
      x: midX - 70,
      y: midY - 22,
      width: 140,
      align: "center",
      text: edge.transition_type || edge.edge_type,
      fill: "rgba(216, 227, 244, 0.85)",
      fontSize: 10,
      listening: false,
    });
    group.add(arrow, hitLine, label);
    group.on("mouseenter", () => {
      document.body.style.cursor = "pointer";
      arrow.strokeWidth(styles.width + 1.5);
      arrow.opacity(1);
      state.layers.edgeLayer.batchDraw();
    });
    group.on("mouseleave", () => {
      document.body.style.cursor = "default";
      arrow.strokeWidth(styles.width);
      arrow.opacity(0.92);
      state.layers.edgeLayer.batchDraw();
    });
    group.on("click", () => selectElement({ type: "edge", id: edge.id }));
    state.layers.edgeLayer.add(group);
    state.edgeGroups.set(edge.id, { group, arrow, hitLine, label, edge, startX, startY, endX, endY });
  }

  function renderStage(payload) {
    state.nodeGroups.clear();
    state.edgeGroups.clear();
    state.nodeLookup = new Map((payload.nodes || []).map((node) => [node.id, node]));
    state.edgeLookup = new Map((payload.edges || []).map((edge) => [edge.id, edge]));
    const layout = buildLayout(payload.nodes || []);
    state.stage.width(layout.width);
    state.stage.height(layout.height);
    drawBackgroundGrid(layout.width, layout.height);
    state.layers.edgeLayer.destroyChildren();
    state.layers.nodeLayer.destroyChildren();
    state.layers.overlayLayer.destroyChildren();

    for (const node of payload.nodes || []) {
      const position = layout.positions.get(node.id) || { x: 120, y: 120 };
      registerNode(node, position);
    }
    for (const edge of payload.edges || []) {
      registerEdge(edge);
    }

    state.layers.edgeLayer.draw();
    state.layers.nodeLayer.draw();
    state.layers.overlayLayer.draw();
    fitStageToHost();
    refs.canvasLoading.classList.add("hidden");
  }

  function selectElement(selection) {
    state.selected = selection;
    if (!selection) {
      renderEmptyDetail();
      return;
    }
    if (selection.type === "node") {
      const node = state.nodeLookup.get(selection.id);
      if (!node) return;
      renderNodeDetail(node);
      return;
    }
    if (selection.type === "edge") {
      const edge = state.edgeLookup.get(selection.id);
      if (!edge) return;
      renderEdgeDetail(edge);
    }
  }

  function renderEmptyDetail() {
    refs.detailPanel.innerHTML = '<p class="detail-empty">Clique em um node ou edge para inspecionar o contexto.</p>';
  }

  function renderNodeDetail(node) {
    const symbol = node.symbol || {};
    refs.detailPanel.innerHTML = `
      <dl class="detail-grid">
        <div class="detail-row"><dt>Label/IP</dt><dd>${esc(node.label || "-")} / ${esc(node.ip || "-")}</dd></div>
        <div class="detail-row"><dt>knowledge_state</dt><dd>${esc(node.knowledge_state || "-")}</dd></div>
        <div class="detail-row"><dt>visual_state</dt><dd>${esc(node.visual_state || "-")}</dd></div>
        <div class="detail-row"><dt>known_before / observed_now</dt><dd>${node.known_before ? "true" : "false"} / ${node.observed_now ? "true" : "false"}</dd></div>
        <div class="detail-row"><dt>confidence</dt><dd>${esc(formatConfidence(node.confidence))}</dd></div>
        <div class="detail-row"><dt>operator_message</dt><dd class="detail-operator">${esc(node.operator_message || "-")}</dd></div>
        <div class="detail-row"><dt>symbol</dt><dd>${esc(symbol.device_icon || "-")} · ${esc(symbol.org_badge || "-")} · ${esc(symbol.flag || "-")} · ${esc((symbol.states || []).join(", ") || "-")}</dd></div>
        <div class="detail-row"><dt>metadata</dt><dd>${esc(summarizeMetadata(node.metadata))}</dd></div>
      </dl>
    `;
  }

  function renderEdgeDetail(edge) {
    refs.detailPanel.innerHTML = `
      <dl class="detail-grid">
        <div class="detail-row"><dt>source → target</dt><dd>${esc(edge.source)} → ${esc(edge.target)}</dd></div>
        <div class="detail-row"><dt>edge_type</dt><dd>${esc(edge.edge_type || "-")}</dd></div>
        <div class="detail-row"><dt>transition_type</dt><dd>${esc(edge.transition_type || "-")}</dd></div>
        <div class="detail-row"><dt>visual_state</dt><dd>${esc(edge.visual_state || "-")}</dd></div>
        <div class="detail-row"><dt>confidence</dt><dd>${esc(formatConfidence(edge.confidence))}</dd></div>
        <div class="detail-row"><dt>operator_message</dt><dd class="detail-operator">${esc(edge.operator_message || "-")}</dd></div>
        <div class="detail-row"><dt>metadata</dt><dd>${esc(summarizeMetadata(edge.metadata))}</dd></div>
      </dl>
    `;
  }

  function renderIgnoringAndQueue(payload) {
    refs.ignorancePanel.innerHTML = (payload.ignorance_events || [])
      .map((event) => {
        const tags = [
          event.event_type,
          event.priority,
          event.next_action,
        ].filter(Boolean);
        return `
          <article class="compact-item" data-ignorance-id="${esc(event.event_uid)}">
            <div class="compact-item-top">
              <span class="compact-item-title">${esc(event.event_type)}</span>
              <span class="compact-item-meta">${esc(event.priority || "-")}</span>
            </div>
            <div class="compact-item-meta">${esc(event.object_id || "-")}</div>
            <div class="compact-item-note">${esc(event.operator_message || "-")}</div>
            <div class="compact-tags">${tags.map((tag) => `<span class="compact-tag">${esc(tag)}</span>`).join("")}</div>
          </article>
        `;
      })
      .join("");

    refs.queuePanel.innerHTML = (payload.learning_queue || [])
      .map((item) => {
        const tags = [item.reason, item.status, item.priority_score].filter((value) => value !== undefined && value !== null);
        return `
          <article class="compact-item" data-queue-id="${esc(item.queue_uid)}">
            <div class="compact-item-top">
              <span class="compact-item-title">${esc(item.object_id || "-")}</span>
              <span class="compact-item-meta">${esc(String(item.priority_score ?? "-"))}</span>
            </div>
            <div class="compact-item-meta">${esc(item.reason || "-")}</div>
            <div class="compact-item-note">${esc(item.operator_message || "-")}</div>
            <div class="compact-tags">${tags.map((tag) => `<span class="compact-tag">${esc(tag)}</span>`).join("")}</div>
            <div class="compact-item-meta">planned: ${esc((item.planned_actions || []).join(", ") || "-")}</div>
          </article>
        `;
      })
      .join("");
  }

  function renderDedicatedRunPlan(payload) {
    if (!refs.dedicatedPlanSection || !refs.dedicatedPlanPanel) return;
    const plan = payload.dedicated_run_plan;
    const comparison = payload.learning_comparison_plan;
    const routeProfile = payload.route_profile;
    const postChangePlans = payload.post_change_run_plans;
    if (!plan && !postChangePlans) {
      refs.dedicatedPlanSection.classList.add("hidden");
      refs.dedicatedPlanPanel.innerHTML = "";
      return;
    }
    refs.dedicatedPlanSection.classList.remove("hidden");
    const safety = plan.safety_policy || {};
    const safetyBits = [
      safety.read_only_plan ? "read_only_plan=true" : null,
      safety.no_execution_in_this_request ? "no_execution_in_this_request=true" : null,
      safety.max_targets !== undefined ? `max_targets=${safety.max_targets}` : null,
      safety.require_admin ? "require_admin=true" : null,
      safety.require_confirm ? "require_confirm=true" : null,
    ].filter(Boolean);
    const routeSummary = routeProfile?.route_summary || {};
    const measurementContext = routeProfile?.measurement_context || {};
    const postChangePlanCards = (postChangePlans?.plans || [])
      .map((postPlan) => `
        <article class="compact-item">
          <div class="compact-item-top">
            <span class="compact-item-title">${esc(postPlan.ip_family || "-")} · ${esc(postPlan.status || "-")}</span>
            <span class="compact-item-meta">${esc(postPlan.required_role || "-")}</span>
          </div>
          <div class="compact-item-meta">target=${esc(postPlan.target || "-")} · baseline=${esc(postPlan.baseline_type || "-")}</div>
          <div class="compact-tags">
            <span class="compact-tag">plan_uid=${esc(postPlan.plan_uid || "-")}</span>
            <span class="compact-tag">confirm=${postPlan.requires_operator_confirmation ? "required" : "not_required"}</span>
            <span class="compact-tag">active_action_executed=${postPlan.active_action_executed ? "true" : "false"}</span>
          </div>
          <div class="compact-item-note">${esc(postPlan.operator_message || "Plano read-only; nenhuma acao ativa executada neste payload.")}</div>
        </article>
      `)
      .join("");
    refs.dedicatedPlanPanel.innerHTML = `
      ${plan ? `
        <article class="compact-item">
        <div class="compact-item-top">
          <span class="compact-item-title">${esc(plan.status || "waiting_operator_confirmation")}</span>
          <span class="compact-item-meta">${esc(plan.required_role || "-")}</span>
        </div>
        <div class="compact-item-meta">${esc(plan.reason || "-")}</div>
        <div class="compact-item-note">${esc(plan.operator_message || "-")}</div>
        <div class="compact-tags">
          <span class="compact-tag">plan_uid=${esc(plan.plan_uid || "-")}</span>
          <span class="compact-tag">requires_confirmation=${plan.requires_operator_confirmation ? "true" : "false"}</span>
          <span class="compact-tag">active_action_executed=${plan.active_action_executed ? "true" : "false"}</span>
        </div>
        <div class="compact-item-meta">expected: ${esc((plan.expected_learning || []).join(", ") || "-")}</div>
        <div class="compact-item-meta">proposed: ${esc((plan.proposed_actions || []).join(", ") || "-")}</div>
        <div class="compact-item-meta">safety: ${esc(safetyBits.join(" · ") || "-")}</div>
        ${comparison ? `
          <div class="compact-item-meta">comparacao: ${esc(comparison.status || "-")} · ${esc(comparison.endpoint || "-")}</div>
          <div class="compact-item-note">${esc(comparison.operator_message || "-")}</div>
          ${comparison.observed_after_state ? `
            <div class="compact-item-meta">after observado: ${comparison.observed_after_state.exists ? "true" : "false"} · run=${esc(comparison.observed_after_state.dedicated_run_uid || "-")}</div>
            <div class="compact-item-note">${esc((comparison.comparison_result && comparison.comparison_result.operator_message) || "Comparação ainda não observada.")}</div>
          ` : ""}
        ` : ""}
        ${routeProfile ? `
          <div class="compact-item-top" style="margin-top: 0.85rem;">
            <span class="compact-item-title">Perfil de rota</span>
            <span class="compact-item-meta">${esc(routeProfile.status || "-")}</span>
          </div>
          <div class="compact-item-meta">aprendido de: ${esc(routeProfile.learned_from?.dedicated_run_uid || "-")}</div>
          <div class="compact-item-meta">endpoint: ${esc(routeProfile.endpoint || "-")}</div>
          <div class="compact-item-meta">contexto: ${esc(measurementContext.baseline_type || "-")} · ${esc(measurementContext.local_change_event || "-")} · ${esc(measurementContext.ip_family || "-")}</div>
          <div class="compact-item-meta">logical/responding/silent: ${esc(routeSummary.logical_hop_count || routeSummary.hop_count || "-")} / ${esc(routeSummary.responding_hop_count || "-")} / ${esc(routeSummary.silent_hop_count ?? "-")}</div>
          <div class="compact-item-meta">edges: ${esc(routeSummary.edge_count || "-")} · persisted=${esc(routeSummary.persisted_edge_count || "-")} · final_destination_asserted=${routeSummary.final_destination_asserted ? "true" : "false"}</div>
          ${routeProfile.temporal_comparison ? `
            <div class="compact-item-meta">baseline temporal: ${esc(routeProfile.temporal_comparison.status || "-")} · ${esc(routeProfile.temporal_comparison.baseline_availability?.status || "-")}</div>
            <div class="compact-item-note">${esc(routeProfile.temporal_comparison.operator_message || "-")}</div>
          ` : ""}
          <div class="compact-item-meta">ASN: ${esc(routeProfile.asn_attribution_summary?.attribution_engine_status || "-")} · sem ASN: ${esc(routeProfile.asn_attribution_summary?.hops_without_asn || "-")} · privados: ${esc(routeProfile.asn_attribution_summary?.private_ip_hops || "-")} · silenciosos: ${esc(routeProfile.asn_attribution_summary?.icmp_silent_hops || "-")}</div>
          <div class="compact-item-note">${esc(routeProfile.operator_message || "-")}</div>
        ` : ""}
      </article>
      ` : ""}
      ${postChangePlans ? `
        <article class="compact-item">
          <div class="compact-item-top">
            <span class="compact-item-title">Planos pos-mudanca</span>
            <span class="compact-item-meta">${esc(postChangePlans.safety_status || "-")}</span>
          </div>
          <div class="compact-item-meta">active_action_executed=${postChangePlans.active_action_executed ? "true" : "false"} · required_role=${esc(postChangePlans.required_role || "-")}</div>
          <div class="compact-item-note">${esc(postChangePlans.operator_message || "-")}</div>
        </article>
        ${postChangePlanCards}
      ` : ""}
    `;
  }

  function highlightNode(nodeId, mode = "observed_now") {
    const nodeEntry = state.nodeGroups.get(nodeId);
    if (!nodeEntry) return;
    const styles = stateStyle(mode);
    nodeEntry.body.shadowBlur(18);
    nodeEntry.body.shadowOpacity(0.5);
    nodeEntry.body.stroke(styles.stroke);
    nodeEntry.body.fill(styles.fill);
    nodeEntry.label.fill(styles.text);
    nodeEntry.short.fill("rgba(226,232,240,0.9)");
    nodeEntry.statePill.visible(true);
    state.layers.nodeLayer.batchDraw();
    window.setTimeout(() => {
      nodeEntry.body.shadowBlur(0);
      nodeEntry.body.shadowOpacity(0.18);
      state.layers.nodeLayer.batchDraw();
    }, 650);
  }

  function highlightEdge(edgeId, mode = "observed_now") {
    const edgeEntry = state.edgeGroups.get(edgeId);
    if (!edgeEntry) return;
    const styles = stateStyle(mode);
    edgeEntry.arrow.stroke(styles.stroke);
    edgeEntry.arrow.fill(styles.stroke);
    edgeEntry.arrow.opacity(1);
    state.layers.edgeLayer.batchDraw();
    window.setTimeout(() => {
      edgeEntry.arrow.opacity(0.92);
      state.layers.edgeLayer.batchDraw();
    }, 650);
  }

  function getNodeCenter(nodeId) {
    const entry = state.nodeGroups.get(nodeId);
    if (!entry) return null;
    return { x: entry.position.x + 86, y: entry.position.y + 48 };
  }

  function ensurePacket() {
    if (state.packet) return state.packet;
    state.packet = new Konva.Circle({
      x: 0,
      y: 0,
      radius: 7,
      fill: "#f8fafc",
      stroke: "#4cc9f0",
      strokeWidth: 2,
      shadowColor: "#4cc9f0",
      shadowBlur: 12,
      shadowOpacity: 0.8,
      opacity: 0,
      listening: false,
    });
    state.layers.overlayLayer.add(state.packet);
    state.layers.overlayLayer.draw();
    return state.packet;
  }

  function movePacketTo(targetId) {
    const target = getNodeCenter(targetId);
    if (!target) return;
    const packet = ensurePacket();
    const start = state.packetNodeId ? getNodeCenter(state.packetNodeId) : getNodeCenter("origin:local") || target;
    packet.opacity(1);
    packet.position({ x: start.x, y: start.y });
    state.layers.overlayLayer.draw();
    packet.to({
      x: target.x,
      y: target.y,
      duration: 0.55,
      easing: Konva.Easings.EaseInOut,
      onFinish: () => state.layers.overlayLayer.batchDraw(),
    });
    state.packetNodeId = targetId;
  }

  function updateStatusFromEvent(event) {
    if (!event) return;
    switch (event.event_type) {
      case "session_started":
        setStatus(event.message || "Sessão iniciada");
        setPlaybackBadge("sessão ativa");
        break;
      case "knowledge_checked":
        setStatus(event.message || "Conhecimento checado");
        break;
      case "ignorance_revealed":
        setStatus(`Ignorância revelada: ${event.target_id || "gap"}`);
        break;
      case "queued_for_learning":
        setStatus(`Enfileirado para aprendizado: ${event.target_id || "-"}`);
        break;
      case "learning_completed":
        setStatus(event.message || "Aprendizado concluído");
        break;
      case "session_completed":
        setStatus(event.message || "Sessão concluída");
        setPlaybackBadge("sessão concluída");
        break;
      default:
        if (event.message) setStatus(event.message);
        break;
    }
  }

  function applyTimelineEvent(event) {
    setFrameBadge(`frame ${event.time_index}/${state.payload.timeline.length}`);
    updateStatusFromEvent(event);
    switch (event.event_type) {
      case "session_started":
        if (event.target_id) highlightNode("origin:local", "known");
        break;
      case "node_added":
        if (event.target_id) {
          highlightNode(event.target_id, "observed_now");
          movePacketTo(event.target_id);
        }
        break;
      case "edge_added":
        if (event.target_id) highlightEdge(event.target_id, "observed_now");
        break;
      case "packet_moved":
        if (event.target_id) movePacketTo(event.target_id);
        break;
      case "knowledge_checked":
        if (event.target_id) highlightNode(event.target_id, "limited");
        break;
      case "ignorance_revealed":
        if (event.target_id && state.nodeGroups.has(event.target_id)) {
          highlightNode(event.target_id, "queued_for_inventory");
        } else if (event.target_id && state.edgeGroups.has(event.target_id)) {
          highlightEdge(event.target_id, "limited");
        } else {
          highlightEdge("edge:hop:10.21.0.1->hop:unknown:3", "limited");
        }
        break;
      case "queued_for_learning":
        if (event.target_id) highlightNode(event.target_id, "queued_for_inventory");
        break;
      case "learning_completed":
        if (event.target_id) {
          highlightNode(event.target_id, "learned_now");
          movePacketTo(event.target_id);
        }
        break;
      case "session_completed":
        if (event.target_id) highlightNode(event.target_id, "learned_now");
        break;
      default:
        break;
    }
  }

  function stopPlayback() {
    state.playing = false;
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
    setPlaybackBadge("timeline parada");
    refs.playButton.disabled = false;
    refs.pauseButton.disabled = true;
  }

  function playNext() {
    if (!state.payload) return;
    if (state.timelineIndex >= state.payload.timeline.length) {
      stopPlayback();
      setStatus("Sessão concluída.");
      return;
    }
    const event = state.payload.timeline[state.timelineIndex];
    applyTimelineEvent(event);
    state.timelineIndex += 1;
    const duration = Math.max(320, Math.round((event.duration_ms || 650) * 0.85));
    state.timer = window.setTimeout(playNext, duration);
  }

  function startPlayback() {
    if (!state.payload) return;
    if (state.playing) return;
    state.playing = true;
    refs.playButton.disabled = true;
    refs.pauseButton.disabled = false;
    setPlaybackBadge("reproduzindo");
    playNext();
  }

  function resetDemo() {
    if (!state.payload) return;
    stopPlayback();
    state.timelineIndex = 0;
    state.packetNodeId = null;
    setFrameBadge(`frame 0/${state.payload.timeline.length}`);
    renderStage(state.payload);
    renderSummary(state.payload);
    renderDedicatedRunPlan(state.payload);
    renderIgnoringAndQueue(state.payload);
    renderEmptyDetail();
    setStatus("Sessão reiniciada. Pronto para reproduzir.");
  }

  async function loadPayload(sessionKey = "google") {
    const endpoints = SESSION_OPTIONS[sessionKey] || SESSION_OPTIONS.google;
    let lastError = null;
    for (const endpoint of endpoints) {
      try {
        const response = await fetch(endpoint, { credentials: "same-origin" });
        if (response.ok) {
          return response.json();
        }
        lastError = new Error(`Falha ao carregar o payload demo (${endpoint} -> ${response.status}).`);
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("Falha ao carregar o payload demo.");
  }

  function initRefs() {
    refs.canvasHost = document.getElementById("canvasHost");
    refs.canvasLoading = document.getElementById("canvasLoading");
    refs.sessionStatusBadge = document.getElementById("sessionStatusBadge");
    refs.targetBadge = document.getElementById("targetBadge");
    refs.sessionSummary = document.getElementById("sessionSummary");
    refs.playbackBadge = document.getElementById("playbackBadge");
    refs.frameBadge = document.getElementById("frameBadge");
    refs.statusLine = document.getElementById("statusLine");
    refs.summaryStrip = document.getElementById("summaryStrip");
    refs.detailPanel = document.getElementById("detailPanel");
    refs.ignorancePanel = document.getElementById("ignorancePanel");
    refs.queuePanel = document.getElementById("queuePanel");
    refs.dedicatedPlanSection = document.getElementById("dedicatedPlanSection");
    refs.dedicatedPlanPanel = document.getElementById("dedicatedPlanPanel");
    refs.playButton = document.getElementById("playButton");
    refs.pauseButton = document.getElementById("pauseButton");
    refs.restartButton = document.getElementById("restartButton");
    refs.fitButton = document.getElementById("fitButton");
    refs.demoModeBadge = document.getElementById("demoModeBadge");
    refs.sessionPicker = document.getElementById("sessionPicker");
  }

  function bindEvents() {
    refs.playButton.addEventListener("click", startPlayback);
    refs.pauseButton.addEventListener("click", stopPlayback);
    refs.restartButton.addEventListener("click", resetDemo);
    refs.fitButton.addEventListener("click", () => {
      fitStageToHost();
      setStatus("Canvas ajustado à tela.");
    });
    refs.sessionPicker.addEventListener("change", () => {
      stopPlayback();
      bootstrapPayload(refs.sessionPicker.value);
    });
    window.addEventListener("resize", () => {
      if (state.autoFit) fitStageToHost();
    });
  }

  async function bootstrapPayload(sessionKey = "google") {
    refs.pauseButton.disabled = true;
    refs.playButton.disabled = true;
    refs.canvasLoading.classList.remove("hidden");
    refs.canvasLoading.innerHTML = "<p>Carregando visualização demo...</p>";
    setStatus("Carregando payload demonstrativo...");
    try {
      const payload = await loadPayload(sessionKey);
      state.payload = payload;
      state.timelineIndex = 0;
      state.packetNodeId = null;
      state.selected = null;
      createStage();
      renderSummary(payload);
      renderDedicatedRunPlan(payload);
      renderIgnoringAndQueue(payload);
      renderStage(payload);
      renderEmptyDetail();
      setFrameBadge(`frame 0/${payload.timeline.length}`);
      setPlaybackBadge("timeline parada");
      setStatus("Payload carregado. Pronto para reprodução read-only.");
      refs.playButton.disabled = false;
      refs.pauseButton.disabled = true;
    } catch (error) {
      setSessionBadge("erro", "pill-loading");
      refs.canvasLoading.innerHTML = "<p>Falha ao carregar o payload demo.</p>";
      setStatus(error?.message || "Falha ao carregar payload demo.");
      console.error("[route-learning-demo]", error);
      return;
    }
  }

  async function bootstrap() {
    initRefs();
    bindEvents();
    await bootstrapPayload(refs.sessionPicker?.value || "google");
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
