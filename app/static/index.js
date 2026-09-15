const $ = (id) => document.getElementById(id);

async function fetchJson(path) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(response.statusText);
  }
  return response.json();
}

async function loadAuth() {
  const badge = $("authBadge");
  try {
    const payload = await fetchJson("/auth/me");
    const role = payload.role || "desconhecido";
    const username = payload.username || "usuário";
    badge.textContent = `${username} · ${role === "admin" ? "operador" : "leitura"}`;
    badge.classList.remove("auth-loading");
    badge.classList.add(role === "admin" ? "auth-admin" : "auth-viewer");
  } catch {
    badge.textContent = "não autenticado";
    badge.classList.add("auth-error");
  }
}

async function checkInventory() {
  const card = $("inventoryCard");
  const state = $("inventoryState");
  if (!card || !state) return;
  try {
    const response = await fetch("/inventory/ui", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "text/html" },
    });
    if (!response.ok) {
      throw new Error("unavailable");
    }
    state.textContent = "ativo";
  } catch {
    state.textContent = "em preparação";
    state.classList.add("preparing");
    card.removeAttribute("href");
    card.classList.add("is-disabled");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadAuth().catch(() => {
    const badge = $("authBadge");
    if (badge) {
      badge.textContent = "Autenticação indisponível";
      badge.classList.add("auth-error");
    }
  });
  checkInventory().catch(() => {});
});
