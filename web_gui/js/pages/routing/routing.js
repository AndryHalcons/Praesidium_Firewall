/*
 * ES: Página especial Routing: snapshot readonly de rutas/reglas + recarga admin.
 * EN: Special Routing page: readonly routes/rules snapshot + admin reload.
 */
(() => {
  "use strict";

  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;
  const { t } = window.PraesidiumI18n;
  const SECTION = "routing";
  const BASE = "/js/pages/routing";

  const state = {
    commands: null,
    routes: [],
    rules: [],
  };

  const ROUTE_COLUMNS = ["table", "ip_version", "action", "destination", "gateway", "interface", "metric", "proto", "scope", "src", "type"];
  const RULE_COLUMNS = ["priority", "action", "from", "to", "table"];

  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  async function loadMetadata() {
    if (state.commands) return state;
    state.commands = await fetchJson(`${BASE}/routing_commands_api.json`);
    return state;
  }

  function label(key) {
    const translated = t(`routing.${key}`);
    return translated !== `routing.${key}` ? translated : key;
  }

  function statusNode(message, type = "info") {
    return el("div", { className: `pf-alert ${type}` }, [message]);
  }

  function titleNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("routing.title")]),
        el("p", { className: "pf-muted" }, [t("routing.description")]),
      ]),
    ]);
  }

  function cellValue(row, key) {
    const value = row && Object.prototype.hasOwnProperty.call(row, key) ? row[key] : "";
    if (value === null || value === undefined) return "";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  }

  function renderTable(rows, columns, emptyText) {
    if (!Array.isArray(rows) || rows.length === 0) return statusNode(emptyText, "info");
    const table = el("table", { className: "interfaz" }, []);
    const thead = document.createElement("thead");
    thead.appendChild(tr(columns.map(col => th(label(col), { "data-status": col }))));
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    rows.forEach(row => {
      tbody.appendChild(tr(columns.map(col => td(cellValue(row, col)))));
    });
    table.appendChild(tbody);
    window.PraesidiumTableFilter.attach(table);
    return el("div", { className: "pf-table-wrap" }, [table]);
  }

  function renderSummary(payload) {
    const hasSnapshot = payload && payload.has_snapshot === true;
    const routesCount = Array.isArray(payload && payload.routes) ? payload.routes.length : 0;
    const rulesCount = Array.isArray(payload && payload.rules) ? payload.rules.length : 0;
    return el("div", { className: "pf-card" }, [
      el("h3", {}, [t("routing.summary_title")]),
      el("div", { className: "pf-grid" }, [
        statusNode(`${t("routing.has_snapshot")}: ${hasSnapshot ? t("routing.yes") : t("routing.no")}`),
        statusNode(`${t("routing.routes_count")}: ${routesCount}`),
        statusNode(`${t("routing.rules_count")}: ${rulesCount}`),
      ]),
    ]);
  }

  function renderData(container, payload, statusBox) {
    state.routes = Array.isArray(payload && payload.routes) ? payload.routes : [];
    state.rules = Array.isArray(payload && payload.rules) ? payload.rules : [];
    const content = [
      titleNode(),
      renderActions(container, statusBox),
      renderSummary(payload || {}),
      el("div", { className: "pf-card" }, [
        el("h3", {}, [t("routing.routes_title")]),
        renderTable(state.routes, ROUTE_COLUMNS, t("routing.no_routes")),
      ]),
      el("div", { className: "pf-card" }, [
        el("h3", {}, [t("routing.rules_title")]),
        renderTable(state.rules, RULE_COLUMNS, t("routing.no_rules")),
      ]),
    ];
    replaceChildren(container, content);
  }

  async function read(container) {
    const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "read");
    renderData(container, payload, statusNode(t("routing.ready")));
  }

  async function reload(container, button, statusBox) {
    try {
      button.disabled = true;
      statusBox.className = "pf-alert";
      statusBox.replaceChildren(t("routing.reloading"));
      const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "reload");
      renderData(container, { routes: payload.routes, rules: payload.rules, has_snapshot: true }, statusNode(t("routing.reload_done"), "success"));
    } catch (error) {
      statusBox.className = "pf-alert error";
      statusBox.replaceChildren(error && error.message ? error.message : String(error));
    } finally {
      button.disabled = false;
    }
  }

  function renderActions(container, existingStatus) {
    const statusBox = existingStatus || statusNode(t("routing.ready"));
    const refreshButton = el("button", { className: "button_save", type: "button" }, [t("routing.refresh")]);
    if (window.PraesidiumState.isAdmin()) {
      refreshButton.addEventListener("click", () => reload(container, refreshButton, statusBox));
    } else {
      refreshButton.addEventListener("click", () => read(container));
    }
    return el("div", { className: "pf-card" }, [
      el("h3", {}, [t("routing.actions_title")]),
      el("div", { className: "pf-actions" }, [refreshButton]),
      statusBox,
    ]);
  }

  async function render(container) {
    try {
      replaceChildren(container, [titleNode(), statusNode(t("common.loading"))]);
      await loadMetadata();
      await read(container);
    } catch (error) {
      replaceChildren(container, [titleNode(), statusNode(error && error.message ? error.message : String(error), "error")]);
    }
  }

  window.PraesidiumRoutingPage = { render };
})();
