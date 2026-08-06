/*
 * ES: Página especial Monitor Logs: filtros iniciales + resultados readonly.
 * EN: Special Monitor Logs page: initial filters + readonly results.
 */
(() => {
  "use strict";

  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;
  const { t } = window.PraesidiumI18n;
  const SECTION = "monitor_logs";
  const BASE = "/js/pages/monitor_logs";

  const state = {
    commands: null,
    filterColumns: [],
    logColumns: [],
    forms: {},
    lastRows: [],
    lastFilters: {},
  };

  // ES: Carga un JSON de metadata local sin caché para reflejar cambios de desarrollo.
  // EN: Loads local metadata JSON without cache so development changes are reflected.
  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  // ES: Carga y cachea forms, estructuras y comandos API del módulo monitor_logs.
  // EN: Loads and caches forms, structures, and API commands for the monitor_logs module.
  async function loadMetadata() {
    if (state.commands) return state;
    const [forms, filtersStructure, logsStructure, commands] = await Promise.all([
      fetchJson(`${BASE}/forms_monitor.json`),
      fetchJson(`${BASE}/structure_table_monitor.json`),
      fetchJson(`${BASE}/structure_table_monitor_log.json`),
      fetchJson(`${BASE}/monitor_logs_commands_api.json`),
    ]);
    state.forms = forms || {};
    state.filterColumns = Array.isArray(filtersStructure.Search_Filter) ? filtersStructure.Search_Filter : [];
    state.logColumns = Array.isArray(logsStructure.Search_Filter) ? logsStructure.Search_Filter : [];
    state.commands = commands || {};
    return state;
  }

  // ES: Traduce una columna de monitor_logs y cae al nombre técnico si no hay clave i18n.
  // EN: Translates a monitor_logs column and falls back to the technical name when no i18n key exists.
  function label(key) {
    return t(`monitor_logs.${key}`) !== `monitor_logs.${key}` ? t(`monitor_logs.${key}`) : key;
  }

  // ES: Construye un aviso visual estándar para estados de carga, error o vacío.
  // EN: Builds a standard visual alert for loading, error, or empty states.
  function statusNode(message, type = "info") {
    return el("div", { className: `pf-alert ${type}` }, [message]);
  }

  // ES: Devuelve el título normal del módulo sin usar la cabecera legacy.
  // EN: Returns the normal module title without using the legacy header.
  function titleNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("monitor_logs.title")]),
        el("p", { className: "pf-muted" }, [t("monitor_logs.description")]),
      ]),
    ]);
  }

  // ES: Formatea una fecha JavaScript como YYYY-MM-DD para inputs date.
  // EN: Formats a JavaScript date as YYYY-MM-DD for date inputs.
  function formatDate(date) {
    return date.toISOString().slice(0, 10);
  }

  // ES: Formatea una fecha JavaScript como HH:MM para inputs time.
  // EN: Formats a JavaScript date as HH:MM for time inputs.
  function formatTime(date) {
    return date.toTimeString().slice(0, 5);
  }

  // ES: Calcula valores iniciales de filtros, incluyendo última hora y Max_Records.
  // EN: Computes initial filter values, including last hour and Max_Records.
  function defaultValueFor(key) {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    if (key === "Start_Date") return formatDate(oneHourAgo);
    if (key === "End_Date") return formatDate(now);
    if (key === "Start_Time") return formatTime(oneHourAgo);
    if (key === "End_Time") return formatTime(now);
    const selectOptions = state.forms.select || {};
    if (key === "Max_Records") return "100";
    if (key in selectOptions && Array.isArray(selectOptions[key]) && selectOptions[key].length) return selectOptions[key][0];
    return "";
  }

  // ES: Crea el input/select correcto para cada columna de filtros.
  // EN: Creates the right input/select control for each filter column.
  function controlFor(key) {
    const selectOptions = state.forms.select || {};
    let input;
    if (key in selectOptions && Array.isArray(selectOptions[key])) {
      input = document.createElement("select");
      selectOptions[key].forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value || "-";
        input.appendChild(option);
      });
    } else {
      input = document.createElement("input");
      if ((state.forms.date || {}).hasOwnProperty(key)) input.type = "date";
      else if ((state.forms.time || {}).hasOwnProperty(key)) input.type = "time";
      else if (["Source_Port", "Destination_Port"].includes(key)) input.type = "number";
      else input.type = "text";
    }
    input.className = "campo-resumen";
    input.name = key;
    input.value = defaultValueFor(key);
    return input;
  }

  // ES: Escapa un valor para CSV preservando comillas, comas y saltos de línea.
  // EN: Escapes a value for CSV while preserving quotes, commas, and newlines.
  function csvValue(value) {
    const text = String(value ?? "");
    const escaped = text.replace(/"/g, '""');
    return /[",\r\n]/.test(escaped) ? `"${escaped}"` : escaped;
  }

  // ES: Exporta a CSV los resultados cargados por la última búsqueda sin reconsultar FastAPI.
  // EN: Exports to CSV the results loaded by the last search without querying FastAPI again.
  function exportCsv() {
    if (!state.lastRows.length) return;
    const header = state.logColumns.map(csvValue).join(",");
    const rows = state.lastRows.map(row => state.logColumns.map(col => csvValue(row[col])).join(","));
    const meta = [
      ["Praesidium Firewall - Monitor logs export"],
      ["Exported_At", new Date().toISOString()],
      ["Filters_JSON", JSON.stringify(state.lastFilters)],
      [],
    ].map(line => line.map(csvValue).join(","));
    const blob = new Blob(["\ufeff", `${meta.join("\r\n")}\r\n${[header, ...rows].join("\r\n")}\r\n`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `praesidium-monitor-logs-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  // ES: Convierte payload.logs de FastAPI en filas pintables o preserva info/error.
  // EN: Converts FastAPI payload.logs into renderable rows or preserves info/error.
  function rowsFromLogs(logs) {
    if (!logs || typeof logs !== "object" || Array.isArray(logs)) return [];
    if (logs.error || logs.info) return logs;
    return Object.values(logs).filter(row => row && typeof row === "object");
  }

  // ES: Pinta la tabla readonly de resultados y activa filtros locales por columna.
  // EN: Renders the readonly results table and enables local per-column filters.
  function renderResults(container, logs) {
    const resultHost = container.querySelector("[data-monitor-logs-results]");
    if (!resultHost) return;
    resultHost.replaceChildren();

    if (logs && typeof logs === "object" && logs.error) {
      state.lastRows = [];
      resultHost.appendChild(statusNode(`${t("monitor_logs.search_error")}: ${logs.error}`, "error"));
      return;
    }
    if (logs && typeof logs === "object" && logs.info) {
      state.lastRows = [];
      resultHost.appendChild(statusNode(logs.info, "info"));
      return;
    }

    const rows = rowsFromLogs(logs);
    state.lastRows = Array.isArray(rows) ? rows : [];
    if (!state.lastRows.length) {
      resultHost.appendChild(statusNode(t("monitor_logs.empty"), "info"));
      return;
    }

    const table = el("table", { className: "interfaz" }, []);
    const thead = document.createElement("thead");
    thead.appendChild(tr(state.logColumns.map(col => th(label(col), { "data-status": col }))));
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    state.lastRows.forEach(row => {
      tbody.appendChild(tr(state.logColumns.map(col => td(row[col] ?? ""))));
    });
    table.appendChild(tbody);
    window.PraesidiumTableFilter.attach(table);
    resultHost.appendChild(el("div", { className: "pf-table-wrap" }, [table]));
  }

  // ES: Lee la fila de filtros iniciales y construye el payload para FastAPI.
  // EN: Reads the initial filters row and builds the payload for FastAPI.
  function currentFilters(form) {
    const filters = {};
    state.filterColumns.forEach(key => {
      const input = form.elements[key];
      filters[key] = input ? String(input.value || "").trim() : "";
    });
    return filters;
  }

  // ES: Ejecuta Search contra /monitor-logs/search y actualiza estado, tabla y exportación.
  // EN: Runs Search against /monitor-logs/search and updates status, table, and export.
  async function search(container, form, searchButton, exportButton, statusBox) {
    try {
      searchButton.disabled = true;
      exportButton.disabled = true;
      statusBox.replaceChildren(t("monitor_logs.searching"));
      statusBox.className = "pf-alert";
      const filters = currentFilters(form);
      state.lastFilters = { ...filters };
      const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "search", { payload: filters });
      renderResults(container, payload.logs);
      exportButton.disabled = state.lastRows.length === 0;
      statusBox.replaceChildren(t("monitor_logs.search_done", { count: String(state.lastRows.length) }));
    } catch (error) {
      state.lastRows = [];
      exportButton.disabled = true;
      statusBox.className = "pf-alert error";
      statusBox.replaceChildren(error && error.message ? error.message : String(error));
      renderResults(container, {});
    } finally {
      searchButton.disabled = false;
    }
  }

  // ES: Construye la tabla especial de filtros iniciales y el contenedor de resultados.
  // EN: Builds the special initial filters table and the results container.
  function renderFilterTable(container) {
    const form = document.createElement("form");
    form.addEventListener("submit", event => event.preventDefault());

    const table = el("table", { className: "interfaz" }, []);
    const thead = document.createElement("thead");
    const headerCells = [th(t("monitor_logs.search")), th(t("monitor_logs.export_csv")), ...state.filterColumns.map(col => th(label(col)))];
    thead.appendChild(tr(headerCells));
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    const row = document.createElement("tr");
    const searchButton = el("button", { className: "button_save", type: "button" }, [t("monitor_logs.search")]);
    const exportButton = el("button", { className: "modal-button", type: "button" }, [t("monitor_logs.export_csv")]);
    exportButton.disabled = true;
    row.appendChild(td(searchButton));
    row.appendChild(td(exportButton));
    state.filterColumns.forEach(key => {
      const cell = document.createElement("td");
      cell.appendChild(controlFor(key));
      row.appendChild(cell);
    });
    tbody.appendChild(row);
    table.appendChild(tbody);
    form.appendChild(table);

    const statusBox = statusNode(t("monitor_logs.ready"));
    const filterCard = el("div", { className: "pf-card" }, [
      el("h3", {}, [t("monitor_logs.filters_title")]),
      el("div", { className: "pf-table-wrap" }, [form]),
      statusBox,
    ]);
    const resultsHost = document.createElement("div");
    resultsHost.className = "monitor-results";
    resultsHost.dataset.monitorLogsResults = "true";
    resultsHost.appendChild(statusNode(t("monitor_logs.no_search")));
    const resultsCard = el("div", { className: "pf-card" }, [
      el("h3", {}, [t("monitor_logs.results_title")]),
      resultsHost,
    ]);

    searchButton.addEventListener("click", () => search(container, form, searchButton, exportButton, statusBox));
    exportButton.addEventListener("click", exportCsv);
    replaceChildren(container, [titleNode(), filterCard, resultsCard]);
  }

  // ES: Punto de entrada del registry: carga metadata y renderiza la página monitor_logs.
  // EN: Registry entry point: loads metadata and renders the monitor_logs page.
  async function render(container) {
    try {
      replaceChildren(container, [titleNode(), statusNode(t("common.loading"))]);
      await loadMetadata();
      renderFilterTable(container);
    } catch (error) {
      replaceChildren(container, [titleNode(), statusNode(error && error.message ? error.message : String(error), "error")]);
    }
  }

  window.PraesidiumMonitorLogsPage = { render };
})();
