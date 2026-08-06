/*
 * ES: Página especial Monitor Session: opciones conntrack + resultados readonly.
 * EN: Special Monitor Session page: conntrack options + readonly results.
 */
(() => {
  "use strict";

  const { el, td, th, tr } = window.PraesidiumDom;
  const { t } = window.PraesidiumI18n;
  const SECTION = "monitor_session";
  const BASE = "/js/pages/monitor_session";

  const state = {
    commands: null,
    forms: {},
    optionColumns: [],
    rowColumns: [],
    lastRows: [],
    lastCommand: {},
    lastOutput: "",
  };

  // ES: Carga un JSON local sin caché para reflejar cambios de desarrollo.
  // EN: Loads a local JSON file without cache so development changes are reflected.
  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  // ES: Carga y cachea metadata, columnas y comandos API del módulo monitor_session.
  // EN: Loads and caches metadata, columns, and API commands for the monitor_session module.
  async function loadMetadata() {
    if (state.commands) return state;
    const [forms, optionsStructure, rowsStructure, commands] = await Promise.all([
      fetchJson(`${BASE}/forms_monitor_session.json`),
      fetchJson(`${BASE}/structure_table_monitor_session_options.json`),
      fetchJson(`${BASE}/structure_table_monitor_session_rows.json`),
      fetchJson(`${BASE}/monitor_session_commands_api.json`),
    ]);
    state.forms = forms || {};
    state.optionColumns = Array.isArray(optionsStructure.Search_Filter) ? optionsStructure.Search_Filter : [];
    state.rowColumns = Array.isArray(rowsStructure.Search_Filter) ? rowsStructure.Search_Filter : [];
    state.commands = commands || {};
    return state;
  }

  // ES: Traduce una clave de monitor_session y cae al nombre técnico si falta i18n.
  // EN: Translates a monitor_session key and falls back to the technical name when i18n is missing.
  function label(key) {
    const translated = t(`monitor_session.${key}`);
    return translated !== `monitor_session.${key}` ? translated : key;
  }

  // ES: Construye un aviso visual estándar para estados de carga, vacío o error.
  // EN: Builds a standard visual alert for loading, empty, or error states.
  function statusNode(message, type = "info") {
    return el("div", { className: `pf-alert ${type}` }, [message]);
  }

  // ES: Devuelve el título normal del módulo sin usar cajas legacy locales.
  // EN: Returns the normal module title without using local legacy boxes.
  function titleNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("monitor_session.title")]),
        el("p", { className: "pf-muted" }, [t("monitor_session.description")]),
      ]),
    ]);
  }

  // ES: Crea el control correcto para cada opción de ejecución conntrack.
  // EN: Creates the right control for each conntrack execution option.
  function controlFor(key) {
    const selectOptions = state.forms.select || {};
    let input;
    if (key in selectOptions && Array.isArray(selectOptions[key])) {
      input = document.createElement("select");
      selectOptions[key].forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = `${value} — ${label(`action_${value.replace("-", "")}`)}`;
        input.appendChild(option);
      });
    } else {
      input = document.createElement("input");
      input.type = "text";
      input.placeholder = t("monitor_session.arguments_placeholder");
    }
    input.className = "campo-resumen";
    input.name = key;
    if (key === "Action") input.value = "-L";
    if (key === "Arguments") {
      input.style.minWidth = "32rem";
      input.style.width = "100%";
    }
    return input;
  }

  // ES: Lee la tabla de opciones y construye el payload para FastAPI sin enviar usuario.
  // EN: Reads the options table and builds the FastAPI payload without sending a user.
  function currentCommand(form) {
    const action = form.elements.Action ? String(form.elements.Action.value || "").trim() : "-L";
    const argumentsValue = form.elements.Arguments ? String(form.elements.Arguments.value || "").trim() : "";
    return { action, arguments: argumentsValue };
  }

  // ES: Escapa un valor para CSV preservando comillas, comas y saltos de línea.
  // EN: Escapes a CSV value while preserving quotes, commas, and newlines.
  function csvValue(value) {
    const text = String(value ?? "");
    const escaped = text.replace(/"/g, '""');
    return /[",\r\n]/.test(escaped) ? `"${escaped}"` : escaped;
  }

  // ES: Exporta los resultados cargados por la última consulta sin reconsultar FastAPI.
  // EN: Exports the results loaded by the last query without calling FastAPI again.
  function exportCsv() {
    if (!state.lastRows.length) return;
    const header = state.rowColumns.map(col => csvValue(label(col))).join(",");
    const rows = state.lastRows.map(row => state.rowColumns.map(col => csvValue(row[col])).join(","));
    const meta = [
      ["Praesidium Firewall - Monitor session export"],
      ["Exported_At", new Date().toISOString()],
      ["Command_JSON", JSON.stringify(state.lastCommand)],
      ["Output", state.lastOutput],
      [],
    ].map(line => line.map(csvValue).join(","));
    const blob = new Blob(["\ufeff", `${meta.join("\r\n")}\r\n${[header, ...rows].join("\r\n")}\r\n`], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `praesidium-monitor-session-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  // ES: Pinta stdout/stderr devuelto por FastAPI para que acciones no tabulares sean visibles.
  // EN: Renders stdout/stderr returned by FastAPI so non-table actions remain visible.
  function renderOutput(container, payload) {
    const outputHost = container.querySelector("[data-monitor-session-output]");
    if (!outputHost) return;
    outputHost.replaceChildren();
    const output = String((payload && payload.output) || "").trim();
    state.lastOutput = output;
    if (!output) {
      outputHost.appendChild(statusNode(t("monitor_session.no_output"), "info"));
      return;
    }
    outputHost.appendChild(el("pre", { className: "pf-pre" }, [output]));
  }

  // ES: Pinta la tabla readonly de sesiones y activa filtros locales por columna.
  // EN: Renders the readonly sessions table and enables local per-column filters.
  function renderResults(container, rows) {
    const resultHost = container.querySelector("[data-monitor-session-results]");
    if (!resultHost) return;
    resultHost.replaceChildren();
    state.lastRows = Array.isArray(rows) ? rows : [];
    if (!state.lastRows.length) {
      resultHost.appendChild(statusNode(t("monitor_session.empty"), "info"));
      return;
    }

    const table = el("table", { className: "interfaz" }, []);
    const thead = document.createElement("thead");
    thead.appendChild(tr(state.rowColumns.map(col => th(label(col), { "data-status": col }))));
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    state.lastRows.forEach(row => {
      tbody.appendChild(tr(state.rowColumns.map(col => td(row[col] ?? ""))));
    });
    table.appendChild(tbody);
    window.PraesidiumTableFilter.attach(table);
    resultHost.appendChild(el("div", { className: "pf-table-wrap" }, [table]));
  }

  // ES: Extrae un mensaje de error estable desde errores FastAPI/API client.
  // EN: Extracts a stable error message from FastAPI/API-client errors.
  function errorMessage(error) {
    if (!error) return t("monitor_session.run_error");
    if (error.detail && typeof error.detail === "object") {
      const code = error.detail.error_code || error.detail.detail || JSON.stringify(error.detail);
      const output = error.detail.output ? `\n${error.detail.output}` : "";
      return `${code}${output}`;
    }
    return error.message || String(error);
  }

  // ES: Ejecuta la acción conntrack seleccionada y actualiza output, tabla y exportación.
  // EN: Runs the selected conntrack action and updates output, table, and export.
  async function runCommand(container, form, runButton, exportButton, statusBox) {
    try {
      runButton.disabled = true;
      exportButton.disabled = true;
      statusBox.className = "pf-alert";
      statusBox.replaceChildren(t("monitor_session.running"));
      const command = currentCommand(form);
      state.lastCommand = { ...command };
      const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "run", { payload: command });
      renderOutput(container, payload);
      renderResults(container, payload.rows || []);
      exportButton.disabled = state.lastRows.length === 0;
      statusBox.replaceChildren(t("monitor_session.run_done", { count: String(state.lastRows.length) }));
    } catch (error) {
      state.lastRows = [];
      exportButton.disabled = true;
      renderOutput(container, { output: errorMessage(error) });
      renderResults(container, []);
      statusBox.className = "pf-alert error";
      statusBox.replaceChildren(t("monitor_session.run_error"));
    } finally {
      runButton.disabled = false;
    }
  }

  // ES: Construye la tabla especial de opciones iniciales y contenedores de salida/resultados.
  // EN: Builds the special initial options table and output/results containers.
  function renderOptionsTable(container) {
    const form = document.createElement("form");
    form.addEventListener("submit", event => event.preventDefault());

    const table = el("table", { className: "interfaz" }, []);
    const thead = document.createElement("thead");
    thead.appendChild(tr([
      th(t("monitor_session.run")),
      th(t("monitor_session.export_csv")),
      ...state.optionColumns.map(col => th(label(col))),
    ]));
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    const row = document.createElement("tr");
    const runButton = el("button", { className: "button_save", type: "button" }, [t("monitor_session.run")]);
    const exportButton = el("button", { className: "modal-button", type: "button" }, [t("monitor_session.export_csv")]);
    exportButton.disabled = true;
    row.appendChild(td(runButton));
    row.appendChild(td(exportButton));
    state.optionColumns.forEach(key => {
      const cell = document.createElement("td");
      cell.appendChild(controlFor(key));
      row.appendChild(cell);
    });
    tbody.appendChild(row);
    table.appendChild(tbody);
    form.appendChild(el("div", { className: "pf-table-wrap" }, [table]));

    const statusBox = statusNode(t("monitor_session.ready"), "info");
    runButton.addEventListener("click", () => runCommand(container, form, runButton, exportButton, statusBox));
    exportButton.addEventListener("click", exportCsv);

    const outputHost = el("div", {}, [statusNode(t("monitor_session.no_output"), "info")]);
    outputHost.setAttribute("data-monitor-session-output", "");
    const resultHost = el("div", {}, [statusNode(t("monitor_session.no_run"), "info")]);
    resultHost.setAttribute("data-monitor-session-results", "");

    return el("div", { className: "pf-stack" }, [
      titleNode(),
      el("section", { className: "pf-card" }, [
        el("h3", {}, [t("monitor_session.options_title")]),
        form,
        statusBox,
      ]),
      el("section", { className: "pf-card" }, [
        el("h3", {}, [t("monitor_session.output_title")]),
        outputHost,
      ]),
      el("section", { className: "pf-card" }, [
        el("h3", {}, [t("monitor_session.results_title")]),
        resultHost,
      ]),
    ]);
  }

  // ES: Punto de entrada público usado por registry.js para pintar la página.
  // EN: Public entrypoint used by registry.js to render the page.
  async function render(container) {
    container.replaceChildren(statusNode(t("common.loading") || "Loading...", "info"));
    try {
      await loadMetadata();
      container.replaceChildren(renderOptionsTable(container));
    } catch (error) {
      container.replaceChildren(statusNode(error && error.message ? error.message : String(error), "error"));
    }
  }

  window.PraesidiumMonitorSessionPage = { render };
})();
