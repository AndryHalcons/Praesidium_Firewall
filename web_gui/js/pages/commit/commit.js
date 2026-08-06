/*
 * ES: Página WebGUI del módulo Commit: sólo botón de aplicar commit y resultado.
 * EN: WebGUI page for the Commit module: only apply-commit button and result.
 */
(() => {
  "use strict";

  const { el } = window.PraesidiumDom;
  const { t } = window.PraesidiumI18n;
  const SECTION = "commit";
  const BASE = "/js/pages/commit";

  const state = {
    commands: null,
  };

  // ES: Carga un JSON local sin caché para reflejar cambios de desarrollo.
  // EN: Loads a local JSON file without cache so development changes are reflected.
  async function fetchJson(path) {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  // ES: Carga y cachea los comandos API declarados para Commit.
  // EN: Loads and caches declared API commands for Commit.
  async function loadMetadata() {
    if (state.commands) return state;
    state.commands = await fetchJson(`${BASE}/commit_commands_api.json`);
    return state;
  }

  // ES: Construye un aviso visual estándar para estados de listo/carga/error.
  // EN: Builds a standard visual alert for ready/loading/error states.
  function statusNode(message, type = "info") {
    return el("div", { className: `pf-alert ${type}` }, [message]);
  }

  // ES: Devuelve el título normal del módulo usando clases modernas globales.
  // EN: Returns the normal module title using modern global classes.
  function titleNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("commit.title")]),
        el("p", { className: "pf-muted" }, [t("commit.description")]),
      ]),
    ]);
  }

  // ES: Convierte cualquier valor de respuesta en JSON legible para mostrarlo sin HTML crudo.
  // EN: Converts any response value to readable JSON for display without raw HTML.
  function pretty(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (_error) {
      return String(value ?? "");
    }
  }

  // ES: Extrae un mensaje de error estable desde errores FastAPI/API client.
  // EN: Extracts a stable error message from FastAPI/API-client errors.
  function errorMessage(error) {
    if (!error) return t("commit.apply_error");
    if (error.detail && typeof error.detail === "object") {
      return error.detail.error_code || error.detail.detail || pretty(error.detail);
    }
    return error.message || String(error);
  }

  // ES: Crea una línea de resumen con etiqueta y valor para el preview de commit.
  // EN: Creates a summary item with label and value for the commit preview.
  function summaryItem(labelKey, value) {
    return el("div", { className: "pf-card" }, [
      el("strong", {}, [t(labelKey)]),
      el("p", { className: "pf-muted" }, [String(value ?? 0)]),
    ]);
  }

  // ES: Pinta un objeto JSON redactado en un bloque pre seguro.
  // EN: Renders a redacted JSON object in a safe pre block.
  function jsonBlock(value) {
    return el("pre", { className: "pf-pre" }, [pretty(value)]);
  }

  // ES: Pinta una tarjeta individual de cambio del preview candidate/running.
  // EN: Renders one individual candidate/running preview change card.
  function renderChange(change) {
    const type = String((change && change.type) || "");
    const title = `${t(`commit.change_${type}`)} · ${change.file || ""} · ${change.path || ""} · ${change.label || ""}`;
    const children = [el("h4", {}, [title])];
    if (type === "modified") {
      children.push(el("div", { className: "pf-grid" }, [
        el("div", { className: "pf-card" }, [el("h4", {}, [t("commit.running")]), jsonBlock(change.running_object || {})]),
        el("div", { className: "pf-card" }, [el("h4", {}, [t("commit.candidate")]), jsonBlock(change.candidate_object || {})]),
      ]));
    } else {
      children.push(jsonBlock(change.object || {}));
    }
    return el("section", { className: `pf-card preview-${type}` }, children);
  }

  // ES: Pinta el preview de Compare Commit devuelto por FastAPI en la misma página.
  // EN: Renders the Compare Commit preview returned by FastAPI on the same page.
  function renderPreview(resultHost, payload) {
    resultHost.replaceChildren();
    const summary = (payload && payload.summary) || {};
    const changes = Array.isArray(payload && payload.changes) ? payload.changes : [];
    const summaryGrid = el("div", { className: "pf-grid" }, [
      summaryItem("commit.added", summary.added),
      summaryItem("commit.modified", summary.modified),
      summaryItem("commit.deleted", summary.deleted),
      summaryItem("commit.unchanged", summary.unchanged),
      summaryItem("commit.files", summary.files),
    ]);
    const children = [statusNode(t("commit.compare_success"), "success"), summaryGrid];
    if (!changes.length) {
      children.push(statusNode(t("commit.no_changes"), "info"));
    } else {
      changes.forEach(change => children.push(renderChange(change)));
    }
    resultHost.appendChild(el("div", { className: "pf-stack" }, children));
  }

  // ES: Crea un nodo seguro dentro del documento de la ventana emergente de comparación.
  // EN: Creates a safe node inside the comparison popup document.
  function popupEl(doc, tagName, className, text = "") {
    const node = doc.createElement(tagName);
    if (className) node.className = className;
    if (text !== "") node.textContent = String(text);
    return node;
  }

  // ES: Añade un bloque JSON seguro al documento de comparación.
  // EN: Appends a safe JSON block to the comparison document.
  function appendPopupJson(doc, parent, value) {
    const pre = popupEl(doc, "pre", "preview-json", pretty(value));
    parent.appendChild(pre);
  }

  // ES: Añade JSON línea a línea y marca en amarillo los campos modificados.
  // EN: Appends JSON line by line and highlights modified fields in yellow.
  function appendPopupJsonLines(doc, parent, value, changedFields) {
    const fields = new Set(Array.isArray(changedFields) ? changedFields : []);
    const lines = pretty(value).split("\n");
    const pre = popupEl(doc, "pre", "preview-json-lines");
    lines.forEach(line => {
      const row = popupEl(doc, "div", "", line);
      const match = line.match(/^\s*"([^"]+)":/);
      if (match && fields.has(match[1])) {
        row.className = "preview-line-modified";
      }
      pre.appendChild(row);
    });
    parent.appendChild(pre);
  }

  // ES: Pinta el preview en una ventana nueva, siguiendo el comportamiento legacy sin HTML dinámico.
  // EN: Renders the preview in a new window, following legacy behavior without dynamic HTML.
  function renderPreviewWindow(win, payload) {
    const doc = win.document;
    const root = doc.getElementById("preview-root");
    root.replaceChildren();
    const summary = (payload && payload.summary) || {};
    const changes = Array.isArray(payload && payload.changes) ? payload.changes : [];

    const summaryBox = popupEl(doc, "div", "preview-summary");
    summaryBox.textContent = `${t("commit.added")}: ${summary.added || 0} | ${t("commit.modified")}: ${summary.modified || 0} | ${t("commit.deleted")}: ${summary.deleted || 0} | ${t("commit.unchanged")}: ${summary.unchanged || 0} | ${t("commit.files")}: ${summary.files || 0}`;
    root.appendChild(summaryBox);

    if (!changes.length) {
      root.appendChild(popupEl(doc, "p", "preview-empty", t("commit.no_changes")));
      return;
    }

    changes.forEach(change => {
      const type = String((change && change.type) || "");
      const card = popupEl(doc, "section", `preview-card preview-${type}`);
      const title = popupEl(doc, "h3", "", `${t(`commit.change_${type}`)} · ${change.file || ""} · ${change.path || ""} · ${change.label || ""}`);
      card.appendChild(title);
      if (type === "modified") {
        const grid = popupEl(doc, "div", "preview-side-by-side");
        const running = popupEl(doc, "div", "preview-side preview-running");
        running.appendChild(popupEl(doc, "h4", "", t("commit.running")));
        appendPopupJsonLines(doc, running, change.running_object || {}, change.changed_fields);
        const candidate = popupEl(doc, "div", "preview-side preview-candidate");
        candidate.appendChild(popupEl(doc, "h4", "", t("commit.candidate")));
        appendPopupJsonLines(doc, candidate, change.candidate_object || {}, change.changed_fields);
        grid.appendChild(running);
        grid.appendChild(candidate);
        card.appendChild(grid);
      } else {
        appendPopupJson(doc, card, change.object || {});
      }
      root.appendChild(card);
    });
  }

  // ES: Abre una ventana nueva de comparación con CSS local como hacía el legacy.
  // EN: Opens a new comparison window with local CSS like the legacy page did.
  function openPreviewWindow() {
    const win = window.open("", "PraesidiumCommitCompare", "width=1200,height=850");
    if (!win) throw new Error(t("commit.popup_blocked"));
    win.document.write(`<!DOCTYPE html>
<html>
<head>
  <title>${t("commit.compare")}</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #111827; color: #e5e7eb; margin: 10px; font-size: 13px; }
    h2 { margin: 0 0 8px 0; font-size: 18px; }
    .preview-summary { padding: 7px 9px; margin-bottom: 8px; background: #1f2937; border-radius: 6px; }
    .preview-card { border-radius: 6px; padding: 7px; margin: 7px 0; border: 1px solid #374151; }
    .preview-card h3 { margin: 0 0 6px 0; font-size: 13px; }
    .preview-added { background: rgba(22, 101, 52, 0.25); border-color: #22c55e; }
    .preview-modified { background: rgba(133, 77, 14, 0.25); border-color: #eab308; }
    .preview-deleted { background: rgba(127, 29, 29, 0.28); border-color: #ef4444; }
    .preview-side-by-side { display: grid; grid-template-columns: 1fr 1fr; gap: 7px; }
    .preview-side { border: 1px solid #374151; border-radius: 5px; background: rgba(15, 23, 42, 0.55); overflow: auto; }
    .preview-side h4 { margin: 0; padding: 4px 6px; background: #1f2937; border-bottom: 1px solid #374151; font-size: 12px; }
    .preview-empty { padding: 7px 9px; background: #1f2937; border-radius: 6px; }
    .preview-json-lines { padding: 5px 6px; }
    .preview-json-lines div { line-height: 1.15; margin: 0; padding-top: 0; padding-bottom: 0; }
    .preview-line-modified { background: rgba(234, 179, 8, 0.35); color: #fef3c7; border-left: 2px solid #eab308; padding-left: 3px; }
    pre { white-space: pre-wrap; word-break: break-word; margin: 0; padding: 5px 6px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; line-height: 1.15; }
  </style>
</head>
<body><h2>${t("commit.preview_title")}</h2><div id="preview-root">${t("commit.comparing")}</div></body>
</html>`);
    win.document.close();
    return win;
  }

  // ES: Pinta el resultado técnico del apply devuelto por FastAPI.
  // EN: Renders the technical apply result returned by FastAPI.
  function renderResult(resultHost, payload) {
    resultHost.replaceChildren();
    const commitResult = payload && payload.commit_result ? payload.commit_result : {};
    const status = String(commitResult.status || "");
    const message = payload && payload.message ? String(payload.message) : "";
    const type = status === "ok" ? "success" : "error";
    const title = status === "ok" ? t("commit.apply_success") : t("commit.apply_error");
    const children = [statusNode(message || title, type)];

    if (commitResult.date) {
      children.push(el("p", { className: "pf-muted" }, [`${t("commit.date")}: ${commitResult.date}`]));
    }
    if (commitResult.user) {
      children.push(el("p", { className: "pf-muted" }, [`${t("commit.user")}: ${commitResult.user}`]));
    }
    children.push(el("pre", { className: "pf-pre" }, [pretty(payload)]));
    resultHost.appendChild(el("div", { className: "pf-stack" }, children));
  }

  // ES: Ejecuta POST /commit/apply y bloquea el botón mientras el apply está en curso.
  // EN: Executes POST /commit/apply and disables the button while apply is running.
  async function applyCommit(button, statusBox, resultHost) {
    button.disabled = true;
    statusBox.className = "pf-alert";
    statusBox.replaceChildren(t("commit.applying"));
    resultHost.replaceChildren(statusNode(t("commit.applying"), "info"));
    try {
      const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "apply");
      renderResult(resultHost, payload);
      const ok = payload && payload.commit_result && payload.commit_result.status === "ok";
      statusBox.className = ok ? "pf-alert success" : "pf-alert error";
      statusBox.replaceChildren(ok ? t("commit.apply_success") : t("commit.apply_error"));
    } catch (error) {
      const message = errorMessage(error);
      statusBox.className = "pf-alert error";
      statusBox.replaceChildren(message);
      resultHost.replaceChildren(statusNode(message, "error"));
    } finally {
      button.disabled = false;
    }
  }

  // ES: Ejecuta GET /commit/preview y pinta la comparación candidate/running en ventana nueva.
  // EN: Executes GET /commit/preview and renders the candidate/running comparison in a new window.
  async function compareCommit(button, statusBox, resultHost) {
    button.disabled = true;
    statusBox.className = "pf-alert";
    statusBox.replaceChildren(t("commit.comparing"));
    let previewWindow = null;
    try {
      previewWindow = openPreviewWindow();
      const payload = await window.PraesidiumApiCommands.execute(state.commands, SECTION, "preview");
      renderPreviewWindow(previewWindow, payload);
      statusBox.className = "pf-alert success";
      statusBox.replaceChildren(t("commit.compare_success"));
      resultHost.replaceChildren(statusNode(t("commit.compare_success"), "success"));
    } catch (error) {
      const message = errorMessage(error);
      statusBox.className = "pf-alert error";
      statusBox.replaceChildren(message);
      resultHost.replaceChildren(statusNode(message, "error"));
      if (previewWindow && !previewWindow.closed) {
        const root = previewWindow.document.getElementById("preview-root");
        if (root) root.textContent = message;
      }
    } finally {
      button.disabled = false;
    }
  }

  // ES: Construye la pantalla moderna del módulo Commit con botones Apply y Compare.
  // EN: Builds the modern Commit module screen with Apply and Compare buttons.
  function renderCommitPage() {
    const applyButton = el("button", { className: "button_save", type: "button" }, [t("commit.apply")]);
    const compareButton = el("button", { className: "modal-button", type: "button" }, [t("commit.compare")]);
    const statusBox = statusNode(t("commit.ready"), "info");
    const resultHost = el("div", { className: "pf-stack" }, [statusNode(t("commit.no_result"), "info")]);
    applyButton.addEventListener("click", () => applyCommit(applyButton, statusBox, resultHost));
    compareButton.addEventListener("click", () => compareCommit(compareButton, statusBox, resultHost));

    return el("div", { className: "pf-stack" }, [
      titleNode(),
      el("section", { className: "pf-card" }, [
        el("h3", {}, [t("commit.apply_title")]),
        el("p", { className: "pf-muted" }, [t("commit.apply_help")]),
        el("div", { className: "pf-row-actions" }, [applyButton, compareButton]),
        statusBox,
      ]),
      el("section", { className: "pf-card" }, [
        el("h3", {}, [t("commit.result_title")]),
        resultHost,
      ]),
    ]);
  }

  // ES: Punto de entrada público usado por registry.js para pintar la página.
  // EN: Public entrypoint used by registry.js to render the page.
  async function render(container) {
    container.replaceChildren(statusNode(t("common.loading"), "info"));
    try {
      await loadMetadata();
      container.replaceChildren(renderCommitPage());
    } catch (error) {
      container.replaceChildren(statusNode(error && error.message ? error.message : String(error), "error"));
    }
  }

  window.PraesidiumCommitPage = { render };
})();
