/*
 * ES: Página WebGUI de System Logging con una fila por mini sección.
 * EN: System Logging WebGUI page with one row per mini-section.
 */
(() => {
  "use strict";

  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;
  const { t } = window.PraesidiumUi;
  const BASE_PATH = "/js/pages/system_logging";
  const SECTION_ORDER = ["journald", "system_logs", "nftables_logs"];
  let metadataPromise = null;

  // ES: Carga únicamente metadata JSON same-origin del propio módulo.
  // EN: Loads only same-origin JSON metadata owned by this module.
  async function fetchMetadata(path) {
    const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  // ES: Cachea la metadata estática del módulo durante la sesión de la página.
  // EN: Caches the module static metadata during the page session.
  function loadMetadata() {
    if (!metadataPromise) {
      metadataPromise = Promise.all([
        fetchMetadata(`${BASE_PATH}/forms_system_logging.json`),
        fetchMetadata(`${BASE_PATH}/structure_table_system_logging.json`),
        fetchMetadata(`${BASE_PATH}/system_logging_commands_api.json`),
      ]).then(([forms, structure, commands]) => ({ forms, structure, commands }));
    }
    return metadataPromise;
  }

  // ES: Crea la cabecera común de la página sin HTML dinámico.
  // EN: Builds the common page header without dynamic HTML.
  function pageHeaderNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("system_logging.title")]),
        el("p", { className: "pf-muted" }, [t("system_logging.description")]),
      ]),
      el("div"),
    ]);
  }

  // ES: Devuelve texto localizado para valores presentes o el guion común.
  // EN: Returns localized text for present values or the common dash.
  function valueText(value) {
    return value === null || value === undefined || value === "" ? t("common.empty_dash") : String(value);
  }

  // ES: Resume los límites propios de cada sección para la tabla única.
  // EN: Summarizes section-specific limits for the single table.
  function limitText(section, config) {
    if (section === "journald") {
      return [
        `${t("system_logging.summary.system")}: ${valueText(config.system_max_use)}`,
        `${t("system_logging.summary.free")}: ${valueText(config.system_keep_free)}`,
        `${t("system_logging.summary.runtime")}: ${valueText(config.runtime_max_use)}`,
      ].join(" · ");
    }
    if (section === "system_logs") return valueText(config.maxsize);
    return valueText(config.size);
  }

  // ES: Convierte las tres mini secciones FastAPI en tres filas manteniendo uuid oculto.
  // EN: Converts the three FastAPI mini-sections into three rows while keeping uuid hidden.
  function rowsFromPayload(payload) {
    const config = payload && payload.config;
    if (!config || typeof config !== "object") throw new Error("system_logging_invalid_response");
    return SECTION_ORDER.map(section => {
      const values = config[section];
      if (!values || typeof values !== "object" || typeof values.uuid !== "string" || !values.uuid) {
        throw new Error(`system_logging_invalid_section:${section}`);
      }
      return {
        section,
        uuid: values.uuid,
        values,
        display: {
          section: t(`system_logging.sections.${section}`),
          enabled: section === "journald" ? null : values.enabled,
          limit: limitText(section, values),
          rotation_retention: section === "journald" ? values.max_retention_sec : (section === "system_logs" ? values.rotation : null),
          rotate: section === "journald" ? null : values.rotate,
          compress: values.compress,
          delaycompress: section === "journald" ? null : values.delaycompress,
        },
      };
    });
  }

  // ES: Renderiza booleanos como checkboxes deshabilitados y el resto como texto seguro.
  // EN: Renders booleans as disabled checkboxes and all other values as safe text.
  function displayCell(value) {
    if (typeof value === "boolean") {
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.disabled = true;
      checkbox.checked = value;
      return td(checkbox);
    }
    const text = valueText(value);
    if (text === t("common.empty_dash")) return td(text);
    return td(el("span", { className: "table-readonly-chip" }, [text]));
  }

  // ES: Convierte metadata forms en un campo para el modal de la fila seleccionada.
  // EN: Converts forms metadata into a field for the selected row modal.
  function modalField(forms, section, key, value) {
    const sectionForms = forms[section] || {};
    const checkbox = sectionForms.checkbox && sectionForms.checkbox[key];
    const select = sectionForms.select && sectionForms.select[key];
    if (checkbox) {
      return {
        key,
        label: t(`system_logging.fields.${key}`),
        type: "checkbox",
        value,
        checkedValue: checkbox.checked,
        uncheckedValue: checkbox.unchecked,
      };
    }
    if (Array.isArray(select)) {
      return { key, label: t(`system_logging.fields.${key}`), type: "select", value, options: select };
    }
    return { key, label: t(`system_logging.fields.${key}`), type: "text", value };
  }

  // ES: Normaliza sólo los enteros estrictos exigidos por FastAPI.
  // EN: Normalizes only the strict integers required by FastAPI.
  function normalizePayload(section, payload) {
    const normalized = { ...payload };
    if ((section === "system_logs" || section === "nftables_logs") && Object.prototype.hasOwnProperty.call(normalized, "rotate")) {
      const rotate = Number(normalized.rotate);
      if (!Number.isInteger(rotate)) throw new Error("system_logging_invalid_rotate");
      normalized.rotate = rotate;
    }
    return normalized;
  }

  // ES: Abre el modal de una mini sección; uuid queda sólo en context y nunca en payload.
  // EN: Opens a mini-section modal; uuid stays only in context and never in the payload.
  function openEditModal(row, metadata, refresh) {
    const keys = metadata.structure[row.section] || [];
    const fields = keys.map(key => modalField(metadata.forms, row.section, key, row.values[key]));
    window.PraesidiumModal.openFormModal({
      title: t("system_logging.edit_title", { section: row.display.section }),
      fields,
      context: { section: row.section, uuid: row.uuid },
      onSave: async payload => {
        await window.PraesidiumApiCommands.execute(metadata.commands, row.section, "update", {
          payload: normalizePayload(row.section, payload),
        });
        await refresh();
      },
    });
  }

  // ES: Construye una tabla independiente con los campos reales de una mini sección.
  // EN: Builds an independent table with the real fields of one mini-section.
  function sectionTableNode(row, metadata, refresh) {
    const columns = metadata.structure[row.section] || [];
    const head = tr([th(t("common.action")), ...columns.map(column => th(t(`system_logging.fields.${column}`)))]);
    const edit = el("button", { className: "button_edit", type: "button" }, [t("common.edit")]);
    edit.addEventListener("click", () => openEditModal(row, metadata, refresh));
    const body = tr([
      td(edit),
      ...columns.map(column => displayCell(row.values[column])),
    ]);
    const table = el("table", { className: "pf-table" }, [
      el("thead", {}, [head]),
      el("tbody", {}, [body]),
    ]);
    return el("div", { className: "pf-card" }, [
      el("h3", {}, [row.display.section]),
      el("div", { className: "pf-table-wrap" }, [table]),
    ]);
  }

  // ES: Mantiene las tres tablas separadas y en el orden estable del backend.
  // EN: Keeps the three tables separate and in the backend stable order.
  function tablesNode(rows, metadata, refresh) {
    return el("div", {}, rows.map(row => sectionTableNode(row, metadata, refresh)));
  }

  // ES: Renderiza la página leyendo una sola vez la configuración completa.
  // EN: Renders the page by reading the complete configuration once.
  async function render(container) {
    replaceChildren(container, [pageHeaderNode(), el("div", { className: "pf-alert" }, [t("system_logging.loading")])]);
    try {
      const metadata = await loadMetadata();
      const payload = await window.PraesidiumApiCommands.execute(metadata.commands, "system_logging", "list");
      const rows = rowsFromPayload(payload);
      replaceChildren(container, [pageHeaderNode(), tablesNode(rows, metadata, () => render(container))]);
    } catch (error) {
      replaceChildren(container, [
        pageHeaderNode(),
        el("div", { className: "pf-alert error" }, [error && error.message ? error.message : String(error)]),
      ]);
    }
  }

  // ES: API pública del módulo para cuando el registro de páginas sea autorizado.
  // EN: Public module API for when page registration is authorized.
  window.PraesidiumSystemLoggingPage = { render };
})();
