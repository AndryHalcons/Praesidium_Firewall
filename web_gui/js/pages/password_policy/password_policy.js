/*
 * ES: Página WebGUI de la sección password_policy.
 * EN: WebGUI page for the password_policy section.
 */
(() => {
  "use strict";

  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;
  const { t } = window.PraesidiumUi;
  const BASE_PATH = "/js/pages/password_policy";
  let metadataPromise = null;

  // ES: Carga metadata local del módulo, igual que las páginas metadata-driven.
  // EN: Loads module-local metadata, like metadata-driven pages.
  async function fetchMetadata(path) {
    const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }

  // ES: Cachea forms/structure/commands del módulo.
  // EN: Caches module forms/structure/commands.
  function loadMetadata() {
    if (!metadataPromise) {
      metadataPromise = Promise.all([
        fetchMetadata(`${BASE_PATH}/forms_password_policy.json`),
        fetchMetadata(`${BASE_PATH}/structure_tables_password_policy.json`),
        fetchMetadata(`${BASE_PATH}/password_policy_commands_api.json`),
      ]).then(([forms, structure, commands]) => ({ forms, structure, commands }));
    }
    return metadataPromise;
  }

  // ES: Cabecera segura de la página.
  // EN: Safe page header.
  function pageHeaderNode() {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [
        el("h2", {}, [t("password_policy.title")]),
        el("p", { className: "pf-muted" }, [t("password_policy.description")]),
      ]),
      el("div"),
    ]);
  }

  // ES: Renderiza strings true/false como checkbox deshabilitado.
  // EN: Renders true/false strings as disabled checkboxes.
  function cellNode(value, isCheckbox) {
    if (isCheckbox) {
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.disabled = true;
      checkbox.checked = value === "true" || value === true;
      return td(checkbox);
    }
    return td(el("span", { className: "table-readonly-chip" }, [String(value || t("common.empty_dash"))]));
  }

  // ES: Convierte columnas y forms en campos del modal común.
  // EN: Converts columns and forms into common modal fields.
  function modalFields(policy, metadata) {
    const forms = metadata.forms.password_policy || {};
    const columns = metadata.structure.password_policy || [];
    return columns.map(column => {
      const checkbox = forms.checkbox && forms.checkbox[column];
      const readonly = forms.not_editable && Object.prototype.hasOwnProperty.call(forms.not_editable, column);
      return {
        key: column,
        label: t(`password_policy.${column}`),
        type: checkbox ? "checkbox" : "text",
        value: policy[column],
        readonly,
        checkedValue: checkbox && checkbox.checked,
        uncheckedValue: checkbox && checkbox.unchecked,
      };
    });
  }

  // ES: Construye payload sólo con campos editables declarados.
  // EN: Builds payload only from declared editable fields.
  function payloadFromData(data, metadata) {
    const allowed = metadata.commands.password_policy.table.payload_fields || [];
    const payload = {};
    allowed.forEach(key => {
      if (Object.prototype.hasOwnProperty.call(data, key)) payload[key] = String(data[key] ?? "").trim();
    });
    return payload;
  }

  // ES: Abre edición del singleton de política.
  // EN: Opens edit for the policy singleton.
  function openEditModal(policy, metadata, refresh) {
    window.PraesidiumModal.openFormModal({
      title: t("common.edit_title"),
      fields: modalFields(policy, metadata),
      async onSave(data) {
        await window.PraesidiumApiCommands.execute(metadata.commands, "password_policy", "update", {
          payload: payloadFromData(data, metadata),
        });
        await refresh();
      },
    });
  }

  // ES: Tabla de una sola fila porque FastAPI expone un singleton policy.
  // EN: One-row table because FastAPI exposes a policy singleton.
  function tableNode(policy, metadata, refresh) {
    const columns = metadata.structure.password_policy || [];
    const forms = metadata.forms.password_policy || {};
    const checkboxFields = forms.checkbox || {};
    const edit = el("button", { className: "button_edit", type: "button" }, [t("common.edit")]);
    edit.addEventListener("click", () => openEditModal(policy, metadata, refresh));
    const table = el("table", { className: "pf-table" }, [
      el("thead", {}, [tr([th(t("common.action")), ...columns.map(column => th(t(`password_policy.${column}`)))])]),
      el("tbody", {}, [tr([
        td(edit),
        ...columns.map(column => cellNode(policy[column], Object.prototype.hasOwnProperty.call(checkboxFields, column))),
      ])]),
    ]);
    PraesidiumTableFilter.attach(table, { disabledColumnIndexes: [0] });
    return el("div", { className: "pf-card" }, [el("div", { className: "pf-table-wrap" }, [table])]);
  }

  // ES: Render principal de la política candidate.
  // EN: Main render for candidate policy.
  async function render(container) {
    replaceChildren(container, [pageHeaderNode(), el("div", { className: "pf-alert" }, [t("password_policy.loading")])]);
    try {
      const metadata = await loadMetadata();
      const payload = await window.PraesidiumApiCommands.execute(metadata.commands, "password_policy", "list");
      replaceChildren(container, [pageHeaderNode(), tableNode(payload.policy || {}, metadata, () => render(container))]);
    } catch (error) {
      replaceChildren(container, [pageHeaderNode(), el("div", { className: "pf-alert error" }, [error && error.message ? error.message : String(error)])]);
    }
  }

  // ES: API pública del módulo password_policy.
  // EN: Public API for the password_policy module.
  window.PraesidiumPasswordPolicyPage = { render };
})();
