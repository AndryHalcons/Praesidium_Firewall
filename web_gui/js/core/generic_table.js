/*
 * ES: Renderer genérico para tablas metadata-driven.
 * EN: Generic renderer for metadata-driven tables.
 */
(() => {
  "use strict";

  const { t } = window.PraesidiumUi;
  const { el, replaceChildren, td, th, tr } = window.PraesidiumDom;

  // ES: Construye la cabecera sin HTML crudo.
  // EN: Builds the header without raw HTML.
  function pageHeaderNode(title, description) {
    const titleChildren = [el("h2", {}, [title])];
    if (description) titleChildren.push(el("p", { className: "pf-muted" }, [description]));
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, titleChildren),
      el("div"),
    ]);
  }

  // ES: Carga un JSON estático same-origin y exige JSON válido.
  // EN: Loads same-origin static JSON and requires valid JSON.
  async function fetchMetadataJson(path) {
    const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`metadata_load_failed:${path}:${response.status}`);
    return response.json();
  }


  // ES: Cachea fuentes de tooltip para no repetir GET en cada repintado.
  // EN: Caches tooltip sources to avoid repeating GET on every repaint.
  const tooltipSourceCache = new Map();

  // ES: Extrae consultas GET locales declaradas en forms.tooltip_fields.
  // EN: Extracts local GET queries declared in forms.tooltip_fields.
  function parseGetQueries(config) {
    const rawItems = Array.isArray(config) ? config : [config];
    return rawItems
      .filter(item => typeof item === "string" && item.trim())
      .map(item => {
        const match = item.trim().match(/^(GET)\s+(\/\S*)$/i);
        if (!match) return null;
        let path = match[2];
        if (path.startsWith("/api/v1/")) path = path.slice("/api/v1".length);
        if (!path.startsWith("/") || path.includes("://") || path.includes("..") || path.startsWith("//")) return null;
        return { method: match[1].toUpperCase(), path };
      })
      .filter(Boolean);
  }

  // ES: Normaliza respuestas de lista a array seguro.
  // EN: Normalizes list responses into a safe array.
  function rowsFromResponse(payload, rowsKey) {
    if (Array.isArray(payload)) return payload;
    if (rowsKey && payload && Array.isArray(payload[rowsKey])) return payload[rowsKey];
    if (payload && Array.isArray(payload.aliases)) return payload.aliases;
    if (payload && Array.isArray(payload.items)) return payload.items;
    if (payload && Array.isArray(payload.rules)) return payload.rules;
    if (payload && Array.isArray(payload.entries)) return payload.entries;
    if (payload && payload.entries && typeof payload.entries === "object") {
      return Object.keys(payload.entries).map(name => Object.assign({ name }, payload.entries[name] || {}));
    }
    return [];
  }

  // ES: Devuelve el tipo de campo definido en forms para una columna.
  // EN: Returns the field type defined in forms for a column.
  function fieldType(forms, sectionKey, column) {
    const section = forms && forms[sectionKey] ? forms[sectionKey] : {};
    if (section.button && Object.prototype.hasOwnProperty.call(section.button, column)) return "button";
    if (section.checkbox && Object.prototype.hasOwnProperty.call(section.checkbox, column)) return "checkbox";
    if (section.object_multiselect && Object.prototype.hasOwnProperty.call(section.object_multiselect, column)) return "object_multiselect";
    if (section.select_dynamic && Object.prototype.hasOwnProperty.call(section.select_dynamic, column)) return "select_dynamic";
    if (section.select_list && Object.prototype.hasOwnProperty.call(section.select_list, column)) return "select_list";
    if (section.select && Object.prototype.hasOwnProperty.call(section.select, column)) return "select";
    if (section.not_editable && Object.prototype.hasOwnProperty.call(section.not_editable, column)) return "not_editable";
    return "text";
  }

  // ES: Convierte valores backend a texto seguro para render de sólo lectura.
  // EN: Converts backend values into safe text for read-only rendering.
  function displayValue(value, type) {
    if (Array.isArray(value)) {
      if (!value.length) return t("common.empty_dash");
      return value.map(item => {
        if (item && typeof item === "object") return item.name || item.id || item.UUID || JSON.stringify(item);
        return String(item);
      }).join(", ");
    }
    if (type === "checkbox") return value === true || value === "true" ? "true" : "false";
    if (value === null || value === undefined || value === "") return t("common.empty_dash");
    if (typeof value === "object") return value.name || value.id || value.UUID || JSON.stringify(value);
    return String(value);
  }

  // ES: Normaliza valores de tabla a lista de chips sólo lectura.
  // EN: Normalizes table values into read-only chips.
  function readonlyChipItems(value, type) {
    if (Array.isArray(value)) return value.length ? value : [t("common.empty_dash")];
    const text = displayValue(value, type);
    if (text === t("common.empty_dash")) return [text];
    return String(text).split(",").map(item => item.trim()).filter(Boolean);
  }

  // ES: Texto visible de chip de tabla sin interpretar HTML.
  // EN: Visible table chip text without interpreting HTML.
  function readonlyChipText(item) {
    if (item && typeof item === "object") return item.name || item.id || item.UUID || JSON.stringify(item);
    return String(item);
  }

  // ES: Claves por las que se puede localizar un alias/objeto para tooltip.
  // EN: Keys used to locate an alias/object for tooltip.
  function tooltipLookupKeys(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [String(item || "")];
    return [item.UUID, item.uuid, item.name, item.id].map(value => String(value || "")).filter(Boolean);
  }

  // ES: Normaliza content interno para tooltips.
  // EN: Normalizes internal content for tooltips.
  function tooltipContentItems(value) {
    if (Array.isArray(value)) return value;
    if (value === null || value === undefined || value === "") return [];
    if (typeof value === "object") return [value];
    return String(value).split(",").map(item => item.trim()).filter(Boolean);
  }

  // ES: Texto visible de un objeto/valor dentro del tooltip.
  // EN: Visible text for an object/value inside the tooltip.
  function tooltipDisplayItem(item) {
    if (item && typeof item === "object" && !Array.isArray(item)) return item.name || item.UUID || item.uuid || item.id || JSON.stringify(item);
    return String(item || "");
  }

  // ES: Genera el texto title para un chip resolviendo alias/grupos si están cargados.
  // EN: Builds the title text for a chip, resolving aliases/groups when loaded.
  function tooltipTextForChip(item, lookup) {
    const visible = readonlyChipText(item).trim();
    const resolved = lookup && (lookup[visible] || lookup[String(item || "")]);
    const objectItem = resolved || (item && typeof item === "object" && !Array.isArray(item) ? item : null);
    if (!objectItem) return visible;
    const name = tooltipDisplayItem(objectItem);
    const content = tooltipContentItems(objectItem.content);
    if (!content.length) return name;
    const lines = content.map(child => {
      const childText = tooltipDisplayItem(child);
      const childResolved = lookup && lookup[childText];
      if (!childResolved) return childText;
      const childContent = tooltipContentItems(childResolved.content).map(tooltipDisplayItem).filter(Boolean).join(", ");
      return childContent ? `${tooltipDisplayItem(childResolved)}: ${childContent}` : tooltipDisplayItem(childResolved);
    }).filter(Boolean);
    return [name, ...lines].filter(Boolean).join("\n");
  }

  // ES: Crea chips de tabla sin X porque la tabla es sólo lectura, con límite visual y modal read-only.
  // EN: Creates read-only table chips, with a visual limit and a read-only modal for the full list.
  function readonlyChipsNode(value, type, tooltipLookup, title) {
    const items = readonlyChipItems(value, type);
    const maxVisible = 5;
    const fullItems = items.map(item => ({ text: readonlyChipText(item), title: tooltipLookup ? tooltipTextForChip(item, tooltipLookup) : "" }));
    const children = fullItems.slice(0, maxVisible).map(item => {
      const chip = el("span", { className: "table-readonly-chip" }, [item.text]);
      if (item.title) chip.title = item.title;
      return chip;
    });

    // ES: Mantiene todos los valores en el DOM para que los filtros de tabla sigan encontrándolos.
    // EN: Keeps all values in the DOM so table filters can still find them.
    children.push(el("span", { className: "table-readonly-filter-text" }, [fullItems.map(item => item.text).join(" ")]));

    if (fullItems.length > maxVisible) {
      const moreBtn = el("button", { className: "table-chip-more", type: "button" }, ["more"]);
      moreBtn.addEventListener("click", () => {
        if (window.PraesidiumModal && typeof window.PraesidiumModal.openReadOnlyListModal === "function") {
          window.PraesidiumModal.openReadOnlyListModal({ title, items: fullItems });
        }
      });
      children.push(moreBtn);
    }
    return el("div", { className: "table-readonly-chips" }, children);
  }

  // ES: Etiqueta visible de columna usando prefijo i18n configurable.
  // EN: Visible column label using a configurable i18n prefix.
  function columnLabel(column, tableConfig) {
    const prefix = tableConfig.column_label_prefix || "columns";
    return PraesidiumI18n.t(`${prefix}.${column}`);
  }

  // ES: Devuelve la sección forms de la tabla actual.
  // EN: Returns the forms section for the current table.
  function formSection(metadata, sectionKey) {
    return metadata.forms && metadata.forms[sectionKey] ? metadata.forms[sectionKey] : {};
  }

  // ES: Devuelve configuración genérica de tabla desde commands_api.
  // EN: Returns generic table config from commands_api.
  function tableConfig(metadata, sectionKey) {
    const sectionCommands = metadata.commands && metadata.commands[sectionKey] ? metadata.commands[sectionKey] : {};
    return sectionCommands.table || {};
  }


  // ES: Devuelve la configuración tooltip_fields del forms actual.
  // EN: Returns tooltip_fields config for the current forms section.
  function tooltipFields(metadata, sectionKey) {
    const section = formSection(metadata, sectionKey);
    return section.tooltip_fields || {};
  }

  // ES: Carga fuentes tooltip declaradas y construye lookup por columna.
  // EN: Loads declared tooltip sources and builds a lookup per column.
  async function loadTooltipLookups(metadata, sectionKey) {
    const fields = tooltipFields(metadata, sectionKey);
    const result = {};
    await Promise.all(Object.keys(fields).map(async column => {
      const queries = parseGetQueries(fields[column]);
      const lists = await Promise.all(queries.map(query => {
        const key = `${query.method} ${query.path}`;
        if (!tooltipSourceCache.has(key)) {
          tooltipSourceCache.set(key, window.PraesidiumApi.request(query.path, { method: query.method }).then(payload => rowsFromResponse(payload)));
        }
        return tooltipSourceCache.get(key);
      }));
      const lookup = {};
      lists.flat().forEach(item => {
        tooltipLookupKeys(item).forEach(key => { lookup[key] = item; });
      });
      result[column] = lookup;
    }));
    return result;
  }

  // ES: Construye los campos del modal desde structure/forms y la fila backend.
  // EN: Builds modal fields from structure/forms and the backend row.
  function modalFields(row, metadata, sectionKey, columns) {
    const section = formSection(metadata, sectionKey);
    const cfg = tableConfig(metadata, sectionKey);
    return columns.filter(column => fieldType(metadata.forms, sectionKey, column) !== "button").map(column => {
      const type = fieldType(metadata.forms, sectionKey, column);
      const checkbox = section.checkbox && section.checkbox[column] ? section.checkbox[column] : {};
      const objectMultiselect = section.object_multiselect && Object.prototype.hasOwnProperty.call(section.object_multiselect, column)
        ? section.object_multiselect[column]
        : null;
      const selectList = section.select_list && Object.prototype.hasOwnProperty.call(section.select_list, column)
        ? section.select_list[column]
        : null;
      const selectDynamic = section.select_dynamic && Object.prototype.hasOwnProperty.call(section.select_dynamic, column)
        ? section.select_dynamic[column]
        : null;
      const tooltipSources = section.tooltip_fields && Object.prototype.hasOwnProperty.call(section.tooltip_fields, column)
        ? section.tooltip_fields[column]
        : null;
      return {
        key: column,
        label: columnLabel(column, cfg),
        type,
        value: row[column],
        readonly: type === "not_editable",
        options: section.select && Array.isArray(section.select[column]) ? section.select[column] : [],
        selectList,
        selectDynamic,
        tooltipSources,
        objectMultiselect,
        checkedValue: checkbox.checked,
        uncheckedValue: checkbox.unchecked,
      };
    });
  }

  // ES: Crea payload genérico limitando campos según commands_api.table.payload_fields.
  // EN: Creates a generic payload constrained by commands_api.table.payload_fields.
  function actionPayload(data, metadata, sectionKey) {
    const cfg = tableConfig(metadata, sectionKey);
    const allowed = Array.isArray(cfg.payload_fields) ? cfg.payload_fields : Object.keys(data || {});
    const payload = {};
    allowed.forEach(key => {
      if (!Object.prototype.hasOwnProperty.call(data || {}, key)) return;
      if (fieldType(metadata.forms, sectionKey, key) === "not_editable") return;
      const value = data[key];
      if (Array.isArray(value)) {
        payload[key] = value.map(String).filter(Boolean);
      } else if (key === "content") {
        payload[key] = String(value || "").split(",").map(item => item.trim()).filter(Boolean);
      } else {
        payload[key] = String(value || "").trim();
      }
    });
    return payload;
  }

  // ES: Envuelve payloads cuando el backend espera una clave raíz declarada.
  // EN: Wraps payloads when the backend expects a declared root key.
  function wrapPayload(payload, metadata, sectionKey) {
    const cfg = tableConfig(metadata, sectionKey);
    if (!cfg.payload_wrapper) return payload;
    return { [cfg.payload_wrapper]: payload };
  }

  // ES: Construye campos vacíos para crear una fila; no muestra campos not_editable.
  // EN: Builds empty fields to create a row; it does not show not_editable fields.
  function createFields(metadata, sectionKey, columns) {
    const emptyRow = {};
    return modalFields(emptyRow, metadata, sectionKey, columns).filter(field => !field.readonly);
  }

  // ES: Abre modal vacío para crear usando commands_api create.
  // EN: Opens an empty modal to create using commands_api create.
  function openCreateModal(metadata, sectionKey, columns, refresh) {
    window.PraesidiumModal.openFormModal({
      title: t("common.add"),
      fields: createFields(metadata, sectionKey, columns),
      async onSave(data) {
        await window.PraesidiumApiCommands.execute(metadata.commands, sectionKey, "create", {
          payload: wrapPayload(actionPayload(data, metadata, sectionKey), metadata, sectionKey),
        });
        await refresh();
      },
    });
  }

  // ES: Obtiene el identificador oculto de fila según commands_api.table.row_key.
  // EN: Gets the hidden row identifier from commands_api.table.row_key.
  function rowIdentity(row, cfg) {
    const rowKey = cfg.row_key || "UUID";
    return row[rowKey] || row.UUID || row.uuid || "";
  }

  // ES: Construye una identidad humana con los campos disponibles de la fila.
  // EN: Builds a human-readable identity from the row fields that are available.
  function deleteObjectIdentityLines(row) {
    const parts = [];
    const addPart = (label, value) => {
      if (value !== undefined && value !== null && String(value).trim() !== "") parts.push({ label, value: String(value) });
    };
    addPart("ID", row && row.id);
    addPart("UUID", row && (row.UUID || row.uuid));
    addPart(t("common.name_label"), row && row.name);
    const values = parts.length ? parts : [{ label: t("common.unknown"), value: "" }];
    return values.map((item, index) => ({ ...item, suffix: index < values.length - 1 ? "," : "" }));
  }

  // ES: Pide confirmación explícita antes de ejecutar DELETE y refrescar la tabla.
  // EN: Requests explicit confirmation before executing DELETE and refreshing the table.
  function openDeleteConfirmModal(row, metadata, sectionKey, refresh) {
    const cfg = tableConfig(metadata, sectionKey);
    const contextKey = cfg.context_key || "uuid";
    const context = { [contextKey]: rowIdentity(row, cfg) };
    window.PraesidiumModal.openConfirmModal({
      title: t("common.delete_confirm_title"),
      message: t("common.delete_confirm_message"),
      details: deleteObjectIdentityLines(row),
      async onConfirm() {
        await window.PraesidiumApiCommands.execute(metadata.commands, sectionKey, "delete", { params: context });
        await refresh();
      },
    });
  }

  // ES: Abre el modal de edición; Guardar usa commands_api y refresca la tabla.
  // EN: Opens the edit modal; Save uses commands_api and refreshes the table.
  function openEditModal(row, metadata, sectionKey, columns, refresh) {
    const cfg = tableConfig(metadata, sectionKey);
    const contextKey = cfg.context_key || "uuid";
    const context = {};
    context[contextKey] = rowIdentity(row, cfg);
    const titleSuffix = row && row.name ? ` - ${row.name}` : "";
    window.PraesidiumModal.openFormModal({
      title: `${t("common.edit_title")}${titleSuffix}`,
      fields: modalFields(row, metadata, sectionKey, columns),
      // ES: Identificador oculto para guardar; no se pinta en el modal.
      // EN: Hidden identifier for saving; it is not rendered in the modal.
      context,
      async onSave(data, modalContext) {
        await window.PraesidiumApiCommands.execute(metadata.commands, sectionKey, "update", {
          params: modalContext,
          payload: wrapPayload(actionPayload(data, metadata, sectionKey), metadata, sectionKey),
        });
        await refresh();
      },
    });
  }

  // ES: Comprueba si commands_api.table.disable_buttons oculta un botón concreto.
  // EN: Checks whether commands_api.table.disable_buttons hides a concrete button.
  function buttonDisabled(metadata, sectionKey, buttonName) {
    const cfg = tableConfig(metadata, sectionKey);
    const disabled = Array.isArray(cfg.disable_buttons) ? cfg.disable_buttons : [];
    return disabled.includes(buttonName);
  }

  // ES: Devuelve los IDs de botones declarados para una columna forms.button.
  // EN: Returns button IDs declared for a forms.button column.
  function buttonFieldActionIds(metadata, sectionKey, column) {
    const section = formSection(metadata, sectionKey);
    const configured = section.button && Object.prototype.hasOwnProperty.call(section.button, column)
      ? section.button[column]
      : [];
    if (!Array.isArray(configured) || configured.some(item => typeof item !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(item))) {
      throw new Error(`invalid_button_field:${sectionKey}:${column}`);
    }
    return configured;
  }

  // ES: Valida una acción declarativa cerrada; no admite JS, URLs externas ni métodos arbitrarios.
  // EN: Validates a closed declarative action; it accepts no JS, external URLs, or arbitrary methods.
  function buttonActionDefinition(metadata, sectionKey, actionId) {
    const sectionCommands = metadata.commands && metadata.commands[sectionKey] ? metadata.commands[sectionKey] : {};
    const actions = sectionCommands.button_actions && typeof sectionCommands.button_actions === "object"
      ? sectionCommands.button_actions
      : {};
    const action = actions[actionId];
    if (!action || typeof action !== "object" || Array.isArray(action)) throw new Error(`missing_button_action:${sectionKey}:${actionId}`);
    const method = String(action.method || "").toUpperCase();
    const path = String(action.path || "");
    const responseType = String(action.response_type || "");
    const labelKey = String(action.label_key || "");
    const params = action.params;
    if (method !== "GET") throw new Error(`invalid_button_action_method:${sectionKey}:${actionId}`);
    if (responseType !== "download") throw new Error(`invalid_button_action_response:${sectionKey}:${actionId}`);
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("://") || path.includes("..") || path.includes("\\")) {
      throw new Error(`invalid_button_action_path:${sectionKey}:${actionId}`);
    }
    if (!labelKey || !Array.isArray(params) || params.some(param => typeof param !== "string" || !/^[A-Za-z0-9_]{1,64}$/.test(param))) {
      throw new Error(`invalid_button_action_metadata:${sectionKey}:${actionId}`);
    }
    const placeholders = [...path.matchAll(/\{([A-Za-z0-9_]{1,64})\}/g)].map(match => match[1]);
    const residue = path.replace(/\{[A-Za-z0-9_]{1,64}\}/g, "");
    const declared = [...new Set(params)].sort();
    const used = [...new Set(placeholders)].sort();
    if (residue.includes("{") || residue.includes("}") || JSON.stringify(declared) !== JSON.stringify(used)) {
      throw new Error(`invalid_button_action_params:${sectionKey}:${actionId}`);
    }
    return { method, path, responseType, labelKey, params: declared };
  }

  // ES: Sustituye sólo parámetros declarados con valores de la fila codificados para URL.
  // EN: Replaces declared parameters only with URL-encoded row values.
  function buttonActionPath(action, row, cfg, sectionKey, actionId) {
    const contextKey = cfg.context_key || "uuid";
    let path = action.path;
    action.params.forEach(param => {
      const value = param === contextKey ? rowIdentity(row, cfg) : row[param];
      if (value === undefined || value === null || String(value).trim() === "") {
        throw new Error(`missing_button_action_param:${sectionKey}:${actionId}:${param}`);
      }
      path = path.split(`{${param}}`).join(encodeURIComponent(String(value)));
    });
    return path;
  }

  // ES: Muestra errores de acciones dentro de la tarjeta de tabla.
  // EN: Shows action errors inside the table card.
  function setButtonActionError(errorBox, message = "") {
    replaceChildren(errorBox, message ? [message] : []);
    errorBox.hidden = !message;
  }

  // ES: Renderiza botones declarativos de una columna y ejecuta descargas seguras.
  // EN: Renders declarative column buttons and executes safe downloads.
  function buttonFieldCell(row, metadata, sectionKey, column, errorBox) {
    const cfg = tableConfig(metadata, sectionKey);
    const buttons = buttonFieldActionIds(metadata, sectionKey, column).map(actionId => {
      const action = buttonActionDefinition(metadata, sectionKey, actionId);
      const button = el("button", { className: "button_action button_download", type: "button" }, [PraesidiumI18n.t(action.labelKey)]);
      button.addEventListener("click", async () => {
        setButtonActionError(errorBox);
        button.disabled = true;
        try {
          const path = buttonActionPath(action, row, cfg, sectionKey, actionId);
          await window.PraesidiumApi.download(path);
        } catch (err) {
          setButtonActionError(errorBox, err && err.message ? err.message : String(err));
        } finally {
          button.disabled = false;
        }
      });
      return button;
    });
    return td(el("div", { className: "pf-row-actions" }, buttons));
  }

  // ES: Crea los botones de acción de fila; no llaman API directamente, abren el modal.
  // EN: Creates row action buttons; they do not call the API directly, they open the modal.
  function rowActionCell(row, metadata, sectionKey, columns, refresh) {
    const actions = [];
    if (!buttonDisabled(metadata, sectionKey, "edit")) {
      const editButton = el("button", { className: "button_edit", type: "button" }, [t("common.edit")]);
      editButton.addEventListener("click", () => openEditModal(row, metadata, sectionKey, columns, refresh));
      actions.push(editButton);
    }
    if (!buttonDisabled(metadata, sectionKey, "delete")) {
      const deleteButton = el("button", { className: "button_delete", type: "button" }, [t("common.delete")]);
      deleteButton.addEventListener("click", () => openDeleteConfirmModal(row, metadata, sectionKey, refresh));
      actions.push(deleteButton);
    }
    return td(el("div", { className: "pf-row-actions" }, actions));
  }

  // ES: Tabla generada desde structure; JavaScript añade sólo la columna de acciones.
  // EN: Table generated from structure; JavaScript only adds the actions column.
  function metadataTableNode(rows, metadata, sectionKey, refresh, tooltipLookups = {}) {
    const cfg = tableConfig(metadata, sectionKey);
    const columns = Array.isArray(metadata.structure[sectionKey]) ? metadata.structure[sectionKey] : [];
    if (!columns.length) return el("div", { className: "pf-alert error" }, [`missing_table_structure:${sectionKey}`]);
    const buttonColumns = columns.filter(column => fieldType(metadata.forms, sectionKey, column) === "button");
    buttonColumns.forEach(column => {
      buttonFieldActionIds(metadata, sectionKey, column).forEach(actionId => buttonActionDefinition(metadata, sectionKey, actionId));
    });

    const toolbarItems = [];
    if (!buttonDisabled(metadata, sectionKey, "add")) {
      const addAction = el("button", { className: "button_add", type: "button" }, [t("common.add")]);
      addAction.addEventListener("click", () => openCreateModal(metadata, sectionKey, columns, refresh));
      toolbarItems.push(addAction);
    }
    const addButton = el("div", { className: "pf-table-toolbar" }, toolbarItems);
    const actionError = buttonColumns.length ? el("div", { className: "pf-alert error" }, []) : null;
    if (actionError) actionError.hidden = true;

    if (!rows.length) {
      return el("div", { className: "pf-card" }, [
        addButton,
        el("div", { className: "pf-alert" }, [PraesidiumI18n.t(cfg.empty_key || "common.empty_dash")]),
      ]);
    }

    const table = el("table", { className: "pf-table" }, [
      el("thead", {}, [tr([th(t("common.action")), ...columns.map(column => th(columnLabel(column, cfg)))])]),
      el("tbody", {}, rows.map(row => tr([
        rowActionCell(row, metadata, sectionKey, columns, refresh),
        ...columns.map(column => {
          const type = fieldType(metadata.forms, sectionKey, column);
          if (type === "button") return buttonFieldCell(row, metadata, sectionKey, column, actionError);
          if (type === "checkbox") {
            const checkboxConfig = formSection(metadata, sectionKey).checkbox?.[column] || {};
            const hasDeclaredChecked = Object.prototype.hasOwnProperty.call(checkboxConfig, "checked");
            const checkedValue = hasDeclaredChecked ? checkboxConfig.checked : "true";
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.disabled = true;
            checkbox.checked = row[column] === checkedValue || (checkedValue === "true" && row[column] === true);
            return td(checkbox);
          }
          if (type === "select_list" && tooltipLookups[column]) {
            const referenced = tooltipLookups[column][String(row[column] ?? "")];
            if (referenced) {
              const visible = referenced.name || referenced.id || row[column];
              return td(cfg.readonly_chips === false
                ? displayValue(visible, type)
                : readonlyChipsNode(visible, type, null, columnLabel(column, cfg)));
            }
          }
          return td(cfg.readonly_chips === false ? displayValue(row[column], type) : readonlyChipsNode(row[column], type, tooltipLookups[column], columnLabel(column, cfg)));
        })
      ]))),
    ]);
    const disabledColumnIndexes = [
      0,
      ...buttonColumns.map(column => columns.indexOf(column) + 1),
    ];
    PraesidiumTableFilter.attach(table, { disabledColumnIndexes });
    const tableWrap = el("div", { className: "pf-table-wrap" }, [table]);
    const cardChildren = actionError ? [addButton, actionError, tableWrap] : [addButton, tableWrap];
    return el("div", { className: "pf-card" }, cardChildren);
  }

  // ES: Construye rutas metadata estándar desde sección y basePath.
  // EN: Builds standard metadata paths from section and basePath.
  function metadataPaths(config) {
    const section = config.section;
    const basePath = config.basePath || `/js/pages/${section}`;
    return {
      formsPath: config.formsPath || `${basePath}/forms_${section}.json`,
      structurePath: config.structurePath || `${basePath}/structure_tables_${section}.json`,
      commandsPath: config.commandsPath || `${basePath}/${section}_commands_api.json`,
    };
  }

  // ES: Crea un renderer de página para una sección metadata-driven concreta.
  // EN: Creates a page renderer for one concrete metadata-driven section.
  function createRenderer(config) {
    const sectionKey = config.section || config.tableKey;
    const paths = metadataPaths({ ...config, section: sectionKey });
    let metadataPromise = null;

    function loadMetadata() {
      if (!metadataPromise) {
        metadataPromise = Promise.all([
          fetchMetadataJson(paths.formsPath),
          fetchMetadataJson(paths.structurePath),
          fetchMetadataJson(paths.commandsPath),
        ]).then(([forms, structure, commands]) => ({ forms, structure, commands }));
      }
      return metadataPromise;
    }

    return async function render(container) {
      try {
        const metadata = await loadMetadata();
        const cfg = tableConfig(metadata, sectionKey);
        const title = PraesidiumI18n.t(config.titleKey || cfg.title_key || sectionKey);
        const description = PraesidiumI18n.t(config.descriptionKey || cfg.description_key || "");
        const listCommand = metadata.commands && metadata.commands[sectionKey] ? metadata.commands[sectionKey].list : null;
        const endpoint = config.endpoint || (listCommand && listCommand.path) || "";
        replaceChildren(container, [
          pageHeaderNode(title, description),
          el("div", { className: "pf-alert" }, [PraesidiumI18n.t(cfg.loading_key || "common.loading", { path: endpoint })]),
        ]);
        const payload = await window.PraesidiumApiCommands.execute(metadata.commands, sectionKey, "list");
        const tooltipLookups = await loadTooltipLookups(metadata, sectionKey);
        replaceChildren(container, [
          pageHeaderNode(title, description),
          metadataTableNode(rowsFromResponse(payload, cfg.rows_key), metadata, sectionKey, () => render(container), tooltipLookups),
        ]);
      } catch (err) {
        replaceChildren(container, [
          pageHeaderNode(PraesidiumI18n.t(config.titleKey || sectionKey), ""),
          el("div", { className: "pf-alert error" }, [err.message]),
        ]);
      }
    };
  }

  // ES: API pública para módulos que usan tablas metadata-driven.
  // EN: Public API for modules using metadata-driven tables.
  window.PraesidiumGenericTable = { createRenderer };
})();
