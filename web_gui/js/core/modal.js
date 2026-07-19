/*
 * ES: Modal seguro reutilizable para formularios WebGUI.
 * EN: Reusable safe modal for WebGUI forms.
 */
(() => {
  "use strict";

  const { t } = window.PraesidiumUi;
  const { el } = window.PraesidiumDom;

  // ES: Convierte valores de tabla/API en texto editable seguro.
  // EN: Converts table/API values into safe editable text.
  function valueToText(value) {
    if (Array.isArray(value)) return value.map(item => {
      if (item && typeof item === "object") return item.name || item.id || item.UUID || JSON.stringify(item);
      return String(item);
    }).join(", ");
    if (value === null || value === undefined) return "";
    if (typeof value === "object") return value.name || value.id || value.UUID || JSON.stringify(value);
    return String(value);
  }


  // ES: Normaliza content a lista editable para pintarlo como chips dentro del modal.
  // EN: Normalizes content into an editable list to render it as chips inside the modal.
  function contentItems(value) {
    if (Array.isArray(value)) return value.slice();
    if (value === null || value === undefined || value === "") return [];
    return String(value).split(",").map(item => item.trim()).filter(Boolean);
  }

  // ES: Texto visible de chip sin interpretar HTML.
  // EN: Visible chip text without interpreting HTML.
  function chipText(item) {
    if (item && typeof item === "object") return item.name || item.id || item.UUID || JSON.stringify(item);
    return String(item);
  }

  // ES: Cachea fuentes de búsqueda object_multiselect para no repetir GET en cada tecla.
  // EN: Caches object_multiselect search sources to avoid repeating GET on every key.
  const objectSearchCache = new Map();

  // ES: Cachea opciones de select_list para no repetir GET al abrir modales.
  // EN: Caches select_list options to avoid repeating GET when opening modals.
  const selectListCache = new Map();

  // ES: Cachea fuentes tooltip del modal para chips seleccionados.
  // EN: Caches modal tooltip sources for selected chips.
  const tooltipCache = new Map();

  // ES: Extrae una o varias consultas declarativas tipo "GET /api/v1/..." desde metadata de forms.
  // EN: Extracts one or more declarative queries like "GET /api/v1/..." from forms metadata.
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

  // ES: Extrae una o varias consultas declarativas desde forms.object_multiselect[field].
  // EN: Extracts one or more declarative queries from forms.object_multiselect[field].
  function objectMultiselectQueries(field) {
    return parseGetQueries(field.objectMultiselect);
  }

  // ES: Normaliza respuesta de lista para buscador object_multiselect.
  // EN: Normalizes list responses for object_multiselect search.
  function objectSearchRows(payload) {
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.aliases)) return payload.aliases;
    if (payload && Array.isArray(payload.items)) return payload.items;
    if (payload && Array.isArray(payload.rules)) return payload.rules;
    if (payload && Array.isArray(payload.entries)) return payload.entries;
    if (payload && payload.entries && typeof payload.entries === "object") {
      return Object.keys(payload.entries).map(key => Object.assign({ UUID: key }, payload.entries[key] || {}));
    }
    return [];
  }

  // ES: Clave estable de opción para deduplicar resultados de varias fuentes.
  // EN: Stable option key to deduplicate results from several sources.
  function objectSearchKey(item) {
    if (item && typeof item === "object") return item.UUID || item.uuid || item.name || item.id || JSON.stringify(item);
    return String(item);
  }


  // ES: Claves por las que localizar objetos para tooltip.
  // EN: Keys used to locate objects for tooltip.
  function tooltipKeys(item) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [String(item || "")];
    return [item.UUID, item.uuid, item.name, item.id].map(value => String(value || "")).filter(Boolean);
  }

  // ES: Normaliza content interno para tooltip.
  // EN: Normalizes internal content for tooltip.
  function tooltipContentItems(value) {
    if (Array.isArray(value)) return value;
    if (value === null || value === undefined || value === "") return [];
    if (typeof value === "object") return [value];
    return String(value).split(",").map(item => item.trim()).filter(Boolean);
  }

  // ES: Construye lookup tooltip desde una o varias fuentes GET.
  // EN: Builds tooltip lookup from one or more GET sources.
  async function loadTooltipLookup(config) {
    const queries = parseGetQueries(config);
    if (!queries.length) return {};
    const lists = await Promise.all(queries.map(query => {
      const key = `${query.method} ${query.path}`;
      if (!tooltipCache.has(key)) {
        tooltipCache.set(key, window.PraesidiumApi.request(query.path, { method: query.method }).then(objectSearchRows));
      }
      return tooltipCache.get(key);
    }));
    const lookup = {};
    lists.flat().forEach(item => {
      tooltipKeys(item).forEach(key => { lookup[key] = item; });
    });
    return lookup;
  }

  // ES: Texto tooltip para chips del modal.
  // EN: Tooltip text for modal chips.
  function tooltipText(item, lookup) {
    const visible = chipText(item).trim();
    const resolved = lookup && (lookup[visible] || lookup[String(item || "")]);
    const objectItem = resolved || (item && typeof item === "object" && !Array.isArray(item) ? item : null);
    if (!objectItem) return visible;
    const name = chipText(objectItem);
    const content = tooltipContentItems(objectItem.content);
    if (!content.length) return name;
    const lines = content.map(child => {
      const childText = chipText(child);
      const childResolved = lookup && lookup[childText];
      if (!childResolved) return childText;
      const childContent = tooltipContentItems(childResolved.content).map(chipText).filter(Boolean).join(", ");
      return childContent ? `${chipText(childResolved)}: ${childContent}` : chipText(childResolved);
    }).filter(Boolean);
    return [name, ...lines].filter(Boolean).join("\n");
  }

  // ES: Carga opciones desde una o varias consultas declaradas en forms, usando PraesidiumApi/proxy.
  // EN: Loads options from one or more queries declared in forms, using PraesidiumApi/proxy.
  async function loadObjectSearchOptions(queries) {
    if (!queries || !queries.length) return [];
    const lists = await Promise.all(queries.map(query => {
      const key = `${query.method} ${query.path}`;
      if (!objectSearchCache.has(key)) {
        objectSearchCache.set(key, window.PraesidiumApi.request(query.path, { method: query.method }).then(objectSearchRows));
      }
      return objectSearchCache.get(key);
    }));
    const seen = new Set();
    const merged = [];
    lists.flat().forEach(item => {
      const key = objectSearchKey(item);
      if (!key || seen.has(key)) return;
      seen.add(key);
      merged.push(item);
    });
    return merged;
  }


  // ES: Carga opciones de select_list desde una o varias fuentes GET declaradas en forms.
  // EN: Loads select_list options from one or more GET sources declared in forms.
  async function loadSelectListOptions(config) {
    const queries = parseGetQueries(config);
    if (!queries.length) return [];
    const lists = await Promise.all(queries.map(query => {
      const key = `${query.method} ${query.path}`;
      if (!selectListCache.has(key)) {
        selectListCache.set(key, window.PraesidiumApi.request(query.path, { method: query.method }).then(objectSearchRows));
      }
      return selectListCache.get(key);
    }));
    const seen = new Set();
    const merged = [];
    lists.flat().forEach(item => {
      const label = chipText(item).trim();
      const value = item && typeof item === "object"
        ? String(item.UUID || item.uuid || item.name || item.id || "").trim()
        : label;
      if (!label || !value || seen.has(value)) return;
      seen.add(value);
      merged.push({ value, label });
    });
    return merged;
  }

  // ES: Crea un editor de chips; si el campo es object_multiselect añade buscador tipo legacy.
  // EN: Creates a chip editor; if the field is object_multiselect it adds a legacy-like search.
  function contentChipEditor(field, values) {
    const items = contentItems(field.value);
    const queries = field.type === "object_multiselect" ? objectMultiselectQueries(field) : [];
    const hasSearch = queries.length > 0;
    let tooltipLookup = {};
    if (field.tooltipSources) {
      loadTooltipLookup(field.tooltipSources).then(lookup => {
        tooltipLookup = lookup;
        renderChips();
      }).catch(() => {});
    }
    const wrapper = el("div", { className: hasSearch ? "modal-object-multiselect" : "modal-chip-editor" }, []);
    const contentPane = hasSearch ? el("div", { className: "object-multiselect-content-pane" }, []) : null;
    const selectorPane = hasSearch ? el("div", { className: "object-multiselect-selector-pane" }, []) : null;
    const chips = el("div", { className: hasSearch ? "modal-multiselect-chips object-multiselect-selected" : "modal-multiselect-chips" }, []);
    const addRow = el("div", { className: "modal-multiselect-row" }, []);
    const input = document.createElement("input");
    input.type = "text";
    input.className = hasSearch ? "modal-input object-multiselect-search" : "modal-input";
    input.placeholder = hasSearch ? t("common.search") : (field.label || field.key);
    const addBtn = el("button", { className: "button_add", type: "button" }, [t("common.add")]);
    const dropdown = hasSearch ? el("div", { className: "object-multiselect-dropdown" }, []) : null;

    function renderChips() {
      while (chips.firstChild) chips.removeChild(chips.firstChild);
      if (!items.length) {
        chips.appendChild(el("span", { className: "pf-muted" }, [t("common.empty_dash")]));
        return;
      }
      items.forEach(item => {
        const chip = el("span", { className: "multiselect-chip" }, [chipText(item)]);
        const tooltip = field.tooltipSources ? tooltipText(item, tooltipLookup) : "";
        if (tooltip) chip.title = tooltip;
        const removeBtn = el("button", { className: "multiselect-chip-remove", type: "button", "aria-label": t("common.delete") }, ["×"]);
        removeBtn.addEventListener("click", () => {
          const idx = items.map(chipText).indexOf(chipText(item));
          if (idx !== -1) items.splice(idx, 1);
          renderChips();
          renderOptions(input.value);
        });
        chip.appendChild(removeBtn);
        chips.appendChild(chip);
      });
    }

    // ES: Añade un valor como chip evitando duplicados por texto visible.
    // EN: Adds a value as a chip, avoiding duplicates by visible text.
    function addValue(value, clearInput = true) {
      const text = chipText(value).trim();
      if (!text || items.map(chipText).includes(text)) return;
      items.push(text);
      if (clearInput) input.value = "";
      renderChips();
      renderOptions(clearInput ? "" : input.value);
    }

    // ES: Añade el valor escrito manualmente; el backend valida al guardar.
    // EN: Adds the typed manual value; the backend validates on save.
    function addCurrentValue() {
      addValue(input.value.trim());
    }

    // ES: Renderiza hasta 5 resultados cuando el término tiene 3+ caracteres.
    // EN: Renders up to 5 results when the term has 3+ characters.
    async function renderOptions(term) {
      if (!dropdown || !hasSearch) return;
      while (dropdown.firstChild) dropdown.removeChild(dropdown.firstChild);
      const cleanTerm = String(term || "").trim().toLowerCase();
      if (cleanTerm.length < 3) return;
      try {
        const options = await loadObjectSearchOptions(queries);
        options
          .filter(item => chipText(item).toLowerCase().includes(cleanTerm))
          .filter(item => !items.map(chipText).includes(chipText(item)))
          .slice(0, 5)
          .forEach(item => {
            const option = el("button", { className: "object-multiselect-option", type: "button" }, [chipText(item)]);
            option.addEventListener("click", () => addValue(item));
            dropdown.appendChild(option);
          });
      } catch (error) {
        dropdown.appendChild(el("span", { className: "pf-muted" }, [error && error.message ? error.message : String(error)]));
      }
    }

    addBtn.addEventListener("click", addCurrentValue);
    input.addEventListener("keydown", event => {
      if (event.key === "Enter") {
        event.preventDefault();
        addCurrentValue();
      }
    });
    input.addEventListener("input", () => renderOptions(input.value));
    input.addEventListener("focus", () => renderOptions(input.value));
    input.addEventListener("click", () => renderOptions(input.value));

    values.set(field.key, () => items.map(chipText));
    if (hasSearch) {
      contentPane.appendChild(chips);
      addRow.appendChild(input);
      addRow.appendChild(addBtn);
      selectorPane.appendChild(addRow);
      selectorPane.appendChild(dropdown);
      wrapper.appendChild(contentPane);
      wrapper.appendChild(selectorPane);
    } else {
      addRow.appendChild(input);
      addRow.appendChild(addBtn);
      wrapper.appendChild(addRow);
      wrapper.appendChild(chips);
    }
    renderChips();
    return wrapper;
  }


  // ES: Crea un selector dinámico que añade cada selección como chip múltiple.
  // EN: Creates a dynamic select that appends each selected option as a multi-value chip.
  function selectDynamicChipEditor(field, values) {
    const items = contentItems(field.value).map(chipText);
    const wrapper = el("div", { className: "modal-select-dynamic" }, []);
    const chips = el("div", { className: "modal-multiselect-chips" }, []);
    const select = document.createElement("select");
    select.className = "modal-input";
    let optionsCache = [];

    function itemTexts() {
      return items.map(item => String(item));
    }

    function renderChips() {
      while (chips.firstChild) chips.removeChild(chips.firstChild);
      if (!items.length) {
        chips.appendChild(el("span", { className: "pf-muted" }, [t("common.empty_dash")]));
        return;
      }
      items.forEach(item => {
        const chip = el("span", { className: "multiselect-chip" }, [String(item)]);
        const removeBtn = el("button", { className: "multiselect-chip-remove", type: "button", "aria-label": t("common.delete") }, ["×"]);
        removeBtn.addEventListener("click", () => {
          const idx = itemTexts().indexOf(String(item));
          if (idx !== -1) items.splice(idx, 1);
          renderChips();
          renderOptions();
        });
        chip.appendChild(removeBtn);
        chips.appendChild(chip);
      });
    }

    function optionNode(value, text) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = text;
      return option;
    }

    function renderOptions() {
      while (select.firstChild) select.removeChild(select.firstChild);
      select.appendChild(optionNode("", " --- "));
      const selected = new Set(itemTexts());
      optionsCache
        .filter(opt => !selected.has(String(opt.value)))
        .forEach(opt => select.appendChild(optionNode(String(opt.value), String(opt.label))));
      select.value = "";
    }

    function addSelected() {
      const value = String(select.value || "").trim();
      if (!value || itemTexts().includes(value)) {
        select.value = "";
        return;
      }
      items.push(value);
      renderChips();
      renderOptions();
    }

    select.appendChild(optionNode("", t("common.loading")));
    loadSelectListOptions(field.selectDynamic).then(options => {
      optionsCache = options;
      renderOptions();
    }).catch(error => {
      while (select.firstChild) select.removeChild(select.firstChild);
      select.appendChild(optionNode("", error && error.message ? error.message : String(error)));
    });
    select.addEventListener("change", addSelected);
    values.set(field.key, () => itemTexts());
    wrapper.appendChild(select);
    wrapper.appendChild(chips);
    renderChips();
    return wrapper;
  }

  // ES: Cierra el modal retirándolo del DOM.
  // EN: Closes the modal by removing it from the DOM.
  function closeModal(overlay) {
    if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
  }

  // ES: Crea un campo de formulario según la metadata recibida.
  // EN: Creates a form field from the received metadata.
  function fieldNode(field, values) {
    const wrapper = el("div", { className: "modal-input-group" }, []);
    const label = el("label", { className: "modal-prefix" }, [field.label || field.key]);
    wrapper.appendChild(label);

    if (field.readonly) {
      const span = el("span", { className: "modal-input" }, [valueToText(field.value) || t("common.empty_dash")]);
      values.set(field.key, () => field.value);
      wrapper.appendChild(span);
      return wrapper;
    }

    if (field.type === "object_multiselect" || field.key === "content") {
      wrapper.appendChild(contentChipEditor(field, values));
      return wrapper;
    }

    if (field.type === "select_dynamic") {
      wrapper.appendChild(selectDynamicChipEditor(field, values));
      return wrapper;
    }

    if (field.type === "checkbox") {
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = field.value === true || field.value === "true" || field.value === field.checkedValue;
      values.set(field.key, () => checkbox.checked ? (field.checkedValue ?? "true") : (field.uncheckedValue ?? "false"));
      wrapper.appendChild(checkbox);
      return wrapper;
    }

    if (field.type === "select_list") {
      const select = document.createElement("select");
      select.className = "modal-input";
      const currentValue = valueToText(field.value);
      if (currentValue) {
        const currentOption = document.createElement("option");
        currentOption.value = currentValue;
        currentOption.textContent = currentValue;
        currentOption.selected = true;
        select.appendChild(currentOption);
      }
      const loadingOption = document.createElement("option");
      loadingOption.value = "";
      loadingOption.textContent = t("common.loading");
      select.appendChild(loadingOption);
      loadSelectListOptions(field.selectList).then(options => {
        const selected = select.value;
        while (select.firstChild) select.removeChild(select.firstChild);
        const emptyOption = document.createElement("option");
        emptyOption.value = "";
        emptyOption.textContent = " --- ";
        select.appendChild(emptyOption);
        options.forEach(opt => {
          const option = document.createElement("option");
          option.value = String(opt.value);
          option.textContent = String(opt.label);
          if (String(opt.value) === selected || String(opt.value) === currentValue) option.selected = true;
          select.appendChild(option);
        });
      }).catch(error => {
        while (select.firstChild) select.removeChild(select.firstChild);
        const option = document.createElement("option");
        option.value = currentValue;
        option.textContent = error && error.message ? error.message : String(error);
        select.appendChild(option);
      });
      values.set(field.key, () => select.value);
      wrapper.appendChild(select);
      return wrapper;
    }

    if (field.type === "select" && Array.isArray(field.options)) {
      const select = document.createElement("select");
      select.className = "modal-input";
      field.options.forEach(opt => {
        const option = document.createElement("option");
        option.value = String(opt);
        option.textContent = opt === "" ? " --- " : String(opt);
        if (String(opt) === valueToText(field.value)) option.selected = true;
        select.appendChild(option);
      });
      values.set(field.key, () => select.value);
      wrapper.appendChild(select);
      return wrapper;
    }

    const input = document.createElement("input");
    input.type = "text";
    input.name = field.key;
    input.value = valueToText(field.value);
    input.className = "modal-input";
    values.set(field.key, () => input.value);
    wrapper.appendChild(input);
    return wrapper;
  }

  // ES: Abre un modal de edición con campos y botones Guardar/Cancelar.
  // EN: Opens an edit modal with fields and Save/Cancel buttons.
  function openFormModal(options) {
    // ES: Cada apertura consulta fuentes dinámicas actuales; evita Alias/interfaces obsoletos.
    // EN: Every opening queries current dynamic sources; prevents stale aliases/interfaces.
    objectSearchCache.clear();
    selectListCache.clear();
    tooltipCache.clear();

    const values = new Map();
    // ES: Contexto oculto para claves técnicas como uuid; no se renderiza como campo.
    // EN: Hidden context for technical keys like uuid; it is not rendered as a field.
    const context = options.context || {};
    const overlay = el("div", { className: "modal-overlay", role: "dialog", "aria-label": options.title || t("common.edit") }, []);
    const modal = el("div", { className: "modal-window" }, []);
    const title = el("h3", {}, [options.title || t("common.edit")]);
    const form = document.createElement("form");

    (options.fields || []).forEach(field => form.appendChild(fieldNode(field, values)));

    const actions = el("div", { className: "modal-actions" }, []);
    const errorBox = el("div", { className: "pf-alert error" }, []);
    errorBox.style.display = "none";
    const saveBtn = el("button", { className: "button_save", type: "button" }, [t("common.save")]);
    const cancelBtn = el("button", { className: "modal-button cancel", type: "button" }, [t("common.cancel")]);

    // ES: Muestra errores de operaciones API sin cerrar el modal.
    // EN: Shows API operation errors without closing the modal.
    function showError(error) {
      errorBox.textContent = error && error.message ? error.message : String(error || "error");
      errorBox.style.display = "block";
    }

    // ES: Lee payload actual del formulario modal.
    // EN: Reads the current payload from the modal form.
    function readPayload() {
      const payload = {};
      values.forEach((reader, key) => { payload[key] = reader(); });
      return payload;
    }

    saveBtn.addEventListener("click", async () => {
      try {
        saveBtn.disabled = true;
        if (typeof options.onSave === "function") await options.onSave(readPayload(), context);
        closeModal(overlay);
      } catch (error) {
        showError(error);
      } finally {
        saveBtn.disabled = false;
      }
    });

    cancelBtn.addEventListener("click", () => closeModal(overlay));
    overlay.addEventListener("click", event => {
      if (event.target === overlay) closeModal(overlay);
    });

    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    form.appendChild(errorBox);
    form.appendChild(actions);
    modal.appendChild(title);
    modal.appendChild(form);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    return overlay;
  }

  // ES: Abre una confirmación destructiva independiente del formulario de edición.
  // EN: Opens a destructive confirmation independent from the edit form.
  function openConfirmModal(options) {
    const overlay = el("div", { className: "modal-overlay", role: "dialog", "aria-label": options.title || t("common.delete_confirm_title") }, []);
    const modal = el("div", { className: "modal-window" }, []);
    const title = el("h3", {}, [options.title || t("common.delete_confirm_title")]);
    const message = el("p", { className: "pf-muted" }, [options.message || ""]);
    const details = el("div", { className: "pf-delete-confirm-details" },
      (options.details || []).map(item => el("div", { className: "pf-delete-confirm-detail-line" }, [
        el("span", { className: "table-readonly-chip" }, [String(item.label || "")]),
        el("span", {}, [` ${String(item.value || "")}${String(item.suffix || "")}`]),
      ])));
    const actions = el("div", { className: "modal-actions" }, []);
    const errorBox = el("div", { className: "pf-alert error" }, []);
    errorBox.style.display = "none";
    const confirmBtn = el("button", { className: "button_delete", type: "button" }, [t("common.delete")]);
    const cancelBtn = el("button", { className: "modal-button cancel", type: "button" }, [t("common.cancel")]);
    let busy = false;

    // ES: Ejecuta la operación destructiva sólo tras confirmación explícita.
    // EN: Executes the destructive operation only after explicit confirmation.
    confirmBtn.addEventListener("click", async () => {
      try {
        busy = true;
        confirmBtn.disabled = true;
        cancelBtn.disabled = true;
        if (typeof options.onConfirm === "function") await options.onConfirm();
        closeModal(overlay);
      } catch (error) {
        errorBox.textContent = error && error.message ? error.message : String(error || "error");
        errorBox.style.display = "block";
      } finally {
        busy = false;
        confirmBtn.disabled = false;
        cancelBtn.disabled = false;
      }
    });

    cancelBtn.addEventListener("click", () => {
      if (!busy) closeModal(overlay);
    });
    overlay.addEventListener("click", event => {
      if (event.target === overlay && !busy) closeModal(overlay);
    });

    actions.appendChild(confirmBtn);
    actions.appendChild(cancelBtn);
    modal.appendChild(title);
    modal.appendChild(message);
    modal.appendChild(details);
    modal.appendChild(errorBox);
    modal.appendChild(actions);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    return overlay;
  }

  // ES: Abre un modal sólo lectura con todos los valores de una celda.
  // EN: Opens a read-only modal with all values from one cell.
  function openReadOnlyListModal(options) {
    const overlay = el("div", { className: "modal-overlay", role: "dialog", "aria-label": options.title || "more" }, []);
    const modal = el("div", { className: "modal-window" }, []);
    const title = el("h3", {}, [options.title || "more"]);
    const list = el("div", { className: "readonly-list-modal" }, []);

    (options.items || []).forEach(item => {
      const text = item && typeof item === "object" ? item.text : String(item || "");
      const tooltip = item && typeof item === "object" ? item.title : "";
      const chip = el("span", { className: "table-readonly-chip" }, [text]);
      if (tooltip) chip.title = tooltip;
      list.appendChild(chip);
    });

    const actions = el("div", { className: "modal-actions" }, []);
    const closeBtn = el("button", { className: "modal-button cancel", type: "button" }, [t("common.cancel")]);
    closeBtn.addEventListener("click", () => closeModal(overlay));
    overlay.addEventListener("click", event => {
      if (event.target === overlay) closeModal(overlay);
    });
    actions.appendChild(closeBtn);
    modal.appendChild(title);
    modal.appendChild(list);
    modal.appendChild(actions);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    return overlay;
  }

  // ES: API pública del modal común.
  // EN: Public API for the common modal.
  window.PraesidiumModal = { openFormModal, openConfirmModal, openReadOnlyListModal };
})();
