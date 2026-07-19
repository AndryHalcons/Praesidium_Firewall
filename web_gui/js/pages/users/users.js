/*
 * ES: Página WebGUI de Users usando generic_table para la tabla y un Add local por contraseña inicial.
 * EN: Users WebGUI page using generic_table for the table and a local Add for the initial password.
 */
(() => {
  "use strict";

  const { t } = window.PraesidiumUi;
  const { el, replaceChildren } = window.PraesidiumDom;

  // ES: Users reutiliza generic_table para listado, edición y borrado sin tocar core.
  // EN: Users reuses generic_table for listing, editing, and deleting without touching core.
  const tableRenderer = window.PraesidiumGenericTable.createRenderer({
    section: "table_users",
    basePath: "/js/pages/users",
    formsPath: "/js/pages/users/forms_table_users.json",
    structurePath: "/js/pages/users/structure_table_users.json",
    commandsPath: "/js/pages/users/users_commands_api.json",
  });

  // ES: Cierra el modal local de creación retirándolo del DOM.
  // EN: Closes the local create modal by removing it from the DOM.
  function closeCreateModal(overlay) {
    if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
  }

  // ES: Crea un grupo label/input seguro para el modal local.
  // EN: Creates a safe label/input group for the local modal.
  function inputGroup(labelKey, name, type = "text") {
    const wrapper = el("div", { className: "modal-input-group" }, []);
    const label = el("label", { className: "modal-prefix" }, [t(labelKey)]);
    const input = document.createElement("input");
    input.type = type;
    input.name = name;
    input.className = "modal-input";
    input.autocomplete = type === "password" ? "new-password" : "off";
    wrapper.appendChild(label);
    wrapper.appendChild(input);
    return { wrapper, input };
  }

  // ES: Crea un grupo label/select seguro para roles e idiomas permitidos.
  // EN: Creates a safe label/select group for allowed roles and languages.
  function selectGroup(labelKey, name, options) {
    const wrapper = el("div", { className: "modal-input-group" }, []);
    const label = el("label", { className: "modal-prefix" }, [t(labelKey)]);
    const select = document.createElement("select");
    select.name = name;
    select.className = "modal-input";
    options.forEach(value => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      select.appendChild(option);
    });
    wrapper.appendChild(label);
    wrapper.appendChild(select);
    return { wrapper, select };
  }

  // ES: Crea un grupo checkbox para forzar cambio en el primer login.
  // EN: Creates a checkbox group to force password change on first login.
  function checkboxGroup(labelKey, name) {
    const wrapper = el("div", { className: "modal-input-group" }, []);
    const label = el("label", { className: "modal-prefix" }, [t(labelKey)]);
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.name = name;
    checkbox.checked = true;
    wrapper.appendChild(label);
    wrapper.appendChild(checkbox);
    return { wrapper, checkbox };
  }

  // ES: Abre el modal local de Añadir usuario; password sólo existe en este flujo.
  // EN: Opens the local Add user modal; password exists only in this flow.
  function openCreateUserModal(refresh) {
    const overlay = el("div", { className: "modal-overlay", role: "dialog", "aria-label": t("users.add_title") }, []);
    const modal = el("div", { className: "modal-window" }, []);
    const title = el("h3", {}, [t("users.add_title")]);
    const form = document.createElement("form");
    const username = inputGroup("users.user_name", "user_name");
    const password = inputGroup("users.user_pass", "user_pass", "password");
    const role = selectGroup("users.user_role", "user_role", ["admin", "viewer"]);
    const language = selectGroup("users.user_language", "user_language", ["english", "espanol"]);
    const forceChange = checkboxGroup("users.force_password_change", "force_password_change");
    const errorBox = el("div", { className: "pf-alert error" }, []);
    errorBox.style.display = "none";
    const actions = el("div", { className: "modal-actions" }, []);
    const saveBtn = el("button", { className: "button_save", type: "button" }, [t("common.save")]);
    const cancelBtn = el("button", { className: "modal-button cancel", type: "button" }, [t("common.cancel")]);

    function showError(error) {
      errorBox.textContent = error && error.message ? error.message : String(error || "error");
      errorBox.style.display = "block";
    }

    saveBtn.addEventListener("click", async () => {
      try {
        saveBtn.disabled = true;
        const payload = {
          user_name: username.input.value.trim(),
          user_pass: password.input.value,
          user_role: role.select.value,
          user_language: language.select.value,
          force_password_change: forceChange.checkbox.checked ? "true" : "false",
        };
        await window.PraesidiumApi.request("/users/", { method: "POST", body: JSON.stringify(payload) });
        closeCreateModal(overlay);
        await refresh();
      } catch (error) {
        showError(error);
      } finally {
        saveBtn.disabled = false;
      }
    });

    cancelBtn.addEventListener("click", () => closeCreateModal(overlay));
    overlay.addEventListener("click", event => {
      if (event.target === overlay) closeCreateModal(overlay);
    });

    [username, password, role, language, forceChange].forEach(field => form.appendChild(field.wrapper));
    actions.appendChild(saveBtn);
    actions.appendChild(cancelBtn);
    form.appendChild(errorBox);
    form.appendChild(actions);
    modal.appendChild(title);
    modal.appendChild(form);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    username.input.focus();
  }

  // ES: Inserta el botón Añadir local en el toolbar generado por generic_table.
  // EN: Inserts the local Add button into the toolbar generated by generic_table.
  function ensureLocalAddButton(host) {
    const toolbar = host.querySelector(".pf-table-toolbar");
    if (!toolbar || toolbar.querySelector("[data-users-add]")) return;
    const addButton = el("button", { className: "button_add", type: "button" }, [t("common.add")]);
    addButton.setAttribute("data-users-add", "true");
    addButton.addEventListener("click", () => openCreateUserModal(() => render(host)));
    toolbar.appendChild(addButton);
  }

  // ES: Renderiza tabla genérica y repone el Add local tras refrescos internos.
  // EN: Renders the generic table and restores the local Add after internal refreshes.
  async function render(container) {
    const host = container.hasAttribute && container.hasAttribute("data-users-host") ? container : document.createElement("div");
    host.setAttribute("data-users-host", "true");
    if (host !== container) replaceChildren(container, [host]);
    let scheduled = false;
    const observer = new MutationObserver(() => {
      if (scheduled) return;
      scheduled = true;
      queueMicrotask(() => {
        scheduled = false;
        ensureLocalAddButton(host);
      });
    });
    observer.observe(host, { childList: true, subtree: true });
    await tableRenderer(host);
    ensureLocalAddButton(host);
  }

  // ES: API pública del módulo Users para registry.js.
  // EN: Public Users module API for registry.js.
  window.PraesidiumUsersPage = { render };
})();
