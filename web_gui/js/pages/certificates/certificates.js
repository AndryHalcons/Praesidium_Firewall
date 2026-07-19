/*
 * ES: Página WebGUI de Certificates sobre la tabla genérica y subida multipart segura.
 * EN: Certificates WebGUI page built on the generic table and secure multipart upload.
 */
(() => {
  "use strict";

  const { t } = window.PraesidiumUi;
  const { el, replaceChildren } = window.PraesidiumDom;
  const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

  // ES: Reutiliza listado, filtros, confirmación de borrado y descargas del renderer común.
  // EN: Reuses listing, filters, delete confirmation, and downloads from the common renderer.
  const tableRenderer = window.PraesidiumGenericTable.createRenderer({
    section: "certificates",
    basePath: "/js/pages/certificates",
    structurePath: "/js/pages/certificates/structure_table_certificates.json",
  });

  // ES: Muestra un resultado de subida sin interpretar HTML procedente del backend.
  // EN: Shows an upload result without interpreting backend-provided HTML.
  function setUploadStatus(box, message, isError = false) {
    box.textContent = String(message || "");
    box.className = isError ? "pf-alert error" : "pf-alert";
    box.hidden = !message;
  }

  // ES: Oculta acciones mutables para viewers; FastAPI sigue siendo la autoridad de permisos.
  // EN: Hides mutable actions for viewers; FastAPI remains the permission authority.
  function applyRoleVisibility(host) {
    if (window.PraesidiumState.isAdmin()) return;
    host.querySelectorAll(".button_delete, .button_download").forEach(button => button.remove());
  }

  // ES: Añade el control de subida al toolbar creado por generic_table, sólo para admin.
  // EN: Adds the upload control to the generic_table toolbar, for admins only.
  function ensureUploadControls(host) {
    applyRoleVisibility(host);
    if (!window.PraesidiumState.isAdmin()) return;
    const toolbar = host.querySelector(".pf-table-toolbar");
    if (!toolbar || toolbar.querySelector("[data-certificates-upload]")) return;

    const controls = el("div", { className: "pf-row-actions" }, []);
    controls.setAttribute("data-certificates-upload", "true");
    const label = el("label", { className: "pf-muted" }, [t("certificates.upload_label")]);
    const input = document.createElement("input");
    input.type = "file";
    input.className = "modal-input certificate-file-input";
    input.accept = ".pem,.key,.crt,.csr,.srl,.p12,.pfx,.der,.cer,.pkcs12";
    input.setAttribute("aria-label", t("certificates.upload_label"));
    const uploadButton = el("button", { className: "button_add", type: "button" }, [t("certificates.upload")]);
    const hint = el("span", { className: "pf-muted" }, [t("certificates.upload_hint")]);
    const statusBox = el("div", { className: "pf-alert" }, []);
    statusBox.hidden = true;

    // ES: La subida conserva el nombre original y delega validación criptográfica en FastAPI.
    // EN: Upload preserves the original name and delegates cryptographic validation to FastAPI.
    uploadButton.addEventListener("click", async () => {
      const file = input.files && input.files[0];
      if (!file) {
        setUploadStatus(statusBox, t("certificates.choose_file"), true);
        return;
      }
      if (file.size > MAX_UPLOAD_BYTES) {
        setUploadStatus(statusBox, t("certificates.file_too_large"), true);
        return;
      }
      try {
        uploadButton.disabled = true;
        input.disabled = true;
        setUploadStatus(statusBox, t("certificates.uploading"));
        await window.PraesidiumApi.upload("/certificates/upload", file);
        await tableRenderer(host);
        ensureUploadControls(host);
        const freshStatus = host.querySelector("[data-certificates-upload-status]");
        if (freshStatus) setUploadStatus(freshStatus, t("certificates.upload_success"));
      } catch (error) {
        setUploadStatus(statusBox, error && error.message ? error.message : String(error), true);
      } finally {
        uploadButton.disabled = false;
        input.disabled = false;
      }
    });

    statusBox.setAttribute("data-certificates-upload-status", "true");
    controls.appendChild(label);
    controls.appendChild(input);
    controls.appendChild(uploadButton);
    controls.appendChild(hint);
    toolbar.appendChild(controls);
    toolbar.parentNode.insertBefore(statusBox, toolbar.nextSibling);
  }

  // ES: Renderiza la tabla y reinserta controles propios después de refrescos internos.
  // EN: Renders the table and reinserts page controls after internal refreshes.
  async function render(container) {
    const host = document.createElement("div");
    replaceChildren(container, [host]);
    let scheduled = false;
    const observer = new MutationObserver(() => {
      if (scheduled) return;
      scheduled = true;
      queueMicrotask(() => {
        scheduled = false;
        ensureUploadControls(host);
      });
    });
    observer.observe(host, { childList: true, subtree: true });
    await tableRenderer(host);
    ensureUploadControls(host);
  }

  // ES: API pública consumida por registry.js.
  // EN: Public API consumed by registry.js.
  window.PraesidiumCertificatesPage = { render };
})();
