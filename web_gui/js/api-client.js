/*
 * ES: Cliente HTTP único para la sesión WebGUI. El Bearer de FastAPI no llega al navegador.
 * EN: Single HTTP client for the WebGUI session. The FastAPI Bearer never reaches the browser.
 */
(() => {
  "use strict";

  // ES: Estado de sesión no secreto. El token real vive en PHP, no en JavaScript.
  // EN: Non-secret session state. The real token lives in PHP, not in JavaScript.
  let sessionActive = false;

  // ES: CSRF visible para JS; protege mutaciones enviadas mediante cookie HttpOnly.
  // EN: JS-visible CSRF; protects mutations sent with the HttpOnly cookie.
  let csrfToken = "";

  // ES: Base de la capa PHP de sesión WebGUI.
  // EN: Base URL for the PHP WebGUI session layer.
  function sessionBase() {
    return `${window.location.origin}/session`;
  }

  // ES: Compatibilidad visual con el panel API: ya no se usa para guardar tokens.
  // EN: Visual compatibility with the API panel: it is no longer used for token storage.
  function defaultApiBase() {
    return sessionBase();
  }

  // ES: Indica si la sesión fue validada en esta carga de página.
  // EN: Indicates whether the session was validated during this page load.
  function hasToken() {
    return sessionActive;
  }

  // ES: Mantiene API pública antigua sin permitir persistir Bearer en navegador.
  // EN: Keeps the old public API without allowing Bearer persistence in the browser.
  function setToken(value) {
    sessionActive = Boolean(value);
  }

  // ES: Extrae CSRF de respuestas de login/me sin exponer secretos.
  // EN: Extracts CSRF from login/me responses without exposing secrets.
  function rememberSessionMetadata(payload) {
    if (payload && typeof payload === "object" && typeof payload.csrf_token === "string") {
      csrfToken = payload.csrf_token;
      sessionActive = true;
    }
  }

  // ES: Convierte errores FastAPI/PHP en mensaje corto para la UI.
  // EN: Converts FastAPI/PHP errors into a short UI message.
  function describeError(payload, status) {
    if (payload && typeof payload === "object") {
      const detail = payload.detail;
      if (typeof detail === "string") return detail;
      if (detail && typeof detail === "object") return detail.error_code || JSON.stringify(detail);
      if (Array.isArray(detail)) return detail.map(item => item.msg || JSON.stringify(item)).join("; ");
      return payload.error_code || payload.message || `HTTP ${status}`;
    }
    return payload || `HTTP ${status}`;
  }

  // ES: Ejecuta fetch JSON contra la capa PHP con cookies same-origin.
  // EN: Executes JSON fetch against the PHP layer with same-origin cookies.
  async function fetchJson(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!headers.has("Accept")) headers.set("Accept", "application/json");
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const method = String(options.method || "GET").toUpperCase();
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }

    const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();

    if (response.status === 401) {
      sessionActive = false;
      csrfToken = "";
      window.dispatchEvent(new CustomEvent("praesidium:auth-expired"));
    }
    if (!response.ok) {
      const error = new Error(describeError(payload, response.status));
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    rememberSessionMetadata(payload);
    return payload;
  }

  // ES: Login contra PHP; PHP habla con FastAPI y guarda Bearer server-side.
  // EN: Login against PHP; PHP talks to FastAPI and stores Bearer server-side.
  async function login(username, password) {
    return fetchJson(`${sessionBase()}/login.php`, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  }

  // ES: Proxy seguro para llamadas de API existentes. No envía Bearer desde JS.
  // EN: Secure proxy for existing API calls. It sends no Bearer from JS.
  async function request(path, options = {}) {
    if (path === "/auth/me") {
      return fetchJson(`${sessionBase()}/me.php`, { method: "GET" });
    }
    const encodedPath = encodeURIComponent(path);
    return fetchJson(`${sessionBase()}/proxy.php?path=${encodedPath}`, options);
  }

  // ES: Extrae un nombre seguro de Content-Disposition sin aceptar rutas ni controles.
  // EN: Extracts a safe filename from Content-Disposition without accepting paths or controls.
  function responseFilename(disposition) {
    const value = String(disposition || "");
    const utf8 = value.match(/filename\*=UTF-8''([^;]+)/i);
    const basic = value.match(/filename="([^"]+)"|filename=([^;]+)/i);
    let filename = "download";
    try {
      if (utf8) filename = decodeURIComponent(utf8[1]);
      else if (basic) filename = basic[1] || basic[2] || filename;
    } catch (_) {
      filename = "download";
    }
    filename = String(filename).trim().replace(/[\\/\u0000-\u001f\u007f]/g, "_").slice(0, 180);
    return filename || "download";
  }

  // ES: Descarga un binario autenticado mediante PHP sin exponer el Bearer al navegador.
  // EN: Downloads an authenticated binary through PHP without exposing the Bearer to the browser.
  async function download(path) {
    const cleanPath = String(path || "");
    if (!cleanPath.startsWith("/") || cleanPath.startsWith("//") || cleanPath.includes("://") || cleanPath.includes("..") || cleanPath.includes("\\")) {
      throw new Error("INVALID_API_PATH");
    }
    const response = await fetch(`${sessionBase()}/download.php?path=${encodeURIComponent(cleanPath)}`, {
      method: "GET",
      headers: { Accept: "application/octet-stream,image/png,application/zip,application/json" },
      credentials: "same-origin",
      cache: "no-store",
    });
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    if (response.status === 401) {
      sessionActive = false;
      csrfToken = "";
      window.dispatchEvent(new CustomEvent("praesidium:auth-expired"));
    }
    if (!response.ok) {
      let payload;
      try {
        payload = contentType.includes("application/json") ? await response.json() : await response.text();
      } catch (_) {
        payload = `HTTP ${response.status}`;
      }
      const error = new Error(describeError(payload, response.status));
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    const blob = await response.blob();
    const filename = responseFilename(response.headers.get("content-disposition"));
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.hidden = true;
    document.body.appendChild(anchor);
    try {
      anchor.click();
    } finally {
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
    }
    return { filename, contentType, size: blob.size };
  }

  // ES: Sube un archivo mediante el endpoint PHP dedicado sin exponer el Bearer.
  // EN: Uploads a file through the dedicated PHP endpoint without exposing the Bearer.
  async function upload(path, file) {
    const cleanPath = String(path || "");
    if (!cleanPath.startsWith("/") || cleanPath.startsWith("//") || cleanPath.includes("://") || cleanPath.includes("..") || cleanPath.includes("\\")) {
      throw new Error("INVALID_API_PATH");
    }
    if (!(file instanceof Blob) || typeof file.name !== "string" || !file.name) {
      throw new Error("INVALID_UPLOAD_FILE");
    }
    return fetchJson(`${sessionBase()}/upload.php?path=${encodeURIComponent(cleanPath)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-File-Name": encodeURIComponent(file.name),
      },
      body: file,
    });
  }

  // ES: Logout de sesión PHP; limpia cookie/sesión server-side.
  // EN: PHP session logout; clears server-side cookie/session.
  async function logout() {
    try {
      await fetchJson(`${sessionBase()}/logout.php`, { method: "POST", body: "{}" });
    } finally {
      sessionActive = false;
      csrfToken = "";
    }
  }

  // ES: API pública. No expone token crudo porque no existe en JS.
  // EN: Public API. It exposes no raw token because none exists in JS.
  window.PraesidiumApi = {
    defaultApiBase,
    setApiBase() {
      // ES: La capa PHP es fija y same-origin; se ignoran bases API arbitrarias.
      // EN: The PHP layer is fixed and same-origin; arbitrary API bases are ignored.
    },
    hasToken,
    setToken,
    request,
    download,
    upload,
    login,
    logout,
  };
})();
