/*
 * ES: Punto de entrada del WebGUI: inicializa idioma, login, API settings y sesión existente.
 * EN: WebGUI entry point: initializes language, login, API settings, and existing session.
 */
(() => {
  "use strict";

  // ES: Atajo local para seleccionar un único nodo del DOM.
  // EN: Local shortcut to select a single DOM node.
  function qs(selector) {
    return document.querySelector(selector);
  }

  // ES: Atajo local al traductor global para mantener el código legible.
  // EN: Local shortcut to the global translator to keep code readable.
  function t(key, params = {}) {
    return PraesidiumI18n.t(key, params);
  }

  // ES: Pinta mensajes bajo el formulario de login/API settings.
  // EN: Paints messages under the login/API settings form.
  function setLoginError(message) {
    qs("#login-error").textContent = message || "";
  }

  // ES: Inicializa el panel opcional para cambiar la URL base de FastAPI durante pruebas.
  // EN: Initializes the optional panel to change FastAPI base URL during tests.
  function initApiSettings() {
    // ES: panel contiene input y botón para configurar una API alternativa.
    // EN: panel contains input and button to configure an alternate API.
    const panel = qs("#api-settings");
    // ES: input muestra/edita la URL base que se guardará en localStorage.
    // EN: input shows/edits the base URL that will be stored in localStorage.
    const input = qs("#api-base-input");
    input.value = PraesidiumApi.defaultApiBase();
    qs("#api-settings-toggle").addEventListener("click", () => panel.classList.toggle("hidden"));
    qs("#api-base-save").addEventListener("click", () => {
      PraesidiumApi.setApiBase(input.value.trim());
      setLoginError(t("app.api_base_saved"));
    });
  }

  // ES: Conecta el formulario de login con FastAPI y arranca el shell autenticado.
  // EN: Connects the login form with FastAPI and starts the authenticated shell.
  function initLoginForm() {
    qs("#login-form").addEventListener("submit", async event => {
      event.preventDefault();
      setLoginError("");
      // ES: username/password son las credenciales introducidas por el usuario.
      // EN: username/password are the credentials entered by the user.
      const username = qs("#login-username").value.trim();
      const password = qs("#login-password").value;
      try {
        await PraesidiumApi.login(username, password);
        await PraesidiumShell.bootstrapAuthenticated();
      } catch (err) {
        PraesidiumApi.setToken("");
        setLoginError(err.message || t("app.login_failed"));
      }
    });
  }

  // ES: Secuencia inicial: idioma inglés, eventos, token en memoria y vista login/app.
  // EN: Startup sequence: English language, events, in-memory token, and login/app view.
  async function init() {
    await PraesidiumI18n.init();
    PraesidiumI18n.apply(document);
    initApiSettings();
    initLoginForm();
    try {
      await PraesidiumShell.bootstrapAuthenticated();
    } catch (err) {
      PraesidiumApi.setToken("");
      PraesidiumShell.showLogin();
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
