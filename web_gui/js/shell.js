/*
 * ES: Shell visual del WebGUI: menús, cambio de páginas, cabecera de usuario y logout.
 * EN: WebGUI visual shell: menus, page navigation, user header, and logout.
 */
(() => {
  "use strict";

  // ES: Atajo local para consultar elementos del layout principal.
  // EN: Local shortcut to query main layout elements.
  function qs(selector) {
    return document.querySelector(selector);
  }

  // ES: Atajo local al traductor global.
  // EN: Local shortcut to the global translator.
  function t(key, params = {}) {
    return PraesidiumI18n.t(key, params);
  }

  // ES: Guarda la función de limpieza devuelta por la página activa (intervalos, charts, listeners).
  // EN: Stores cleanup returned by the active page (intervals, charts, listeners).
  let activePageCleanup = null;

  // ES: Limpia intervalos/gráficos de la página anterior antes de navegar.
  // EN: Cleans intervals/charts from the previous page before navigation.
  function runActivePageCleanup() {
    if (typeof activePageCleanup !== "function") return;
    const cleanup = activePageCleanup;
    activePageCleanup = null;
    try {
      cleanup();
    } catch (err) {
      console.warn(t("app.page_cleanup_failed"), err);
    }
  }

  // ES: Resuelve el texto visible de un menú desde su labelKey i18n.
  // EN: Resolves visible menu text from its i18n labelKey.
  function labelFor(item) {
    return t(item.labelKey || item.id || "common.unknown");
  }

  // ES: Crea un enlace de menú y centraliza el comportamiento de navegación/logout.
  // EN: Creates a menu link and centralizes navigation/logout behavior.
  function makeLink(page) {
    // ES: a es el enlace real que se inserta en top-menu o sidebar.
    // EN: a is the real link inserted into top-menu or sidebar.
    const a = document.createElement("a");
    a.href = "#";
    a.dataset.page = page.id;
    a.textContent = labelFor(page);
    a.addEventListener("click", event => {
      event.preventDefault();
      if (page.id === "logout") {
        window.PraesidiumShell.logout();
        return;
      }
      window.PraesidiumShell.navigate(page.id);
    });
    return a;
  }

  // ES: Construye menús desde app-state usando claves i18n, no texto hardcodeado.
  // EN: Builds menus from app-state using i18n keys, not hardcoded text.
  function renderMenus() {
    // ES: top y sidebar son contenedores vaciados y reconstruidos tras cambio de idioma/login.
    // EN: top and sidebar are containers cleared and rebuilt after language/login changes.
    const top = qs("#top-menu");
    const sidebar = qs("#sidebar");
    top.replaceChildren();
    sidebar.replaceChildren();
    PraesidiumState.MENU.top.forEach(page => top.appendChild(makeLink(page)));
    PraesidiumState.MENU.sidebar.forEach((section, index) => {
      // ES: details crea cada grupo desplegable del menú lateral.
      // EN: details creates each expandable sidebar group.
      const details = document.createElement("details");
      if (index === 0) details.open = true;
      // ES: summary es el título visible de la sección lateral.
      // EN: summary is the visible title for the sidebar section.
      const summary = document.createElement("summary");
      summary.textContent = labelFor(section);
      details.appendChild(summary);
      section.pages.forEach(page => details.appendChild(makeLink(page)));
      sidebar.appendChild(details);
    });
  }

  // ES: Marca visualmente el enlace correspondiente a la página activa.
  // EN: Visually marks the link corresponding to the active page.
  function markActive(pageId) {
    document.querySelectorAll("a[data-page]").forEach(link => {
      link.classList.toggle("active", link.dataset.page === pageId);
    });
  }

  // ES: Navegación SPA: limpia página anterior, renderiza nueva y guarda cleanup.
  // EN: SPA navigation: cleans previous page, renders new one, and stores cleanup.
  async function navigate(pageId) {
    runActivePageCleanup();
    PraesidiumState.state.activePage = pageId;
    markActive(pageId);
    // ES: main es la zona central donde pages.js inyecta cada pantalla.
    // EN: main is the central area where pages.js injects each screen.
    const main = qs("#main-content");
    // ES: cleanup puede ser una función si la página creó timers o gráficos.
    // EN: cleanup can be a function if the page created timers or charts.
    const cleanup = await PraesidiumPages.render(main, pageId);
    activePageCleanup = typeof cleanup === "function" ? cleanup : null;
    main.focus({ preventScroll: true });
  }

  // ES: Muestra login y oculta app; se usa al arrancar sin token o expirar sesión.
  // EN: Shows login and hides app; used on startup without token or expired session.
  function showLogin() {
    runActivePageCleanup();
    PraesidiumI18n.apply(document);
    qs("#app-view").classList.add("hidden");
    qs("#login-view").classList.remove("hidden");
    qs("#login-username").focus();
  }

  // ES: Muestra el shell autenticado después de validar /auth/me.
  // EN: Shows the authenticated shell after validating /auth/me.
  function showApp() {
    qs("#login-view").classList.add("hidden");
    qs("#app-view").classList.remove("hidden");
  }

  // ES: Carga el idioma del usuario y pinta cabecera después de /auth/me.
  // EN: Loads the user language and paints the header after /auth/me.
  async function paintUser(user) {
    PraesidiumState.state.user = user;
    await PraesidiumI18n.setLanguage(user.user_language);
    qs("#welcome-text").textContent = t("app.welcome", { user: user.user_name });
    qs("#user-role").textContent = user.user_role || t("common.empty_dash");
    qs("#user-language").textContent = user.user_language || t("common.empty_dash");
  }

  // ES: Valida token actual, carga usuario/idioma/menús y abre la página activa.
  // EN: Validates current token, loads user/language/menus, and opens the active page.
  async function bootstrapAuthenticated() {
    const user = await PraesidiumApi.request("/auth/me");
    await paintUser(user);
    qs("#api-state").textContent = t("app.api_state_connected");
    renderMenus();
    showApp();
    await navigate(PraesidiumState.state.activePage || "dashboard");
  }

  // ES: Cierra sesión, limpia estado local y vuelve a inglés/login.
  // EN: Logs out, clears local state, and returns to English/login.
  async function logout() {
    runActivePageCleanup();
    await PraesidiumApi.logout();
    PraesidiumState.state.user = null;
    await PraesidiumI18n.setLanguage("english");
    showLogin();
  }

  // ES: Evento emitido por api-client.js cuando FastAPI responde 401.
  // EN: Event emitted by api-client.js when FastAPI returns 401.
  window.addEventListener("praesidium:auth-expired", showLogin);

  // ES: Delegación para botones genéricos que piden navegar a una página.
  // EN: Delegation for generic buttons requesting navigation to a page.
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-page-target]");
    if (!button) return;
    event.preventDefault();
    navigate(button.dataset.pageTarget);
  });

  // ES: API pública del shell para app.js, consola de QA y eventos delegados.
  // EN: Public shell API for app.js, QA console, and delegated events.
  window.PraesidiumShell = {
    navigate,
    logout,
    showLogin,
    showApp,
    bootstrapAuthenticated,
    renderMenus,
  };
})();
