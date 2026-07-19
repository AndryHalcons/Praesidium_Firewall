/*
 * ES: Página WebGUI de la sección login_attempts.
 * EN: WebGUI page for the login_attempts section.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "login_attempts",
    basePath: "/js/pages/login_attempts",
  });

  // ES: API pública del módulo login_attempts.
  // EN: Public API for the login_attempts module.
  window.PraesidiumLoginAttemptsPage = { render };
})();
