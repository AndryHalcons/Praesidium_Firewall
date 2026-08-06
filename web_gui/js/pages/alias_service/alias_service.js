/*
 * ES: Página WebGUI de la sección alias_service.
 * EN: WebGUI page for the alias_service section.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "alias_service",
    basePath: "/js/pages/alias_service",
  });

  // ES: API pública del módulo alias_service.
  // EN: Public API for the alias_service module.
  window.PraesidiumAliasServicePage = { render };
})();
