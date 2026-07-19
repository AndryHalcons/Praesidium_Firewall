/*
 * ES: Página WebGUI de la sección alias_service_group.
 * EN: WebGUI page for the alias_service_group section.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "alias_service_group",
    basePath: "/js/pages/alias_service_group",
  });

  // ES: API pública del módulo alias_service_group.
  // EN: Public API for the alias_service_group module.
  window.PraesidiumAliasServiceGroupPage = { render };
})();
