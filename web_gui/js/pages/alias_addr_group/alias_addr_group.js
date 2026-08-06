/*
 * ES: Página WebGUI de la sección alias_addr_group.
 * EN: WebGUI page for the alias_addr_group section.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "alias_addr_group",
    basePath: "/js/pages/alias_addr_group",
  });

  // ES: API pública del módulo alias_addr_group.
  // EN: Public API for the alias_addr_group module.
  window.PraesidiumAliasAddrGroupPage = { render };
})();
