/*
 * ES: Página WebGUI de la sección alias_address.
 * EN: WebGUI page for the alias_address section.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "alias_address",
    basePath: "/js/pages/alias_address",
  });

  // ES: API pública del módulo alias_address.
  // EN: Public API for the alias_address module.
  window.PraesidiumAliasAddressPage = { render };
})();
