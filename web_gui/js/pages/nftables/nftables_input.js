/*
 * ES: Página WebGUI Nftables para input.
 * EN: Nftables WebGUI page for input.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "nftables_input",
    basePath: "/js/pages/nftables",
  });

  // ES: API pública del módulo Nftables input.
  // EN: Public API for the Nftables input module.
  window.PraesidiumNftablesInputPage = { render };
})();
