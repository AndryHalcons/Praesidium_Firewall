/*
 * ES: Página WebGUI Nftables para output.
 * EN: Nftables WebGUI page for output.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "nftables_output",
    basePath: "/js/pages/nftables",
  });

  // ES: API pública del módulo Nftables output.
  // EN: Public API for the Nftables output module.
  window.PraesidiumNftablesOutputPage = { render };
})();
