/*
 * ES: Página WebGUI Nftables para PREROUTING.
 * EN: Nftables WebGUI page for PREROUTING.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "nftables_prerouting",
    basePath: "/js/pages/nftables",
  });

  // ES: API pública del módulo Nftables PREROUTING.
  // EN: Public API for the Nftables PREROUTING module.
  window.PraesidiumNftablesPreroutingPage = { render };
})();
