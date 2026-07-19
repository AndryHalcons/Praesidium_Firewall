/*
 * ES: Página WebGUI Nftables para POSTROUTING.
 * EN: Nftables WebGUI page for POSTROUTING.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "nftables_postrouting",
    basePath: "/js/pages/nftables",
  });

  // ES: API pública del módulo Nftables POSTROUTING.
  // EN: Public API for the Nftables POSTROUTING module.
  window.PraesidiumNftablesPostroutingPage = { render };
})();
