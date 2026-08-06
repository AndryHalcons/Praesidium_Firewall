/*
 * ES: Página WebGUI de Services usando generic_table.js.
 * EN: Services WebGUI page using generic_table.js.
 */
(() => {
  "use strict";

  // ES: Services usa exclusivamente la tabla genérica metadata-driven.
  // EN: Services exclusively uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "services",
    basePath: "/js/pages/services",
    structurePath: "/js/pages/services/structure_table_services.json",
  });

  // ES: API pública del módulo Services para el registro de páginas.
  // EN: Public Services module API for the page registry.
  window.PraesidiumServicesPage = { render };
})();
