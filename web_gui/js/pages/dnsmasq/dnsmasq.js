/*
 * ES: Renderiza cada sección Dnsmasq en una página independiente mediante generic_table.js.
 * EN: Renders each Dnsmasq section on an independent page through generic_table.js.
 */
(() => {
  "use strict";

  const renderScopes = window.PraesidiumGenericTable.createRenderer({
    section: "dnsmasq_scopes",
    basePath: "/js/pages/dnsmasq",
  });

  const renderReservations = window.PraesidiumGenericTable.createRenderer({
    section: "dnsmasq_reservations",
    basePath: "/js/pages/dnsmasq",
  });

  window.PraesidiumDnsmasqPage = { renderScopes, renderReservations };
})();
