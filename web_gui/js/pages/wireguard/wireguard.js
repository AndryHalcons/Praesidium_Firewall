/*
 * ES: Dispatcher WireGuard por endpoint FastAPI real usando la tabla genérica.
 * EN: WireGuard dispatcher by real FastAPI endpoint using the generic table.
 */
(() => {
  "use strict";

  // ES: Cada sección conserva metadata independiente y comparte el renderer central.
  // EN: Each section keeps independent metadata and shares the central renderer.
  const renderers = {
    wireguard_site_to_site: window.PraesidiumGenericTable.createRenderer({
      section: "wireguard_site_to_site",
      basePath: "/js/pages/wireguard",
    }),
    wireguard_server: window.PraesidiumGenericTable.createRenderer({
      section: "wireguard_server",
      basePath: "/js/pages/wireguard",
    }),
    wireguard_clients: window.PraesidiumGenericTable.createRenderer({
      section: "wireguard_clients",
      basePath: "/js/pages/wireguard",
    }),
  };

  // ES: Renderiza únicamente la sección solicitada por registry.js.
  // EN: Renders only the section requested by registry.js.
  async function render(container, pageId) {
    const renderer = renderers[pageId];
    if (!renderer) throw new Error(`unknown_wireguard_page:${pageId}`);
    await renderer(container);
  }

  window.PraesidiumWireGuardPage = { render };
})();
