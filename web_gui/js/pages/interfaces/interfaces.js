/*
 * ES: Páginas WebGUI de Interfaces usando generic_table.js.
 * EN: Interface WebGUI pages using generic_table.js.
 */
(() => {
  "use strict";

  const CONFIG = {
    interface_ethernet: { section: "ethernets", titleKey: "interfaces.ethernets_title", descriptionKey: "interfaces.ethernets_description" },
    interface_bond: { section: "bonds", titleKey: "interfaces.bonds_title", descriptionKey: "interfaces.bonds_description" },
    interface_bridge: { section: "bridges", titleKey: "interfaces.bridges_title", descriptionKey: "interfaces.bridges_description" },
    interface_vlan: { section: "vlans", titleKey: "interfaces.vlans_title", descriptionKey: "interfaces.vlans_description" },
    interface_wifi: { section: "wifis", titleKey: "interfaces.wifis_title", descriptionKey: "interfaces.wifis_description" },
  };

  const renderers = {};

  function rendererFor(pageId) {
    const cfg = CONFIG[pageId];
    if (!cfg) throw new Error(`unknown_interface_page:${pageId}`);
    if (!renderers[pageId]) {
      renderers[pageId] = window.PraesidiumGenericTable.createRenderer({
        section: cfg.section,
        titleKey: cfg.titleKey,
        descriptionKey: cfg.descriptionKey,
        formsPath: "js/pages/interfaces/forms_interfaces.json",
        structurePath: "js/pages/interfaces/structure_table_interfaces.json",
        commandsPath: "js/pages/interfaces/interfaces_commands_api.json",
      });
    }
    return renderers[pageId];
  }

  async function render(container, pageId) {
    return rendererFor(pageId)(container);
  }

  window.PraesidiumInterfacesPage = { render };
})();
