/*
 * ES: Estado global mínimo del WebGUI y definición de menús mediante claves de idioma.
 * EN: Minimal WebGUI global state and menu definition through language keys.
 */
(() => {
  "use strict";

  // ES: Lista de módulos que existen como endpoints FastAPI y pueden tener pantalla base.
  // EN: List of modules that exist as FastAPI endpoints and can have a base screen.
  const FASTAPI_MODULES = [
    "alias_address",
    "alias_addr_group",
    "alias_service",
    "alias_service_group",
    "bpfilter_xdp",
    "bpfilter_tc_ingress",
    "bpfilter_tc_egress",
    "certificates",
    "commit",
    "dnsmasq_scopes",
    "dnsmasq_reservations",
    "interfaces",
    "login_attempts",
    "monitor_logs",
    "monitor_session",
    "nftables_forwarding",
    "nftables_prerouting",
    "nftables_postrouting",
    "nftables_input",
    "nftables_output",
    "password_policy",
    "routing",
    "services",
    "system_logging",
    "users",
    "wireguard",
  ];

  // ES: Estructura de menús. Cada labelKey apunta a web_gui/lang/*.json, no a texto directo.
  // EN: Menu structure. Each labelKey points to web_gui/lang/*.json, not direct text.
  const MENU = {
    // ES: Menú horizontal superior. El id también se usa como pageId de navegación.
    // EN: Top horizontal menu. The id is also used as navigation pageId.
    top: [
      { id: "dashboard", labelKey: "menu.home" },
      { id: "monitor_logs", labelKey: "menu.monitor_logs" },
      { id: "monitor_session", labelKey: "menu.monitor_session" },
      { id: "commit", labelKey: "menu.commit" },
      { id: "logout", labelKey: "menu.logout" },
    ],
    // ES: Menú lateral agrupado por secciones desplegables.
    // EN: Sidebar menu grouped by expandable sections.
    sidebar: [
      { labelKey: "menu.dashboard", pages: [{ id: "dashboard", labelKey: "menu.dashboard" }] },
      { labelKey: "menu.interfaces", pages: [
        { id: "interface_ethernet", labelKey: "menu.interface_ethernet" },
        { id: "interface_bond", labelKey: "menu.interface_bond" },
        { id: "interface_bridge", labelKey: "menu.interface_bridge" },
        { id: "interface_vlan", labelKey: "menu.interface_vlan" },
        { id: "interface_wifi", labelKey: "menu.interface_wifi" },
      ]},
      // ES: WireGuard es un módulo FastAPI independiente de interfaces; por eso vive en VPN.
      // EN: WireGuard is an independent FastAPI module from interfaces, so it lives under VPN.
      { labelKey: "menu.vpn", pages: [
        // ES: WireGuard se divide por endpoint FastAPI real: site-to-site, servidores y clientes.
        // EN: WireGuard is split by real FastAPI endpoint: site-to-site, servers, and clients.
        { id: "wireguard_site_to_site", labelKey: "menu.wireguard_site_to_site" },
        { id: "wireguard_server", labelKey: "menu.wireguard_server" },
        { id: "wireguard_clients", labelKey: "menu.wireguard_clients" },
      ]},
      { labelKey: "menu.firewall", pages: [
        { id: "nftables_forwarding", labelKey: "menu.nftables_forwarding" },
        { id: "nftables_prerouting", labelKey: "menu.nftables_prerouting" },
        { id: "nftables_postrouting", labelKey: "menu.nftables_postrouting" },
        { id: "nftables_input", labelKey: "menu.nftables_input" },
        { id: "nftables_output", labelKey: "menu.nftables_output" },
        { id: "bpfilter_xdp", labelKey: "menu.bpfilter_xdp" },
        { id: "bpfilter_tc_ingress", labelKey: "menu.bpfilter_tc_ingress" },
        { id: "bpfilter_tc_egress", labelKey: "menu.bpfilter_tc_egress" },
      ]},
      { labelKey: "menu.alias", pages: [
        // ES: Cada sección alias tiene ahora su propio módulo WebGUI y metadata.
        // EN: Each alias section now has its own WebGUI module and metadata.
        { id: "alias_address", labelKey: "menu.alias_address" },
        { id: "alias_address_group", labelKey: "menu.alias_address_group" },
        { id: "alias_service", labelKey: "menu.alias_service" },
        { id: "alias_service_group", labelKey: "menu.alias_service_group" },
      ]},
      {
        labelKey: "menu.networking",
        pages: [
          { id: "dnsmasq_scopes", labelKey: "menu.dnsmasq_scopes" },
          { id: "dnsmasq_reservations", labelKey: "menu.dnsmasq_reservations" },
        ],
      },
      { labelKey: "menu.system", pages: [
        { id: "services", labelKey: "menu.services" },
        { id: "routing", labelKey: "menu.routing" },
        { id: "system_logging", labelKey: "menu.system_logging" },
        { id: "certificates", labelKey: "menu.certificates" },
      ]},
      // ES: Auditoría agrupa sólo la navegación; Users, Política de contraseñas e Intentos de login siguen independientes.
      // EN: Audit groups navigation only; Users, Password policy, and Login attempts remain independent.
      { labelKey: "menu.audit", pages: [
        { id: "users", labelKey: "menu.users" },
        { id: "password_policy", labelKey: "menu.password_policy" },
        { id: "login_attempts", labelKey: "menu.login_attempts" },
      ]},
    ],
  };

  // ES: Estado mutable mínimo de la sesión visual actual.
  // EN: Minimal mutable state for the current visual session.
  const state = {
    // ES: Usuario devuelto por /auth/me; null cuando no hay sesión activa.
    // EN: User returned by /auth/me; null when there is no active session.
    user: null,
    // ES: Página activa; se conserva para volver al dashboard o recargar la vista actual.
    // EN: Active page; kept to return to dashboard or reload the current view.
    activePage: "dashboard",
  };

  // ES: Estado público compartido entre shell.js y pages.js.
  // EN: Public state shared between shell.js and pages.js.
  window.PraesidiumState = {
    FASTAPI_MODULES,
    MENU,
    state,
    // ES: Helper de permisos para mostrar acciones destructivas/editables sólo a admin.
    // EN: Permission helper to show destructive/editable actions only to admin.
    isAdmin() {
      return state.user && state.user.user_role === "admin";
    },
  };
})();
