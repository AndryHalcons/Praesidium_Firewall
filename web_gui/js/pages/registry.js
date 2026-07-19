/*
 * ES: Dispatcher central de páginas. No contiene lógica visual de módulos concretos.
 * EN: Central page dispatcher. It does not contain visual logic for concrete modules.
 */
(() => {
  "use strict";

  // ES: Mapa mínimo entre pageId y renderer específico. Añadir nuevas páginas aquí, no en un archivo gigante.
  // EN: Minimal map between pageId and specific renderer. Add new pages here, not in a giant file.
  const PAGE_RENDERERS = {
    dashboard: window.PraesidiumDashboardPage.render,
    services: window.PraesidiumServicesPage.render,
    system_logging: window.PraesidiumSystemLoggingPage.render,
    routing: window.PraesidiumRoutingPage.render,
    interface_ethernet: window.PraesidiumInterfacesPage.render,
    interface_bond: window.PraesidiumInterfacesPage.render,
    interface_bridge: window.PraesidiumInterfacesPage.render,
    interface_vlan: window.PraesidiumInterfacesPage.render,
    interface_wifi: window.PraesidiumInterfacesPage.render,
    alias_address: window.PraesidiumAliasAddressPage.render,
    alias_address_group: window.PraesidiumAliasAddrGroupPage.render,
    alias_service: window.PraesidiumAliasServicePage.render,
    alias_service_group: window.PraesidiumAliasServiceGroupPage.render,
    bpfilter_xdp: window.PraesidiumBpfilterXdpPage.render,
    bpfilter_tc_ingress: window.PraesidiumBpfilterTcIngressPage.render,
    bpfilter_tc_egress: window.PraesidiumBpfilterTcEgressPage.render,
    nftables_forwarding: window.PraesidiumNftablesForwardingPage.render,
    nftables_prerouting: window.PraesidiumNftablesPreroutingPage.render,
    nftables_postrouting: window.PraesidiumNftablesPostroutingPage.render,
    nftables_input: window.PraesidiumNftablesInputPage.render,
    nftables_output: window.PraesidiumNftablesOutputPage.render,
    wireguard_site_to_site: window.PraesidiumWireGuardPage.render,
    wireguard_server: window.PraesidiumWireGuardPage.render,
    wireguard_clients: window.PraesidiumWireGuardPage.render,
    certificates: window.PraesidiumCertificatesPage.render,
    dnsmasq_scopes: window.PraesidiumDnsmasqPage.renderScopes,
    dnsmasq_reservations: window.PraesidiumDnsmasqPage.renderReservations,
    users: window.PraesidiumUsersPage.render,
    password_policy: window.PraesidiumPasswordPolicyPage.render,
    login_attempts: window.PraesidiumLoginAttemptsPage.render,
    monitor_logs: window.PraesidiumMonitorLogsPage.render,
    monitor_session: window.PraesidiumMonitorSessionPage.render,
    commit: window.PraesidiumCommitPage.render,
  };

  // ES: Renderiza la página solicitada o usa la pantalla genérica si no hay renderer dedicado.
  // EN: Renders the requested page or uses the generic screen when no dedicated renderer exists.
  async function render(container, pageId) {
    const renderer = PAGE_RENDERERS[pageId];
    if (renderer) return renderer(container, pageId);
    return window.PraesidiumGenericStatusPage.render(container, pageId);
  }

  // ES: API pública esperada por shell.js.
  // EN: Public API expected by shell.js.
  window.PraesidiumPages = { render };
})();
