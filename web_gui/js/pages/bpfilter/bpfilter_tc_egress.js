/*
 * ES: Página WebGUI BPFilter para BF_HOOK_TC_EGRESS.
 * EN: BPFilter WebGUI page for BF_HOOK_TC_EGRESS.
 */
(() => {
  "use strict";

  // ES: Esta sección usa la tabla genérica metadata-driven.
  // EN: This section uses the metadata-driven generic table.
  const render = window.PraesidiumGenericTable.createRenderer({
    section: "BF_HOOK_TC_EGRESS",
    basePath: "/js/pages/bpfilter",
  });

  // ES: API pública del módulo BPFilter BF_HOOK_TC_EGRESS.
  // EN: Public API for the BPFilter BF_HOOK_TC_EGRESS module.
  window.PraesidiumBpfilterTcEgressPage = { render };
})();
