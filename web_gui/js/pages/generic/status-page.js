/*
 * ES: Pantalla genérica para módulos FastAPI sin página propia. DOM seguro, sin innerHTML.
 * EN: Generic screen for FastAPI modules without a dedicated page. Safe DOM, no innerHTML.
 */
(() => {
  "use strict";

  const { t } = window.PraesidiumUi;
  const { el, replaceChildren } = window.PraesidiumDom;

  // ES: Crea cabecera genérica sin HTML crudo.
  // EN: Creates a generic header without raw HTML.
  function pageHeaderNode(title, description) {
    return el("div", { className: "pf-page-header" }, [
      el("div", { className: "pf-page-title" }, [el("h2", {}, [title]), el("p", { className: "pf-muted" }, [description])]),
      el("div"),
    ]);
  }

  // ES: Resuelve título visible y módulo backend por separado para páginas WebGUI virtuales.
  // EN: Resolves visible title and backend module separately for virtual WebGUI pages.
  function resolveGenericPage(pageId, options = {}) {
    const backendModule = options.backendModule || pageId;
    const titleKey = options.titleKey || `menu.${pageId}`;
    const title = PraesidiumI18n.t(titleKey);
    return { backendModule, title };
  }

  // ES: Pantalla provisional para módulos FastAPI aún sin WebGUI específico.
  // EN: Temporary screen for FastAPI modules without a specific WebGUI yet.
  async function renderApiStatusPage(container, pageId, options = {}) {
    const page = resolveGenericPage(pageId, options);
    const apiPath = `/${page.backendModule.replaceAll("_", "-")}/status`;
    const description = t("module.title_description", { module: page.title });
    replaceChildren(container, [pageHeaderNode(page.title, description), el("div", { className: "pf-alert" }, [t("module.loading_status", { path: apiPath })])]);
    try {
      const status = await PraesidiumApi.request(apiPath);
      replaceChildren(container, [
        pageHeaderNode(page.title, description),
        el("div", { className: "pf-card" }, [el("h3", {}, [t("common.status")]), el("pre", { className: "pf-pre" }, [JSON.stringify(status, null, 2)])]),
        el("div", { className: "pf-alert" }, [t("common.base_screen_created")]),
      ]);
    } catch (err) {
      replaceChildren(container, [pageHeaderNode(page.title, description), el("div", { className: "pf-alert error" }, [err.message])]);
    }
  }

  // ES: Registro público de la pantalla genérica para el dispatcher central.
  // EN: Public generic screen registration for the central dispatcher.
  window.PraesidiumGenericStatusPage = { render: renderApiStatusPage };
})();
