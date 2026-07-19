/*
 * ES: Helpers DOM seguros. Las páginas deben crear nodos con createElement/textContent,
 *     no concatenar HTML con datos dinámicos.
 * EN: Safe DOM helpers. Pages must create nodes with createElement/textContent,
 *     not concatenate HTML with dynamic data.
 */
(() => {
  "use strict";

  // ES: Lista mínima de atributos permitidos por este helper. Evita eventos inline tipo onclick.
  // EN: Minimal allow-list of attributes accepted by this helper. Prevents inline events like onclick.
  const SAFE_ATTRIBUTES = new Set([
    "id", "class", "className", "type", "href", "role", "aria-hidden", "aria-label",
    "colspan", "tabindex", "placeholder", "data-page", "data-status", "data-alias-uuid", "data-interface-uuid", "data-table-filter-column", "data-table-filter-empty"
  ]);

  // ES: Crea un nodo de texto. Todo dato de API/usuario/i18n que sea texto debe acabar aquí o en textContent.
  // EN: Creates a text node. Any API/user/i18n data that is text must end here or in textContent.
  function text(value) {
    return document.createTextNode(String(value ?? ""));
  }

  // ES: Aplica atributos controlados; className se trata separado para compatibilidad DOM.
  // EN: Applies controlled attributes; className is handled separately for DOM compatibility.
  function setSafeAttribute(node, name, value) {
    if (value === null || value === undefined || value === false) return;
    if (!SAFE_ATTRIBUTES.has(name)) throw new Error(`unsafe_dom_attribute:${name}`);
    if (name === "class" || name === "className") {
      node.className = String(value);
      return;
    }
    if (name === "href") {
      const href = String(value).trim();
      if (href !== "#" && !href.startsWith("/")) throw new Error(`unsafe_href:${href}`);
      node.setAttribute(name, href);
      return;
    }
    node.setAttribute(name, String(value));
  }

  // ES: Añade hijos de forma segura aceptando nodos, strings/números o arrays anidados.
  // EN: Appends children safely accepting nodes, strings/numbers, or nested arrays.
  function appendSafe(parent, children) {
    (Array.isArray(children) ? children : [children]).flat(Infinity).forEach(child => {
      if (child === null || child === undefined || child === false) return;
      if (child instanceof Node) parent.appendChild(child);
      else parent.appendChild(text(child));
    });
  }

  // ES: Constructor general de elementos. No acepta HTML crudo.
  // EN: General element builder. It does not accept raw HTML.
  function el(tagName, attrs = {}, children = []) {
    const node = document.createElement(tagName);
    Object.entries(attrs || {}).forEach(([name, value]) => setSafeAttribute(node, name, value));
    appendSafe(node, children);
    return node;
  }

  // ES: Vacía y rellena un contenedor con nodos seguros.
  // EN: Clears and fills a container with safe nodes.
  function replaceChildren(parent, children = []) {
    parent.replaceChildren();
    appendSafe(parent, children);
    return parent;
  }

  // ES: Crea una celda de tabla con texto seguro y atributos permitidos.
  // EN: Creates a table cell with safe text and allowed attributes.
  function td(value, attrs = {}) {
    return el("td", attrs, [value]);
  }

  // ES: Crea una cabecera de tabla con texto seguro.
  // EN: Creates a table header with safe text.
  function th(value, attrs = {}) {
    return el("th", attrs, [value]);
  }

  // ES: Crea una fila de tabla a partir de celdas ya seguras y metadatos permitidos.
  // EN: Creates a table row from already-safe cells and allowed metadata.
  function tr(cells = [], attrs = {}) {
    return el("tr", attrs, cells);
  }

  // ES: API pública para páginas modulares.
  // EN: Public API for modular pages.
  window.PraesidiumDom = { text, el, replaceChildren, td, th, tr };
})();
