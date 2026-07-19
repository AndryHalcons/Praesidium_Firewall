/*
 * ES: Filtro frontend centralizado para tablas WebGUI.
 *     Reproduce la idea legacy: una segunda fila en thead con filtros por columna.
 * EN: Centralized frontend table filter for WebGUI tables.
 *     Recreates the legacy idea: a second thead row with per-column filters.
 */
(() => {
  "use strict";

  const { el, td, th, tr } = window.PraesidiumDom;

  // ES: Normaliza texto para comparación simple en frontend.
  // EN: Normalizes text for simple frontend matching.
  function normalize(value) {
    return String(value ?? "").toLocaleLowerCase().trim();
  }

  // ES: Devuelve el texto visible de una celda concreta.
  // EN: Returns the visible text of a concrete cell.
  function cellText(row, index) {
    const cell = row.cells[index];
    return normalize(cell ? cell.textContent : "");
  }

  // ES: Construye un input de filtro seguro para una columna.
  // EN: Builds a safe filter input for one column.
  function filterInputNode(columnIndex, label) {
    return el("input", {
      className: "generic-table-filter-input",
      type: "search",
      placeholder: PraesidiumI18n.t("table_filter.placeholder", { column: label }),
      "aria-label": PraesidiumI18n.t("table_filter.aria", { column: label }),
      "data-table-filter-column": String(columnIndex),
    });
  }

  // ES: Determina si una columna debe tener filtro según opciones del módulo.
  // EN: Determines whether a column should have a filter according to module options.
  function isFilterableColumn(index, options) {
    const disabled = new Set(options.disabledColumnIndexes || []);
    if (disabled.has(index)) return false;
    if (Array.isArray(options.enabledColumnIndexes)) return options.enabledColumnIndexes.includes(index);
    return true;
  }

  // ES: Crea la fila legacy de filtros dentro del thead.
  // EN: Creates the legacy filter row inside the thead.
  function buildFilterRow(headerCells, options) {
    const cells = headerCells.map((headerCell, index) => {
      if (!isFilterableColumn(index, options)) {
        return th("", { className: "generic-table-filter-actions" });
      }
      const label = headerCell.textContent || String(index + 1);
      return th(filterInputNode(index, label));
    });
    return tr(cells, { className: "generic-table-filter-row" });
  }

  // ES: Crea fila de “sin resultados” que se muestra cuando el filtro oculta todo.
  // EN: Creates a “no results” row shown when the filter hides everything.
  function noResultsRow(columnCount) {
    return tr([
      td(PraesidiumI18n.t("table_filter.no_results"), {
        className: "generic-table-no-results",
        colspan: String(columnCount),
      }),
    ], { "data-table-filter-empty": "true" });
  }

  // ES: Aplica filtros con semántica AND: todas las columnas escritas deben coincidir.
  // EN: Applies filters with AND semantics: every typed column must match.
  function applyFilters(table, inputs, emptyRow) {
    const active = inputs
      .map(input => ({ index: Number(input.dataset.tableFilterColumn), value: normalize(input.value) }))
      .filter(item => item.value.length > 0);

    let visibleCount = 0;
    table.querySelectorAll("tbody tr").forEach(row => {
      if (row.dataset.tableFilterEmpty === "true") return;
      const visible = active.every(item => cellText(row, item.index).includes(item.value));
      row.hidden = !visible;
      if (visible) visibleCount += 1;
    });
    emptyRow.hidden = visibleCount !== 0;
  }

  // ES: Activa filtro centralizado sobre una tabla ya creada.
  // EN: Enables the centralized filter on an already-created table.
  function attach(table, options = {}) {
    if (!table || table.dataset.tableFilterAttached === "true") return table;
    const thead = table.tHead || table.querySelector("thead");
    const tbody = table.tBodies[0] || table.querySelector("tbody");
    const headerRow = thead ? thead.querySelector("tr") : null;
    if (!thead || !tbody || !headerRow) return table;

    const headerCells = Array.from(headerRow.cells);
    if (!headerCells.length) return table;

    const filterRow = buildFilterRow(headerCells, options);
    thead.appendChild(filterRow);

    const emptyRow = noResultsRow(headerCells.length);
    emptyRow.hidden = true;
    tbody.appendChild(emptyRow);

    const inputs = Array.from(filterRow.querySelectorAll("input.generic-table-filter-input"));
    inputs.forEach(input => {
      input.addEventListener("input", () => applyFilters(table, inputs, emptyRow));
    });

    table.dataset.tableFilterAttached = "true";
    return table;
  }

  // ES: API pública para módulos/páginas que pinten tablas.
  // EN: Public API for modules/pages that render tables.
  window.PraesidiumTableFilter = { attach };
})();
