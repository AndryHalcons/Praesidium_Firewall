#!/usr/bin/env python3
"""
Test: test_generic_table_filters_static.py

Objetivo:
    Proteger el experimento de filtros por columna en la tabla genérica.
    Verifica que el filtro vive en generic_table.js, no llama al backend al teclear,
    excluye Acciones y columnas botón, y conserva comentarios bilingües.

Goal:
    Protect the per-column filter experiment in the generic table.
    Verifies that filtering lives in generic_table.js, does not call the backend
    while typing, excludes Actions/button columns, and keeps bilingual comments.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
JS = ROOT / "web" / "my_js" / "generic_table.js"
CSS = ROOT / "web" / "styles.css"
ES = ROOT / "web" / "lang" / "es.php"
EN = ROOT / "web" / "lang" / "en.php"


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        fail(f"missing {label}: {needle}")


def main() -> None:
    js = JS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    es = ES.read_text(encoding="utf-8")
    en = EN.read_text(encoding="utf-8")

    # Funciones del experimento / Experiment functions.
    for fn in [
        "genericGetTableFilterState",
        "genericFilterableValue",
        "genericFilterableCellValue",
        "genericRuleMatchesFilters",
        "genericApplyTableFilters",
        "genericCreateFilterRow",
        "genericRenderTableRows",
    ]:
        require(js, f"function {fn}", f"function {fn}")

    # La fila de filtros debe ser segunda cabecera, no una tabla aparte.
    # The filter row must be a second header row, not a separate table.
    require(js, "thead.appendChild(headerRow);", "main header row")
    require(js, "thead.appendChild(filterRow);", "filter header row")
    require(js, "generic-table-filter-row", "filter row class")
    require(js, "generic-table-filter-input", "filter input class")

    # Acciones y columnas botón quedan excluidas del filtrado.
    # Actions and button columns are excluded from filtering.
    require(js, "generic-table-filter-actions", "empty actions filter cell")
    require(js, "if (genericIsButtonColumn(column)) {\n      return true;", "button columns ignored in filter")
    require(js, "return value === formConfig.checkbox[key].checked ? 'true' : 'false';", "checkbox visual true/false filter")
    require(js, "genericFilterableCellValue(rule[key], formConfig, key)", "filter uses formConfig-aware value")
    require(js, "if (!genericIsButtonColumn(column))", "no input for button columns")

    # El input debe repintar con cache, no disparar fetch() por pulsación.
    # The input must repaint from cache, not trigger fetch() per keystroke.
    input_handler = re.search(r"input\.addEventListener\('input', \(\) => \{(?P<body>.*?)\n      \}\);", js, re.S)
    if not input_handler:
        fail("filter input handler not found")
    if "fetch(" in input_handler.group("body"):
        fail("filter input handler must not call fetch")
    require(input_handler.group("body"), "repaintRows();", "client-side repaint on filter")

    # CSS y textos traducibles.
    # CSS and translatable labels.
    require(css, "table.interfaz thead tr.generic-table-filter-row th", "filter row css")
    require(css, "table.interfaz input.generic-table-filter-input", "filter input css")
    require(es, "'filter' => 'Filtrar'", "Spanish filter label")
    require(en, "'filter' => 'Filter'", "English filter label")
    require(es, "'filter_no_results'", "Spanish no-results label")
    require(en, "'filter_no_results'", "English no-results label")

    # Comentarios bilingües alrededor de las funciones nuevas.
    # Bilingual comments around the new functions.
    require(js, "// Estado en memoria para filtros", "Spanish filter state comment")
    require(js, "// In-memory state for generic table filters", "English filter state comment")
    require(js, "// Convierte cualquier valor de celda", "Spanish value comment")
    require(js, "// Converts any cell value", "English value comment")
    require(js, "// Para checkbox, el filtro debe representar el estado visual", "Spanish checkbox filter comment")
    require(js, "// For checkboxes, the filter must represent visual state", "English checkbox filter comment")

    print("PASS: generic table filters static contract")


if __name__ == "__main__":
    main()
