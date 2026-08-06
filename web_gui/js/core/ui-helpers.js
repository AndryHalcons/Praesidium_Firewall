/*
 * ES: Helpers comunes sin HTML crudo. No devuelven strings HTML para datos dinámicos.
 * EN: Common helpers without raw HTML. They do not return HTML strings for dynamic data.
 */
(() => {
  "use strict";

  // ES: Atajo local al traductor global.
  // EN: Local shortcut to the global translator.
  function t(key, params = {}) {
    return PraesidiumI18n.t(key, params);
  }

  // ES: Convierte bytes a B/KB/MB/GB/TB para métricas de disco/red/RAM.
  // EN: Converts bytes into B/KB/MB/GB/TB for disk/network/RAM metrics.
  function formatBytes(bytes) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let value = Number(bytes) || 0;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
  }

  // ES: Presenta velocidades de red como tamaño por segundo.
  // EN: Presents network speeds as size per second.
  function formatRate(bytesPerSecond) {
    return `${formatBytes(bytesPerSecond)}/s`;
  }

  // ES: Actualiza texto si el elemento existe; sólo usa textContent.
  // EN: Updates text when the element exists; only uses textContent.
  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = String(value ?? "");
  }

  // ES: Normaliza estados para clases CSS seguras.
  // EN: Normalizes states for safe CSS classes.
  function statusClass(value) {
    return String(value ?? t("common.unknown")).toLowerCase().replace(/[^a-z0-9_-]/g, "-");
  }

  // ES: API pública usada por páginas modulares.
  // EN: Public API used by modular pages.
  window.PraesidiumUi = { t, formatBytes, formatRate, setText, statusClass };
})();
