/*
 * ES: Cargador de idiomas del WebGUI. Carga english.json como fallback y el idioma del usuario si existe.
 * EN: WebGUI language loader. Loads english.json as fallback and the user language when available.
 */
(() => {
  "use strict";

  // ES: Mapa cerrado entre idioma lógico y archivo JSON real. No inventar nombres como en.json/es.json.
  // EN: Closed map between logical language and real JSON file. Do not invent names like en.json/es.json.
  const LANGUAGE_FILES = {
    english: "lang/english.json",
    espanol: "lang/espanol.json",
  };
  // ES: Idioma seguro cuando el usuario no tiene idioma válido o un archivo falla.
  // EN: Safe language when the user has no valid language or a file load fails.
  const FALLBACK_LANGUAGE = "english";
  // ES: Diccionario inglés cargado una sola vez; se usa como respaldo de claves.
  // EN: English dictionary loaded once; used as key fallback.
  let fallbackMessages = {};
  // ES: Diccionario del idioma actualmente activo en la interfaz.
  // EN: Dictionary for the currently active interface language.
  let activeMessages = {};
  // ES: Nombre lógico del idioma activo; también controla document.documentElement.lang.
  // EN: Logical active language name; also controls document.documentElement.lang.
  let activeLanguage = FALLBACK_LANGUAGE;

  // ES: Normaliza nombres habituales de idioma al nombre real del archivo JSON.
  // EN: Normalizes common language names to the real JSON file name.
  function normalizeLanguage(language) {
    const value = String(language || "").trim().toLowerCase().replace(/[- ]/g, "_");
    if (["es", "esp", "espanol", "español", "spanish"].includes(value)) return "espanol";
    if (["en", "eng", "english", "ingles", "inglés"].includes(value)) return "english";
    return FALLBACK_LANGUAGE;
  }

  // ES: Descarga un archivo de idioma sin caché para ver cambios durante desarrollo.
  // EN: Downloads a language file without cache so development changes are visible.
  async function loadJson(language) {
    const file = LANGUAGE_FILES[language] || LANGUAGE_FILES[FALLBACK_LANGUAGE];
    const response = await fetch(file, { cache: "no-store" });
    if (!response.ok) throw new Error(`i18n_load_failed:${file}`);
    return response.json();
  }

  // ES: Busca claves anidadas tipo "dashboard.title" dentro del JSON cargado.
  // EN: Looks up nested keys like "dashboard.title" inside the loaded JSON.
  function lookup(messages, key) {
    const normalizedKey = String(key || "");
    if (messages && Object.prototype.hasOwnProperty.call(messages, normalizedKey)) return messages[normalizedKey];
    const parts = normalizedKey.split(".");
    let value = messages;
    for (let index = 0; index < parts.length; index += 1) {
      if (!value) return undefined;
      const remaining = parts.slice(index).join(".");
      if (Object.prototype.hasOwnProperty.call(value, remaining)) return value[remaining];
      const part = parts[index];
      if (!Object.prototype.hasOwnProperty.call(value, part)) return undefined;
      value = value[part];
    }
    return value;
  }

  // ES: Sustituye placeholders simples como {user}, {time} o {count}.
  // EN: Replaces simple placeholders such as {user}, {time}, or {count}.
  function interpolate(text, params = {}) {
    return String(text).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) => {
      return Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match;
    });
  }

  // ES: Traduce una clave con fallback a inglés y sustitución de {parametros}.
  // EN: Translates a key with English fallback and {parameter} replacement.
  function t(key, params = {}) {
    const active = lookup(activeMessages, key);
    const fallback = lookup(fallbackMessages, key);
    const value = active !== undefined ? active : (fallback !== undefined ? fallback : key);
    return interpolate(value, params);
  }

  // ES: Aplica traducciones declarativas a elementos con data-i18n y atributos relacionados.
  // EN: Applies declarative translations to elements with data-i18n and related attributes.
  function apply(root = document) {
    root.querySelectorAll("[data-i18n]").forEach(node => { node.textContent = t(node.dataset.i18n); });
    root.querySelectorAll("[data-i18n-placeholder]").forEach(node => { node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder)); });
    root.querySelectorAll("[data-i18n-aria-label]").forEach(node => { node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel)); });
    root.querySelectorAll("[data-i18n-alt]").forEach(node => { node.setAttribute("alt", t(node.dataset.i18nAlt)); });
    root.querySelectorAll("[data-i18n-title]").forEach(node => { node.setAttribute("title", t(node.dataset.i18nTitle)); });
    document.documentElement.lang = activeLanguage === "espanol" ? "es" : "en";
    document.title = t("app.title");
  }

  // ES: Cambia idioma activo; cualquier error vuelve automáticamente a english.json.
  // EN: Switches active language; any failure automatically falls back to english.json.
  async function setLanguage(language) {
    const normalized = normalizeLanguage(language);
    if (!Object.keys(fallbackMessages).length) {
      fallbackMessages = await loadJson(FALLBACK_LANGUAGE);
    }
    activeLanguage = normalized;
    if (normalized === FALLBACK_LANGUAGE) {
      activeMessages = fallbackMessages;
    } else {
      try {
        activeMessages = await loadJson(normalized);
      } catch (err) {
        activeLanguage = FALLBACK_LANGUAGE;
        activeMessages = fallbackMessages;
      }
    }
    apply(document);
    return activeLanguage;
  }

  // ES: API pública de traducción usada por app.js, shell.js y pages.js.
  // EN: Public translation API used by app.js, shell.js, and pages.js.
  window.PraesidiumI18n = {
    init: () => setLanguage(FALLBACK_LANGUAGE),
    setLanguage,
    normalizeLanguage,
    t,
    apply,
    get language() { return activeLanguage; },
  };
})();
