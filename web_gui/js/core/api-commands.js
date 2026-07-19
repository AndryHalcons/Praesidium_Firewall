/*
 * ES: Executor seguro de comandos API declarados en JSON de módulo.
 * EN: Safe executor for API commands declared in module JSON.
 */
(() => {
  "use strict";

  const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

  // ES: Obtiene un comando validado desde commands[section][action].
  // EN: Gets a validated command from commands[section][action].
  function commandFor(commands, section, action) {
    const sectionCommands = commands && commands[section];
    if (!sectionCommands || !sectionCommands[action]) throw new Error(`missing_api_command:${section}:${action}`);
    const command = sectionCommands[action];
    const method = String(command.method || "GET").toUpperCase();
    const path = String(command.path || "");
    if (!ALLOWED_METHODS.has(method)) throw new Error(`invalid_api_method:${method}`);
    if (!path.startsWith("/") || path.includes("://") || path.includes("..") || path.startsWith("//")) {
      throw new Error(`invalid_api_path:${path}`);
    }
    return { method, path, params: Array.isArray(command.params) ? command.params : [] };
  }

  // ES: Sustituye parámetros {name} usando encodeURIComponent y exige valores presentes.
  // EN: Replaces {name} parameters with encodeURIComponent and requires present values.
  function resolvePath(command, params = {}) {
    let path = command.path;
    command.params.forEach(name => {
      const value = params[name];
      if (value === null || value === undefined || value === "") throw new Error(`missing_api_param:${name}`);
      path = path.replaceAll(`{${name}}`, encodeURIComponent(String(value)));
    });
    if (path.includes("{") || path.includes("}")) throw new Error(`unresolved_api_path:${path}`);
    return path;
  }

  // ES: Ejecuta un comando declarado; el body sólo se envía en mutaciones con payload.
  // EN: Executes a declared command; body is sent only for mutations with payload.
  async function execute(commands, section, action, { params = {}, payload = null } = {}) {
    const command = commandFor(commands, section, action);
    const path = resolvePath(command, params);
    const options = { method: command.method };
    if (payload !== null && command.method !== "GET" && command.method !== "DELETE") {
      options.body = JSON.stringify(payload);
    }
    return window.PraesidiumApi.request(path, options);
  }

  // ES: API pública del executor común.
  // EN: Public API for the common executor.
  window.PraesidiumApiCommands = { execute, commandFor, resolvePath };
})();
