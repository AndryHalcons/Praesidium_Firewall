<?php
/**
 * ES: Núcleo seguro de sesión WebGUI. Guarda el Bearer de FastAPI sólo en servidor.
 * EN: Secure WebGUI session core. Stores the FastAPI Bearer only server-side.
 */
declare(strict_types=1);

const PRAESIDIUM_FASTAPI_BASE = 'http://127.0.0.1:8000/api/v1';
const PRAESIDIUM_SESSION_NAME = 'PRAESIDIUM_WEBGUI_SESSION';
const PRAESIDIUM_ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const PRAESIDIUM_MUTATING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/** ES: Configura cookie de sesión HttpOnly/SameSite antes de session_start. */
/** EN: Configures HttpOnly/SameSite session cookie before session_start. */
function praesidium_start_session(): void
{
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_name(PRAESIDIUM_SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

/** ES: Emite JSON sin filtrar secretos de sesión. */
/** EN: Emits JSON without leaking session secrets. */
function praesidium_json(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/** ES: Lee JSON de entrada con límite de tamaño para evitar cuerpos enormes. */
/** EN: Reads JSON input with a size limit to avoid huge bodies. */
function praesidium_json_input(int $maxBytes = 1048576): array
{
    $raw = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
    if ($raw === false || strlen($raw) > $maxBytes) {
        praesidium_json(413, ['detail' => 'REQUEST_TOO_LARGE']);
    }
    if ($raw === '') {
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        praesidium_json(400, ['detail' => 'INVALID_JSON']);
    }
    return $data;
}

/** ES: Devuelve o crea token CSRF de la sesión WebGUI. */
/** EN: Returns or creates the WebGUI session CSRF token. */
function praesidium_csrf_token(): string
{
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** ES: Valida CSRF para operaciones mutables de la capa WebGUI. */
/** EN: Validates CSRF for mutating operations of the WebGUI layer. */
function praesidium_require_csrf(): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if (!is_string($provided) || !is_string($expected) || $expected === '' || !hash_equals($expected, $provided)) {
        praesidium_json(403, ['detail' => 'CSRF_INVALID']);
    }
}

/** ES: Exige sesión WebGUI autenticada sin exponer el Bearer. */
/** EN: Requires an authenticated WebGUI session without exposing the Bearer. */
function praesidium_require_token(): string
{
    $token = $_SESSION['fastapi_access_token'] ?? '';
    if (!is_string($token) || $token === '') {
        praesidium_json(401, ['detail' => 'AUTH_REQUIRED']);
    }
    return $token;
}

/** ES: Destruye sesión y cookie WebGUI. */
/** EN: Destroys WebGUI session and cookie. */
function praesidium_destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'] ?: '/',
            'domain' => $params['domain'] ?: '',
            'secure' => (bool)$params['secure'],
            'httponly' => true,
            'samesite' => $params['samesite'] ?? 'Strict',
        ]);
    }
    session_destroy();
}

/** ES: Valida que el proxy sólo apunte a rutas FastAPI locales permitidas. */
/** EN: Validates that the proxy only targets allowed local FastAPI paths. */
function praesidium_validated_api_path(string $path): string
{
    $path = trim($path);
    if ($path === '' || $path[0] !== '/') {
        praesidium_json(400, ['detail' => 'INVALID_API_PATH']);
    }
    if (strlen($path) > 2048 || preg_match('/[\x00-\x1F\x7F]/', $path) || str_contains($path, '\\') || str_contains($path, '#')) {
        praesidium_json(400, ['detail' => 'INVALID_API_PATH']);
    }
    if (str_contains($path, '..') || str_contains($path, '://') || str_starts_with($path, '//')) {
        praesidium_json(400, ['detail' => 'INVALID_API_PATH']);
    }
    return $path;
}

/** ES: Llama a FastAPI local con método, ruta, token opcional y cuerpo opcional. */
/** EN: Calls local FastAPI with method, path, optional token, and optional body. */
function praesidium_fastapi_request(string $method, string $path, ?string $bearerToken = null, ?string $body = null, string $accept = 'application/json', string $contentType = 'application/json'): array
{
    $method = strtoupper($method);
    if (!in_array($method, PRAESIDIUM_ALLOWED_METHODS, true)) {
        praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
    }
    $allowedAccepts = [
        'application/json',
        'application/octet-stream,image/png,application/zip,application/json',
    ];
    if (!in_array($accept, $allowedAccepts, true)) {
        praesidium_json(400, ['detail' => 'INVALID_ACCEPT']);
    }
    $validContentType = $contentType === 'application/json'
        || preg_match('/^multipart\/form-data; boundary=[A-Za-z0-9._-]{1,70}$/D', $contentType) === 1;
    if (!$validContentType) {
        praesidium_json(400, ['detail' => 'INVALID_CONTENT_TYPE']);
    }

    $path = praesidium_validated_api_path($path);
    $headers = [
        'Accept: ' . $accept,
        'Content-Type: ' . $contentType,
    ];
    if ($bearerToken !== null && $bearerToken !== '') {
        $headers[] = 'Authorization: Bearer ' . $bearerToken;
    }

    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $body ?? '',
            'ignore_errors' => true,
            'timeout' => 12,
            'follow_location' => $accept === 'application/json' ? 1 : 0,
            'max_redirects' => $accept === 'application/json' ? 20 : 0,
        ],
    ]);

    $responseBody = @file_get_contents(PRAESIDIUM_FASTAPI_BASE . $path, false, $context);
    $responseHeaders = $http_response_header ?? [];
    $status = 502;
    foreach ($responseHeaders as $headerLine) {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headerLine, $matches)) {
            $status = (int)$matches[1];
        }
    }

    if ($responseBody === false) {
        return ['status' => 502, 'body' => json_encode(['detail' => 'FASTAPI_UNREACHABLE']), 'headers' => []];
    }
    return ['status' => $status, 'body' => $responseBody, 'headers' => $responseHeaders];
}

/** ES: Reenvía respuesta FastAPI al navegador sin añadir secretos. */
/** EN: Forwards FastAPI response to the browser without adding secrets. */
function praesidium_forward_json_response(array $response): never
{
    http_response_code((int)$response['status']);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo (string)$response['body'];
    exit;
}

/** ES: Obtiene una cabecera concreta de la respuesta FastAPI. */
/** EN: Gets a concrete header from the FastAPI response. */
function praesidium_response_header(array $headers, string $name): string
{
    $prefix = strtolower($name) . ':';
    foreach ($headers as $line) {
        if (is_string($line) && str_starts_with(strtolower($line), $prefix)) {
            return trim(substr($line, strlen($prefix)));
        }
    }
    return '';
}

/** ES: Reenvía un binario FastAPI con tipos, nombre y tamaño estrictamente limitados. */
/** EN: Forwards a FastAPI binary with strictly limited types, filename, and size. */
function praesidium_forward_download_response(array $response): never
{
    $status = (int)($response['status'] ?? 502);
    if ($status < 200 || $status >= 300) {
        praesidium_forward_json_response($response);
    }
    $body = (string)($response['body'] ?? '');
    if (strlen($body) > 33554432) {
        praesidium_json(502, ['detail' => 'DOWNLOAD_TOO_LARGE']);
    }
    $headers = is_array($response['headers'] ?? null) ? $response['headers'] : [];
    $rawType = praesidium_response_header($headers, 'Content-Type');
    $mediaType = strtolower(trim(explode(';', $rawType, 2)[0]));
    $allowedTypes = ['application/octet-stream', 'image/png', 'application/zip'];
    if (!in_array($mediaType, $allowedTypes, true)) {
        praesidium_json(502, ['detail' => 'INVALID_DOWNLOAD_CONTENT_TYPE']);
    }
    $disposition = praesidium_response_header($headers, 'Content-Disposition');
    $filename = 'download';
    if (preg_match('/filename="?([^";]+)"?/i', $disposition, $matches)) {
        $filename = (string)$matches[1];
    }
    $filename = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($filename)) ?: 'download';
    $filename = substr($filename, 0, 180) ?: 'download';

    http_response_code($status);
    header('Content-Type: ' . $mediaType);
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}
