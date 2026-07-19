<?php
/** ES: Proxy seguro WebGUI -> FastAPI. No acepta URL libre; sólo path local /api/v1. */
/** EN: Secure WebGUI -> FastAPI proxy. It accepts no free URL; only local /api/v1 paths. */
declare(strict_types=1);
require __DIR__ . '/common.php';

praesidium_start_session();
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
if (!in_array($method, PRAESIDIUM_ALLOWED_METHODS, true)) {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}
if (in_array($method, PRAESIDIUM_MUTATING_METHODS, true)) {
    praesidium_require_csrf();
}
$token = praesidium_require_token();
$path = isset($_GET['path']) ? (string)$_GET['path'] : '';
$path = praesidium_validated_api_path($path);
$body = null;
if (in_array($method, PRAESIDIUM_MUTATING_METHODS, true)) {
    $body = file_get_contents('php://input', false, null, 0, 1048577);
    if ($body === false || strlen($body) > 1048576) {
        praesidium_json(413, ['detail' => 'REQUEST_TOO_LARGE']);
    }
    if ($body === '') {
        $body = '{}';
    }
}
$response = praesidium_fastapi_request($method, $path, $token, $body);
if ((int)$response['status'] === 401) {
    praesidium_destroy_session();
}
praesidium_forward_json_response($response);
