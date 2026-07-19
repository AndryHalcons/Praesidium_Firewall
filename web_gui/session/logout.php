<?php
/** ES: Logout WebGUI: limpia sesión PHP y pide logout a FastAPI si hay Bearer. */
/** EN: WebGUI logout: clears PHP session and asks FastAPI logout when a Bearer exists. */
declare(strict_types=1);
require __DIR__ . '/common.php';

praesidium_start_session();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}
$token = $_SESSION['fastapi_access_token'] ?? '';
if (is_string($token) && $token !== '') {
    // ES: Si JS tiene CSRF lo valida; si no, logout sigue limpiando para no dejar sesiones zombie.
    // EN: If JS has CSRF it is validated; otherwise logout still cleans to avoid zombie sessions.
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if (is_string($provided) && $provided !== '' && is_string($expected) && $expected !== '') {
        if (!hash_equals($expected, $provided)) {
            praesidium_json(403, ['detail' => 'CSRF_INVALID']);
        }
    }
    praesidium_fastapi_request('POST', '/auth/logout', $token, '{}');
}
praesidium_destroy_session();
praesidium_json(200, ['status' => 'ok']);
