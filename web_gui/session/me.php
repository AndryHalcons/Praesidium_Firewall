<?php
/** ES: Devuelve identidad actual usando Bearer server-side y refresca CSRF visible para JS. */
/** EN: Returns current identity using server-side Bearer and refreshes JS-visible CSRF. */
declare(strict_types=1);
require __DIR__ . '/common.php';

praesidium_start_session();
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}
$token = praesidium_require_token();
$response = praesidium_fastapi_request('GET', '/auth/me', $token);
$data = json_decode((string)$response['body'], true);
if ((int)$response['status'] === 401) {
    praesidium_destroy_session();
    praesidium_forward_json_response($response);
}
if ((int)$response['status'] >= 200 && (int)$response['status'] < 300 && is_array($data)) {
    $data['csrf_token'] = praesidium_csrf_token();
    praesidium_json((int)$response['status'], $data);
}
praesidium_forward_json_response($response);
