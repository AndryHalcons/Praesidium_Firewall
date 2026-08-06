<?php
/** ES: Login WebGUI: pide Bearer a FastAPI y lo guarda sólo en sesión PHP. */
/** EN: WebGUI login: requests Bearer from FastAPI and stores it only in PHP session. */
declare(strict_types=1);
require __DIR__ . '/common.php';

praesidium_start_session();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}

$payload = praesidium_json_input();
$username = isset($payload['username']) ? trim((string)$payload['username']) : '';
$password = isset($payload['password']) ? (string)$payload['password'] : '';
if ($username === '' || $password === '') {
    praesidium_json(400, ['detail' => 'MISSING_CREDENTIALS']);
}

$loginResponse = praesidium_fastapi_request('POST', '/auth/login', null, json_encode([
    'username' => $username,
    'password' => $password,
]));

$loginData = json_decode((string)$loginResponse['body'], true);
if ((int)$loginResponse['status'] < 200 || (int)$loginResponse['status'] >= 300 || !is_array($loginData) || empty($loginData['access_token'])) {
    praesidium_forward_json_response($loginResponse);
}

session_regenerate_id(true);
$_SESSION['fastapi_access_token'] = (string)$loginData['access_token'];
$_SESSION['fastapi_token_type'] = isset($loginData['token_type']) ? (string)$loginData['token_type'] : 'bearer';
$_SESSION['created_at'] = time();
$csrf = praesidium_csrf_token();

$meResponse = praesidium_fastapi_request('GET', '/auth/me', $_SESSION['fastapi_access_token']);
$meData = json_decode((string)$meResponse['body'], true);
if ((int)$meResponse['status'] < 200 || (int)$meResponse['status'] >= 300 || !is_array($meData)) {
    praesidium_destroy_session();
    praesidium_forward_json_response($meResponse);
}
$meData['csrf_token'] = $csrf;
praesidium_json(200, $meData);
