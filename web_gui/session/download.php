<?php
/** ES: Descarga binarios FastAPI mediante la sesión WebGUI sin exponer Bearer. */
/** EN: Downloads FastAPI binaries through the WebGUI session without exposing Bearer. */
declare(strict_types=1);
require __DIR__ . '/common.php';

praesidium_start_session();
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}
$token = praesidium_require_token();
$path = isset($_GET['path']) ? (string)$_GET['path'] : '';
$path = praesidium_validated_api_path($path);
$wireguardDownload = preg_match('#^/wireguard/remote-clients/[A-Za-z0-9_.:-]{1,160}/(?:config|qr|bundle)$#D', $path) === 1;
$certificateDownload = preg_match('#^/certificates/[A-Za-z0-9_.@+-]{1,255}/download$#D', $path) === 1;
if (!$wireguardDownload && !$certificateDownload) {
    praesidium_json(403, ['detail' => 'DOWNLOAD_PATH_NOT_ALLOWED']);
}
$response = praesidium_fastapi_request(
    'GET',
    $path,
    $token,
    null,
    'application/octet-stream,image/png,application/zip,application/json'
);
if ((int)$response['status'] === 401) {
    praesidium_destroy_session();
}
praesidium_forward_download_response($response);
