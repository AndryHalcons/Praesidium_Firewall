<?php
/** ES: Subida multipart Certificates mediante sesión WebGUI sin exponer el Bearer. */
/** EN: Certificates multipart upload through the WebGUI session without exposing the Bearer. */
declare(strict_types=1);
require __DIR__ . '/common.php';

const PRAESIDIUM_CERTIFICATE_UPLOAD_MAX_BYTES = 5242880;

praesidium_start_session();
if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    praesidium_json(405, ['detail' => 'METHOD_NOT_ALLOWED']);
}
praesidium_require_csrf();
$token = praesidium_require_token();
$path = isset($_GET['path']) ? (string)$_GET['path'] : '';
$path = praesidium_validated_api_path($path);
if ($path !== '/certificates/upload') {
    praesidium_json(403, ['detail' => 'UPLOAD_PATH_NOT_ALLOWED']);
}
$contentType = strtolower(trim((string)($_SERVER['CONTENT_TYPE'] ?? '')));
if ($contentType !== 'application/octet-stream') {
    praesidium_json(415, ['detail' => 'UNSUPPORTED_MEDIA_TYPE']);
}
$encodedName = (string)($_SERVER['HTTP_X_FILE_NAME'] ?? '');
$fileName = rawurldecode($encodedName);
if ($encodedName === '' || strlen($encodedName) > 768 || !preg_match('/^[A-Za-z0-9_.@+-]{1,255}$/D', $fileName) || str_starts_with($fileName, '.')) {
    praesidium_json(400, ['detail' => 'INVALID_FILE_NAME']);
}
$contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
if ($contentLength > PRAESIDIUM_CERTIFICATE_UPLOAD_MAX_BYTES) {
    praesidium_json(413, ['detail' => 'REQUEST_TOO_LARGE']);
}
$fileBody = file_get_contents('php://input', false, null, 0, PRAESIDIUM_CERTIFICATE_UPLOAD_MAX_BYTES + 1);
if ($fileBody === false) {
    praesidium_json(400, ['detail' => 'UPLOAD_READ_FAILED']);
}
if ($fileBody === '') {
    praesidium_json(400, ['detail' => 'EMPTY_FILE']);
}
if (strlen($fileBody) > PRAESIDIUM_CERTIFICATE_UPLOAD_MAX_BYTES) {
    praesidium_json(413, ['detail' => 'REQUEST_TOO_LARGE']);
}

// ES: Construye un único campo multipart y reutiliza el transporte HTTP común.
// EN: Builds one multipart field and reuses the common HTTP transport.
$boundary = '----Praesidium' . bin2hex(random_bytes(16));
$multipartBody = '--' . $boundary . "\r\n"
    . 'Content-Disposition: form-data; name="file"; filename="' . $fileName . "\"\r\n"
    . "Content-Type: application/octet-stream\r\n\r\n"
    . $fileBody . "\r\n--" . $boundary . "--\r\n";
$response = praesidium_fastapi_request(
    'POST',
    $path,
    $token,
    $multipartBody,
    'application/json',
    'multipart/form-data; boundary=' . $boundary
);
if ((int)$response['status'] === 401) {
    praesidium_destroy_session();
}
praesidium_forward_json_response($response);
