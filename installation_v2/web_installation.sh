#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SCRIPT_DIR}/../web_gui/*"
DEST_DIR="/var/www/html"

# Borrar contenido anterior / Delete previous content
rm -rf "${DEST_DIR}"/*

# Copiar nuevo contenido / Copy new content
cp -r ${SOURCE_DIR} "${DEST_DIR}"/

# Ajustar propiedad y permisos WebGUI / Fix WebGUI ownership and permissions
chown -R www-data:www-data "${DEST_DIR}"
find "${DEST_DIR}" -type d ! -path "${DEST_DIR}/session*" -exec chmod 755 {} +
find "${DEST_DIR}" -type f ! -path "${DEST_DIR}/session/*" -exec chmod 644 {} +
if [ -d "${DEST_DIR}/session" ]; then
    find "${DEST_DIR}/session" -type d -exec chmod 750 {} +
    find "${DEST_DIR}/session" -type f -name "*.php" -exec chmod 640 {} +
fi
