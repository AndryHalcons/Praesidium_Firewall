#!/usr/bin/env python3
"""
ES:
    Genera la configuración candidata de Apache para el plano de gestión.

    Este archivo NO modifica Apache directamente. Lee /var/lib/praesidium/candidate/management.json,
    valida IP, puertos, redes permitidas y material TLS, y escribe un candidato en
    /var/lib/praesidium/running/praesidium_management_apache.conf.

EN:
    Generate the candidate Apache configuration for the management plane.

    This file does NOT modify Apache directly. It reads /var/lib/praesidium/candidate/management.json,
    validates IP, ports, allowed networks and TLS material, then writes a candidate to
    /var/lib/praesidium/running/praesidium_management_apache.conf.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

from task_update_json import task_update_json

# Rutas runtime usadas por el pipeline de commit de Praesidium.
# Runtime paths used by Praesidium's commit pipeline.
CONFIG_PATH = Path('/var/lib/praesidium/candidate/management.json')
RUNNING_PATH = Path('/var/lib/praesidium/running/management.json')
CERT_DIR = Path('/var/lib/praesidium/candidate/certificates')
CANDIDATE_PATH = Path('/var/lib/praesidium/running/praesidium_management_apache.conf')


def _task(user: str, date: str, name: str, status: str) -> None:
    """
    ES: Registra una tarea en commit_history sin escribir en stdout.

    El endpoint PHP de commit espera que commit_apply.py devuelva un único JSON final.
    Por eso las tareas internas NO deben imprimir líneas JSON intermedias.

    EN: Register a task in commit_history without writing to stdout.

    The commit PHP endpoint expects commit_apply.py to return one final JSON object.
    Therefore internal tasks must NOT print intermediate JSON lines.
    """
    task_update_json(date, name, status)


def _load_config() -> dict:
    """
    ES: Carga management.json y exige que la raíz sea un objeto JSON.
    EN: Load management.json and require the root to be a JSON object.
    """
    with CONFIG_PATH.open('r', encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError('management.json root must be an object')
    return data


def _validate_file_name(value: str) -> str:
    """
    ES: Valida un nombre de archivo TLS y confirma que existe en CERT_DIR.
    EN: Validate a TLS file name and confirm it exists under CERT_DIR.
    """
    value = os.path.basename(str(value))
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,160}', value):
        raise ValueError(f'invalid certificate file name: {value!r}')
    path = CERT_DIR / value
    if not path.is_file():
        raise FileNotFoundError(str(path))
    return value


def _openssl_modulus(path: Path, mode: str) -> str:
    """
    ES: Extrae el módulo RSA de un certificado o clave para comprobar pareja TLS.
    EN: Extract the RSA modulus from a certificate or key to check the TLS pair.
    """
    if mode == 'cert':
        cmd = ['openssl', 'x509', '-noout', '-modulus', '-in', str(path)]
    else:
        cmd = ['openssl', 'rsa', '-noout', '-modulus', '-in', str(path)]
    result = subprocess.run(cmd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _management_api_proxy_block() -> str:
    """
    ES:
        Devuelve el puente Apache interno entre WebGUI y FastAPI.

        La WebGUI nueva consume /api/v1 en el mismo origen HTTPS que sirve
        /var/www/html. Apache mantiene el punto público y reenvía sólo las rutas
        API necesarias hacia FastAPI local; no se expone el puerto 8000 como
        destino externo.

    EN:
        Return the internal Apache bridge between WebGUI and FastAPI.

        The new WebGUI consumes /api/v1 from the same HTTPS origin that serves
        /var/www/html. Apache keeps the public endpoint and forwards only the
        required API routes to local FastAPI; port 8000 is not exposed as an
        external destination.
    """
    return """    # ES: Puente interno WebGUI -> FastAPI. No editar manualmente; se regenera en commit.
    # EN: Internal WebGUI -> FastAPI bridge. Do not edit manually; regenerated on commit.
    ProxyPreserveHost On
    ProxyPass /api/v1 http://127.0.0.1:8000/api/v1
    ProxyPassReverse /api/v1 http://127.0.0.1:8000/api/v1
    ProxyPass /health http://127.0.0.1:8000/health
    ProxyPassReverse /health http://127.0.0.1:8000/health
"""


def _build_conf(data: dict) -> str:
    """
    ES: Construye el texto de Apache desde las tablas management validadas.
    EN: Build Apache configuration text from validated management tables.
    """
    # La tabla listener y TLS son singleton; usamos la primera fila.
    # Listener and TLS tables are singletons; use the first row.
    listener = (data.get('table_management_listener') or [{}])[0]
    tls = (data.get('table_management_tls') or [{}])[0]

    # ES: Todas las redes existentes se convierten en Require ip; no hay interruptor por fila.
    # EN: Every existing network becomes a Require ip directive; there is no per-row switch.
    sources = list(data.get('table_management_allowed_sources', []))

    # ES: El listener Apache de gestión está siempre activo por diseño appliance.
    #     No existe interruptor editable porque apagarlo puede bloquear la WebGUI.
    # EN: The management Apache listener is always active by appliance design.
    #     There is no editable switch because turning it off can lock out the WebGUI.

    # ES: El plano de gestión sólo debe exponerse por HTTPS.
    # EN: The management plane must be exposed through HTTPS only.

    # Validación estricta de IP, puerto HTTPS y ServerName antes de escribir Apache conf.
    # Strict validation of IP, HTTPS port and ServerName before writing Apache conf.
    ip = str(listener.get('listen_ip', '')).strip()
    ipaddress.ip_address(ip)
    port = int(listener.get('listen_port', '0'))
    if port < 1 or port > 65535:
        raise ValueError('invalid listen_port')
    server_name = str(listener.get('server_name', 'praesidium.local')).strip()
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', server_name):
        raise ValueError('invalid server_name')

    # Valida que certificado, clave y cadena existan y que cert/key formen pareja.
    # Validate that certificate, key and chain exist and cert/key match.
    cert = _validate_file_name(tls.get('certificate_file', ''))
    key = _validate_file_name(tls.get('certificate_key', ''))
    chain = _validate_file_name(tls.get('certificate_chain', ''))
    if _openssl_modulus(CERT_DIR / cert, 'cert') != _openssl_modulus(CERT_DIR / key, 'key'):
        raise ValueError('certificate and key do not match')

    # Traduce redes permitidas a directivas Apache.
    # Translate allowed networks to Apache directives.
    require_lines = []
    for row in sources:
        cidr = str(row.get('source_cidr', '')).strip()
        network = ipaddress.ip_network(cidr, strict=False)

        # Apache no acepta 0.0.0.0/0 como Require ip; para todos se usa Require all granted.
        # Apache does not accept 0.0.0.0/0 as Require ip; use Require all granted for everyone.
        if network.prefixlen == 0:
            require_lines = ['        Require all granted']
            break

        require_lines.append(f'        Require ip {cidr}')
    if not require_lines:
        require_lines = ['        Require all denied']

    # ES: No se genera VirtualHost HTTP/80; 000-default.conf se deshabilita en apply.
    # EN: No HTTP/80 VirtualHost is generated; 000-default.conf is disabled during apply.

    # Vhost HTTPS principal del plano de gestión.
    # Main HTTPS vhost for the management plane.
    return f"""# Generated by Praesidium management module.
# Do not edit manually; edit /var/lib/praesidium/candidate/management.json and commit.
Listen {ip}:{port}

<VirtualHost {ip}:{port}>
    ServerName {server_name}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile {CERT_DIR / cert}
    SSLCertificateKeyFile {CERT_DIR / key}
    SSLCertificateChainFile {CERT_DIR / chain}

    # ES: Cabeceras globales de hardening del plano de gestión.
    #     La CSP mantiene 'unsafe-inline' porque la WebGUI actual usa scripts y estilos inline.
    # EN: Global hardening headers for the management plane.
    #     CSP keeps 'unsafe-inline' because the current WebGUI uses inline scripts and styles.
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "same-origin"
    Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"

{_management_api_proxy_block()}    <Directory /var/www/html>
        Options -Indexes +FollowSymLinks
        AllowOverride None
{chr(10).join(require_lines)}
    </Directory>

    ErrorLog ${{APACHE_LOG_DIR}}/praesidium_management_error.log
    CustomLog ${{APACHE_LOG_DIR}}/praesidium_management_access.log combined
</VirtualHost>
"""


def gen_management_apache(user: str, date: str):
    """
    ES: Punto de entrada llamado por main_task.py durante generate_config.
    EN: Entry point called by main_task.py during generate_config.
    """
    try:
        data = _load_config()
        _task(user, date, 'verify_management_json', 'success')

        try:
            candidate = _build_conf(data)
            _task(user, date, 'verify_management_apache_model', 'success')
        except Exception:
            _task(user, date, 'verify_management_apache_model', 'fail')
            raise

        CANDIDATE_PATH.write_text(candidate, encoding='utf-8')
        RUNNING_PATH.write_text(json.dumps(data, indent=4, ensure_ascii=False) + '\n', encoding='utf-8')
        _task(user, date, 'gen_management_apache_config', 'success')
        _task(user, date, 'gen_management_apache', 'success')
    except Exception:
        _task(user, date, 'gen_management_apache', 'fail')
        raise
