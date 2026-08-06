# Diseño FastAPI nativo - Praesidium

## 1. Objetivo

FastAPI forma parte de Praesidium como servicio local del firewall. Se despliega como servicio systemd, sin red bridge, sin publicación NAT de puertos y sin dependencia de iptables.

## 2. Ubicación en el repositorio

```text
fastApi/
 ├── app/
 ├── dependencies/
 ├── requirements.txt
 ├── tests/
 ├── FASTAPI_DESIGN.md
 └── fastapi_map.txt
```

## 3. Ubicación instalada

El instalador v2 copia la aplicación a:

```text
/opt/praesidium/fastapi
```

Estructura instalada esperada:

```text
/opt/praesidium/fastapi/app
/opt/praesidium/fastapi/dependencies
/opt/praesidium/fastapi/requirements.txt
/opt/praesidium/fastapi/.venv
/opt/praesidium/fastapi/.env
```

## 4. Servicio systemd

FastAPI se ejecuta con:

```text
praesidium-fastapi.service
```

Unidad instalada en:

```text
/etc/systemd/system/praesidium-fastapi.service
```

El servicio arranca Uvicorn accesible por red:

```text
0.0.0.0:8000
```

## 5. Dependencias offline

Las dependencias Python se guardan como wheels locales en:

```text
fastApi/dependencies
```

Durante la instalación se copian a:

```text
/opt/praesidium/fastapi/dependencies
```

La instalación del venv debe usar solo paquetes locales:

```text
pip install --no-index --find-links=/opt/praesidium/fastapi/dependencies -r /opt/praesidium/fastapi/requirements.txt
```

## 6. Rutas runtime

FastAPI trabaja directamente contra rutas del sistema host:

```text
/var/lib/praesidium
/var/log/praesidium
```

Subdirectorios de datos:

```text
/var/lib/praesidium/candidate
/var/lib/praesidium/running
/var/lib/praesidium/commits
/var/lib/praesidium/backups
/var/lib/praesidium/state
/var/lib/praesidium/scripts
```

## 7. Configuración .env

El instalador genera:

```text
/opt/praesidium/fastapi/.env
```

Valores principales:

```text
PRAESIDIUM_DATA_ROOT=/var/lib/praesidium
PRAESIDIUM_LOG_ROOT=/var/log/praesidium
```

## 8. Regla de diseño

Los módulos FastAPI no deben hardcodear rutas absolutas de datos. Deben usar:

```text
settings.data_root
```

o los helpers comunes de storage.

## 9. Verificación mínima

La instalación solo se considera válida si responde:

```text
GET http://0.0.0.0:8000/health
```

con estado correcto.
