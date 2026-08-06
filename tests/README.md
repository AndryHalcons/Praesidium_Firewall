# PraesidiumFirewall tests

## Objetivo

Esta carpeta contiene la suite de tests de PraesidiumFirewall.
La estructura separa los tests por perfil de riesgo y por modulo funcional.

## Estructura

- `run_tests.sh`: runner principal.
- `test_profiles/`: suites transversales por tipo de riesgo: safe, validation, web, security, commit, e2e e installer.
- `test_modules/`: suites por modulo funcional: nftables, bpfilter, dnsmasq, services, wireguard, users, certificates, interfaces, monitor, system_logging y alias.
- `fixtures/`: payloads y allowlists reutilizables.
- `lib/`: helpers comunes para Python/Bash.
- `reports/`: salida generada por ejecuciones locales; no deberia versionar resultados reales.

## Regla de seguridad

Los comandos por defecto son no destructivos. Los tests `commit`, `e2e` e `installer` deben exigir una confirmacion explicita de laboratorio antes de tocar servicios, firewall, red o runtime.

## Ejemplos

```bash
./tests/run_tests.sh safe
./tests/run_tests.sh module nftables
PRAESIDIUM_ALLOW_DESTRUCTIVE=1 ./tests/run_tests.sh commit
```
