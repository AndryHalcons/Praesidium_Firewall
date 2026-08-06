# WireGuard WebGUI generic-table control state

## Scope

```text
wireguard_site_to_site -> completed
wireguard_server       -> completed
wireguard_clients      -> completed
```

## FastAPI mapping

```text
wireguard_site_to_site -> /wireguard/site-to-site
wireguard_server       -> /wireguard/remote-access
wireguard_clients      -> /wireguard/remote-clients
```

## Current task boundary

Only `wireguard_server` is being migrated in this phase. Do not modify FastAPI, `generic_table.js`, or `wireguard_clients` unless Andrés explicitly authorizes it.

## wireguard_server contract

```text
section: wireguard_server
rows_key: entries
payload_wrapper: rule
row_key: name
context_key: name
CRUD identity: FastAPI remote-access name
name: backend-generated, visible readonly
```

## Files

```text
web_gui/js/pages/wireguard/forms_wireguard_server.json
web_gui/js/pages/wireguard/structure_tables_wireguard_server.json
web_gui/js/pages/wireguard/wireguard_server_commands_api.json
web_gui/js/pages/wireguard/wireguard.js
web_gui/lang/english.json
web_gui/lang/espanol.json
```

## wireguard_clients identity

```text
id     -> lowest free positive integer, readonly
UUID   -> wgclient + id through core.identifiers, hidden
name   -> user-defined and editable
vpn    -> displays server name and stores server UUID
CRUD/export -> client UUID
```

## wireguard_server identity

```text
id   -> lowest free positive integer, readonly
UUID -> wgserv + id through core.identifiers, hidden
name -> user-defined and editable
CRUD -> UUID
```

## wireguard_server Alias fields

```text
server_vpn_ip    -> alias_address + literal, single_net_check
vpn_network      -> alias_address/group + literals
listen_port      -> alias_service + literal, single_port_check
public_endpoint  -> alias_address/IP or hostname literal
internal_networks -> alias_address/group + literals
dns              -> alias_address/IP hosts; groups forbidden
```

## Verification

```text
JSON syntax
node --check wireguard.js
WEBGUI SECURITY AUDIT PASSED
installation_v2/dev_installer.sh
runtime static files HTTP 200
browser page/console
real create/list/patch/get/delete with cleanup
```
