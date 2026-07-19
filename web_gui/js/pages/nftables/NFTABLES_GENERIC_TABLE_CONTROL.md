# Nftables generic-table migration control

Scope authorized by Andrés:

```text
web_gui/js/pages/nftables/
web_gui/lang/espanol.json
web_gui/lang/english.json
web_gui/index.html
web_gui/js/app-state.js
web_gui/js/pages/registry.js
```

Core generic table is not authorized and must remain untouched:

```text
web_gui/js/core/generic_table.js
```

Implemented sections:

```text
nftables_forwarding   -> GET/POST/PATCH/DELETE /nftables/filter/FORWARDING
nftables_prerouting   -> GET/POST/PATCH/DELETE /nftables/nat/PREROUTING
nftables_postrouting  -> GET/POST/PATCH/DELETE /nftables/nat/POSTROUTING
nftables_input        -> GET/POST/PATCH/DELETE /nftables/filter/input
nftables_output       -> GET/POST/PATCH/DELETE /nftables/filter/output
```

Checks required before completion:

```text
all JSON valid
all boolean true/false fields declared as checkbox
meta.iifname/meta.oifname use select_list with ethernets+bridges+bonds+vlans+wifis
WEBGUI SECURITY AUDIT PASSED
node --check all nftables JS
runtime static files 200
OpenAPI paths exist
```
