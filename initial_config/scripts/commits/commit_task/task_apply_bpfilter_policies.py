import subprocess
from task_update_json import task_update_json
from collections import defaultdict

def apply_bpfilter_policies(user, date):
    loadPolicyPath = "/var/lib/praesidium/running/bpfilter_machine_format.txt"
    try:
        result = subprocess.run(
            ["sudo", "/usr/local/bin/bfcli", "ruleset", "set", "--from-file", loadPolicyPath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Si hay cualquier salida en stderr, es un fail
        if result.stderr.strip():
            task_update_json(date, "apply_bpfilter_policy", "fail")
        else:
            task_update_json(date, "apply_bpfilter_policy", "success")

    except Exception:
        task_update_json(date, "apply_bpfilter_policy", "fail")
