import os
import shutil
import glob
import json
import yaml
import sys
from pathlib import Path

INTERFACE_HELPERS_DIR = Path(os.environ.get("PRAESIDIUM_INTERFACE_HELPERS_DIR", "/var/lib/praesidium/scripts/checks/check_interfaces"))
SOURCE_INTERFACE_HELPERS_DIR = Path(__file__).resolve().parents[1] / "checks" / "check_interfaces"
for helper_dir in (INTERFACE_HELPERS_DIR, SOURCE_INTERFACE_HELPERS_DIR):
    if helper_dir.exists() and str(helper_dir) not in sys.path:
        sys.path.insert(0, str(helper_dir))
from interface_uuid_helpers import ensure_interface_uuids
import pwd
import grp



# Convierte Netplan YAML en JSON plano con claves tipo padre.hijo, todo como string
# Converts Netplan YAML into flat JSON with keys like parent.child, all values as strings
def create_convert_interfaces_json(source_path, destination_path):
    with open(source_path, "r") as f:
        netplan_data = yaml.safe_load(f)

    # Aplanar diccionario y convertir todo a string
    # Flatten dictionary and convert everything to string
    def flatten_and_stringify(d, parent_key=""):
        items = {}
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(flatten_and_stringify(v, new_key))
            elif isinstance(v, list):
                items[new_key] = ",".join(str(i) for i in v)
            else:
                items[new_key] = str(v)
        return items

    # Inicializar estructura base
    # Initialize base structure
    flat_json = {}
    for top_key, top_value in netplan_data.items():
        if isinstance(top_value, dict):
            flat_json[top_key] = {}
            for sub_key, sub_value in top_value.items():
                if isinstance(sub_value, dict):
                    flat_json[top_key][sub_key] = {}
                    for iface, config in sub_value.items():
                        if isinstance(config, dict):
                            flat_json[top_key][sub_key][iface] = flatten_and_stringify(config)
                        else:
                            flat_json[top_key][sub_key][iface] = str(config)
                else:
                    flat_json[top_key][sub_key] = str(sub_value)
        else:
            flat_json[top_key] = str(top_value)

    ensure_interface_uuids(flat_json)

    # Guardar el JSON plano
    # Save the flattened JSON
    with open(destination_path, "w") as f:
        json.dump(flat_json, f, indent=4)
    # Cambiar grupo a www-data y establecer permisos rw-rw-r--
    gid = grp.getgrnam("www-data").gr_gid
    os.chown(destination_path, os.getuid(), gid)
    os.chmod(destination_path, 0o664)



# Genera el archivo JSON si no existe, usando el primer archivo YAML de Netplan
# Generates the JSON file if it doesn't exist, using the first Netplan YAML file
def generate_interfaces_json():
    destination_path = "/var/lib/praesidium/candidate/interfaces.json"

    # Solo continuar si el archivo no existe
    # Only proceed if the file doesn't exist
    if not os.path.exists(destination_path):
        netplan_files = glob.glob("/etc/netplan/*.yaml")

        # Si hay al menos un archivo YAML, usar el primero
        # If there's at least one YAML file, use the first one
        if netplan_files:
            source_path = netplan_files[0]
            #se genera un nuevo archivo interfaces.json con la configuracion del archivo netplan
            #a new interfaces.json file is generated with the configuration of the netplan file
            create_convert_interfaces_json(source_path, destination_path)
