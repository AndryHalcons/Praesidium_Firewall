import shutil
import subprocess
import os
from task_update_json import task_update_json

def get_existing_netplan_file(user, date):
    # Busca el archivo YAML existente en /etc/netplan  
    # Finds the existing YAML file in /etc/netplan
    try:
        files = [f for f in os.listdir("/etc/netplan") if f.endswith(".yaml") or f.endswith(".yml")]
        if len(files) == 1:
            return files[0]
        elif len(files) > 1:
            # Si hay más de uno, elige el primero 
            # If more than one, pick the first 
            return files[0]
        else:
            return None
    except Exception:
        task_update_json(date, "apply_interfaz_get_netplan_file", "fail")
        exit()


def apply_netplan_config(user, date, source_path):
    # Aplica el archivo YAML especificado como configuración de red  
    # Applies the specified YAML file as network configuration
    try:
        existing_file = get_existing_netplan_file(user, date)
        if not existing_file:
            task_update_json(date, "apply_interfaz_config", "fail")
            exit()

        destination_path = os.path.join("/etc/netplan", existing_file)

        # Sobrescribe el archivo existente con el nuevo  
        # Overwrites the existing file with the new one
        shutil.copy2(source_path, destination_path)

        # Aplica la configuración con netplan  
        # Applies the configuration using netplan
        result = subprocess.run(
            ["netplan", "apply"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            task_update_json(date, "apply_interfaz_config", "fail")
            exit()

        task_update_json(date, "apply_interfaz_config", "success")

    except Exception as e:
        task_update_json(date, "apply_interfaz_config", "fail")
        exit()



def apply_interface_config(user, date):
    source_path = "/var/lib/praesidium/running/interfaces.yml"
    apply_netplan_config(user, date, source_path)

