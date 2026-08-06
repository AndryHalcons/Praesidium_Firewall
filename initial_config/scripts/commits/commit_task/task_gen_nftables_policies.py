import json
import subprocess
import os
import convert_nftables
from collections import defaultdict
from task_update_json import task_update_json

from convert_nftables import (
    validation_icmp_no_ports,
    Main_convert_alias_object_to_network_object,
    comment_convert_id_name,
    validation_form_field_review,
    assign_position,
    log_format_nft,
    saniticed_nftables_policy,
    update_or_insert_nft_rule
)

# Aplica todas las validaciones necesarias a una regla nftables
# Applies all required validations to an nftables rule
def validate_nftables_policy(rule: dict, date):
    rule = validation_icmp_no_ports(rule)
    rule = Main_convert_alias_object_to_network_object(rule, date)
    rule = comment_convert_id_name(rule)
    validation_form_field_review(rule, date)
    rule = assign_position(rule)
    rule = log_format_nft(rule)
    return rule




def verify_nftables_json(date,json_path):
    #verifies that the nftables file has no errors, contains properly formed rules, and is syntactically correct
    #verifica que el archivo nftables no tiene errores, tiene reglas correctamente formadas y está correcto sintacticamente
    try:
        subprocess.run(["sudo", "nft", "-j", "-f", json_path, "--check"], check=True)
        task_update_json(date, "verify_nftables_json", "success")
    except subprocess.CalledProcessError as e:
        task_update_json(date, "verify_nftables_json", "fail")
        exit()





# Convierte las reglas del archivo human_viewer y actualiza el archivo backend
# Converts rules from human_viewer file and updates the backend rules file
def gen_nftables_policies(user, date):
    #print(date)
    try:
        #template json
        
        json_path = "/var/lib/praesidium/running/nftables_tables_chains.json"
        output_path = "/var/lib/praesidium/running/nftables_format.json"
        # Verifica si el archivo de reglas existe
        if not os.path.exists(json_path):
            task_update_json(date, "nftables_convert_json_exist", "fail")
            return

        # Carga el archivo de reglas actuales
        with open(json_path, "r", encoding="utf-8") as f:
            rules_json = json.load(f)

        # Verifica que el JSON tenga la clave 'nftables'
        if "nftables" not in rules_json:
            #print(json.dumps({"error": "'nftables' no presente en rules_nftables_formatn"}))
            task_update_json(date, "nftables_convert_json_format", "fail")
            return

        # Elimina todas las entradas que contienen la clave 'rule'
        rules_json["nftables"] = [
            entry for entry in rules_json["nftables"] if "rule" not in entry
        ]
        #archivo del cual extraeremos las reglas a aplicar
        human_path = "/var/lib/praesidium/running/rules_nftables_human_viewer.json"

        # Verifica si el archivo human_viewer existe
        if not os.path.exists(human_path):
            task_update_json(date, "nftables_convert_human_viewer", "fail")
            return

        # Carga el archivo human_viewer
        with open(human_path, "r", encoding="utf-8") as f:
            human_json = json.load(f)

        # Verifica que el JSON tenga la clave 'nftables'
        if "nftables" not in human_json:
            #print(json.dumps({"error": "'nftables' no presente en rules_nftables_human_viewer.json"}))
            task_update_json(date, "nftables_convert_nftablesKey", "fail")
            return

        # Itera sobre cada regla habilitada en human_viewer
        for entry in human_json["nftables"]:
            rule = entry.get("rule")
            if not isinstance(rule, dict):
                continue
            if rule.get("enable") != "true":
                continue

            validated = validate_nftables_policy(rule, date)
            sanitized = saniticed_nftables_policy(validated)
            # Inserta o actualiza la regla en el archivo backend
            rules_json = update_or_insert_nft_rule(sanitized["rule"], rules_json)
        # Guarda el archivo actualizado de reglas
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(rules_json, f, indent=2, ensure_ascii=False)

        task_update_json(date, "nftables_convert", "success")

    except Exception as e:
        task_update_json(date, "nftables_convert", "fail")
    verify_nftables_json(date, output_path)



#gen_nftables_policies("20250907163352")