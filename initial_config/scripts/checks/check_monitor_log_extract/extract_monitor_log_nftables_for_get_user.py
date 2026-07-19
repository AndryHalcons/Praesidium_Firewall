import os
import json
import sys
import gzip
import re

# --- Leer el JSON como argumento ---
if len(sys.argv) < 2:
    sys.exit("No se recibió ningún argumento JSON")

try:
    data = json.loads(sys.argv[1])
except json.JSONDecodeError:
    sys.exit("Error al decodificar el JSON recibido")

# --- Función para analizar una línea del log y extraer campos relevantes ---
def parse_log_line(line):
    timestamp = line.split()[0]
    parsed = {}
    # Añadir fecha y hora
    parsed["Date"] = timestamp.split("T")[0]
    parsed["Time"] = timestamp.split("T")[1][:5]  # HH:MM
    # Extraer id, chain y action del log de nftables
    if "nftables" in line:
        parts = line.split("nftables", 1)[1].strip().split()
        if len(parts) >= 3:
            parsed["ID"] = parts[0]
            parsed["Chain"] = parts[1]
            # Si el tercer elemento es IN=... o OUT=..., no hay acción -> poner NAT (ya que solo ocurre en este caso)
            if parts[2].startswith("IN=") or parts[2].startswith("OUT="):
                parsed["Action"] = "NAT"
            else:
                parsed["Action"] = parts[2].upper()


    # Extraer campos de red como interfaz de entrada/salida y puertos
    for key in ["IN", "OUT", "SPT", "DPT"]:
        token = f"{key}="
        for part in line.split():
            if part.startswith(token):
                parsed[key] = part[len(token):]  # puede ser cadena vacía

    # Extraer solo direcciones IP y protocolo
    for part in line.split():
        if part.startswith("SRC=") and not part.startswith("MACSRC="):
            parsed["SRC"] = part.split("=")[1]
        elif part.startswith("DST=") and not part.startswith("MACDST="):
            parsed["DST"] = part.split("=")[1]

        #elif part.startswith("PROTO=") and "PROTO" not in parsed:
        #    parsed["PROTO"] = part.split("=")[1]
        elif part.startswith("PROTO=") and "PROTO" not in parsed:
            proto_val = part.split("=")[1]
            parsed["PROTO"] = proto_val

            # Si es ICMP, buscar TYPE y CODE y usarlos como SPT/DPT
            if proto_val == "ICMP":
                type_val = None
                code_val = None
                for p in line.split():
                    if p.startswith("TYPE="):
                        type_val = p.split("=")[1]
                    elif p.startswith("CODE="):
                        code_val = p.split("=")[1]
                if type_val is not None:
                    parsed["SPT"] = f"TYPE={type_val}"
                if code_val is not None:
                    parsed["DPT"] = f"CODE={code_val}"
    return timestamp, parsed

# --- Función para leer líneas de un archivo ---
def leer_lineas_archivo(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line

# --- Función principal ---
def extraer_logs_formateados(data):
    log_dir = "/var/log/praesidium"

    # ES: El usuario llega ya fijado por PHP desde la sesión; aquí se valida de nuevo por defensa en profundidad.
    # EN: The user is already fixed by PHP from the session; validate again here for defense in depth.
    user = str(data.get('user', ''))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", user):
        sys.exit("Usuario inválido")

    # ES: Construir la ruta dentro del directorio permitido, sin aceptar subdirectorios del cliente.
    # EN: Build the path inside the allowed directory, without accepting client-controlled subdirectories.
    output_dir = "/var/lib/praesidium/state/monitor_log"
    output_path = os.path.join(output_dir, f"{user}_log_view.json")

    start_str = f"{data['Start_Date']}T{data['Start_Time']}"
    end_str = f"{data['End_Date']}T{data['End_Time']}"
    max_record = int(data['Max_Records'])

    os.makedirs(output_dir, exist_ok=True)

    resultado = {}
    count = 0

    for filename in sorted(os.listdir(log_dir)):
        if not filename.startswith("nftables.log"):
            continue

        full_path = os.path.join(log_dir, filename)

        for line in leer_lineas_archivo(full_path):
            ts_prefix = line[:16]

            if not (start_str <= ts_prefix <= end_str):
                continue

            if data['Source_IP'] and f"SRC={data['Source_IP']}" not in line:
                continue
            if data['Destination_IP'] and f"DST={data['Destination_IP']}" not in line:
                continue
            if data['Source_Port'] and f"SPT={data['Source_Port']}" not in line:
                continue
            if data['Destination_Port'] and f"DPT={data['Destination_Port']}" not in line:
                continue
            if data['Protocol'] and f"PROTO={data['Protocol'].upper()}" not in line:
                continue
            #if data['Action'] and data['Action'].upper() not in line:
            #    continue
            # --- dentro del bucle que recorre cada línea ---
            # Normalizar a minúsculas lo que llega en el JSON
            if data['Action']:
                action_filter = data['Action'].strip().lower()

                # Detectar acción real en la línea (si no hay, asumir 'accept')
                acciones_posibles = ["accept", "drop", "reject", "queue"]
                accion_en_linea = None
                for act in acciones_posibles:
                    if f" {act} " in line.lower():
                        accion_en_linea = act
                        break
                if accion_en_linea is None:
                    accion_en_linea = "accept"

                # Si no coincide con el filtro, saltar
                if accion_en_linea != action_filter:
                    continue


            ts, parsed = parse_log_line(line)
            resultado[ts] = parsed
            count += 1

            if count >= max_record:
                break
        if count >= max_record:
            break

    with open(output_path, "w") as out_file:
        json.dump(resultado, out_file, indent=4)

# --- Ejecutar ---
extraer_logs_formateados(data)
