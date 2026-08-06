import json
import os



def ensure_commit_history():
    # Asegurar que el directorio y archivo existen
    # Ensure the directory and file exist; if missing, create them.
    history_dir = '/var/lib/praesidium/commits'
    history_file = os.path.join(history_dir, 'commit_history.json')

    # Verificar si el directorio existe
    # Check if the directory exists
    if not os.path.exists(history_dir):
        os.makedirs(history_dir)

    # Verificar si el archivo existe , si no lo creamos.
    # Check if the file exists if missing, create them.
    if not os.path.exists(history_file):
        with open(history_file, 'w') as f:
            json.dump({"commits": {}}, f, indent=4)

def gen_json_entry(user, date):
    history_path = '/var/lib/praesidium/commits/commit_history.json'

    # Asegurar que el directorio y archivo existen
    # Ensure the directory and file exist; if missing, create them.
    ensure_commit_history()

    # Formatear fecha como yyyy/mm/dd
    #Format date as yyyy/mm/dd
    formatted_date = f"{date[0:4]}/{date[4:6]}/{date[6:8]}"

    # Generar ruta de directorio
    # Generate directory path
    commit_directory = f"/var/lib/praesidium/commits/commit_{user}_{date}"

    # Construir entrada
    #Build entry
    new_entry = {
        "date": formatted_date,
        "directory": commit_directory,
        "task": "process",
        "user": user
    }

    # Crear archivo si no existe
    #Create file if it doesn't exist
    if not os.path.exists(history_path):
        with open(history_path, 'w') as f:
            json.dump({"commits": {}}, f, indent=4)

    # Cargar contenido actual
    #Load current content
    with open(history_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = {"commits": {}}

    # Insertar nueva entrada usando date como clave
    #Insert new entry using date as key
    data["commits"][date] = new_entry

    # Guardar cambios
    #Save changes
    with open(history_path, 'w') as f:
        json.dump(data, f, indent=4)
