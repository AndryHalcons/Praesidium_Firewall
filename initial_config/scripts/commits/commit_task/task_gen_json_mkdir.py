import os
import shutil
from task_update_json import task_update_json




"""
def copy_to_running(date):
    #directorio origen configuracion
    #configuration source directory
    source_dir = '/var/lib/praesidium/candidate'

    #directorio destino ejecución
    #destination directory for runtime
    running_dir = '/var/lib/praesidium/running'

    #proceso de copia de archivos
    #file copy process
    try:
        os.makedirs(running_dir, exist_ok=True)

        files_to_copy = [
            'interfaces.json',
            'routes.json',
            'rules_nftables_human_viewer.json',
            'rules_bpfilter_human_viewer.json',
            'users.json',
            'alias.json',
            'system_config.json',
        ]

        for filename in files_to_copy:
            source_file = os.path.join(source_dir, filename)
            running_file = os.path.join(running_dir, filename)
            if os.path.exists(source_file):
                shutil.copy2(source_file, running_file)
        task_update_json(date, "gen_json_mkdir_copy_to_running", "success")

    except Exception:
        task_update_json(date, "gen_json_mkdir_copy_to_running", "fail")
"""
"""
def gen_json_mkdir(user, date):
    #directorio origen configuracion
    #configuration source directory
    source_dir = '/var/lib/praesidium/candidate'

    #directorio destino archivos commit
    #destination directory for commit files
    target_dir = f'/var/lib/praesidium/commits/commit_{user}_{date}'

    #proceso de copia de archivos
    #file copy process
    try:
        os.makedirs(target_dir, exist_ok=True)

        files_to_copy = [
            'interfaces.json',
            'routes.json',
            'rules_nftables_human_viewer.json',
            'rules_bpfilter_human_viewer.json',
            'users.json',
            'alias.json',
            'system_config.json',

        ]

        for filename in files_to_copy:
            source_file = os.path.join(source_dir, filename)
            target_file = os.path.join(target_dir, filename)
            if os.path.exists(source_file):
                shutil.copy2(source_file, target_file)

        # Si todo va bien actualizamos el commit_history.json añadiendo a la entrada success
        # If everything goes well, update commit_history.json adding success to the entry
        task_update_json(date, "gen_json_mkdir", "success")
        #funcion que pone los archivos de configuracion tambien en el directorio config_running
        copy_to_running(date)
    except Exception:
        # Si algo falla actualizamos el commit_history.json añadiendo a la entrada fail
        # If something fails, update commit_history.json adding fail to the entry
        task_update_json(date, "gen_json_mkdir", "fail")

"""

def copy_to_running(date):
    source_dir = '/var/lib/praesidium/candidate'
    running_dir = '/var/lib/praesidium/running'

    try:
        shutil.copytree(source_dir, running_dir, dirs_exist_ok=True)
        task_update_json(date, "gen_json_copytree_to_running", "success")
    except Exception:
        task_update_json(date, "gen_json_copytree_to_running", "fail")




def gen_json_mkdir(user, date):
    # Directorio origen de configuración
    # Configuration source directory
    source_dir = '/var/lib/praesidium/candidate'

    # Directorio destino para archivos de commit
    # Destination directory for commit files
    target_dir = f'/var/lib/praesidium/commits/commit_{user}_{date}'

    try:
        # Crea el directorio destino si no existe
        # Create target directory if it doesn't exist
        os.makedirs(target_dir, exist_ok=True)

        # Recorre el contenido del directorio fuente
        # Iterate through source directory contents
        for item in os.listdir(source_dir):
            if item == 'commit_history':
                continue  # Evita copiar el historial dentro de sí mismo
                          # Skip copying commit_history to avoid recursion

            source_path = os.path.join(source_dir, item)
            target_path = os.path.join(target_dir, item)

            # Si es un directorio, lo copia completamente
            # If it's a directory, copy it entirely
            if os.path.isdir(source_path):
                shutil.copytree(source_path, target_path, dirs_exist_ok=True)
            else:
                # Si es un archivo, lo copia directamente
                # If it's a file, copy it directly
                shutil.copy2(source_path, target_path)

        # Actualiza el historial con éxito
        # Update commit history with success
        task_update_json(date, "gen_json_mkdir", "success")

        # También copia los archivos al directorio de ejecución
        # Also copy files to the runtime directory
        copy_to_running(date)

    except Exception:
        # Actualiza el historial con fallo
        # Update commit history with failure
        task_update_json(date, "gen_json_mkdir", "fail")






#gen_json_mkdir("PRUEBA","2025090716335252d")
