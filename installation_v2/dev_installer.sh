#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Dar permisos de ejecución / Make scripts executable
echo "Dando permisos a los scripts... / Granting execution permissions..."
chmod +x system_configuration.sh
chmod +x configure_logs.sh
chmod +x initial_config/00_initial_config_main.sh
chmod +x praesidium_modules_installer/00_praesidium_modules_main_task_installer.py
chmod +x praesidium_modules_installer/01_praesidium_create_user_and_group.py
chmod +x praesidium_modules_installer/02_praesidium_fastapi_host_storage_installer.py
chmod +x praesidium_modules_installer/03_praesidium_install_fastapi.py
chmod +x praesidium_modules_installer/04_praesidium_generate_initial_certs.py

# Ejecutar instalador modular Praesidium / Run Praesidium modular installer
echo "Instalando estructura modular Praesidium... / Installing Praesidium modular structure..."
python3 praesidium_modules_installer/00_praesidium_modules_main_task_installer.py
echo "Instalación modular Praesidium completada / Praesidium modular installation completed"

# Ejecutar system_configuration.sh / Run system_configuration.sh
echo "Instalando system_configuration... / Installing system_configuration..."
./system_configuration.sh
echo "Instalación system_configuration.sh completada / Installation system_configuration.sh completed"

# Ejecutar configure_logs.sh / Run configure_logs.sh
echo "Configurando logs... / Configuring logs..."
./configure_logs.sh
echo "Instalación configure_logs.sh completada / Installation configure_logs.sh completed"

# Ejecutar initial_config/00_initial_config_main.sh al final para regenerar estado runtime.
# Run initial_config/00_initial_config_main.sh at the end to regenerate runtime state.
echo "Generando configuración inicial de desarrollo... / Generating development initial configuration..."
./initial_config/00_initial_config_main.sh
echo "Instalación 00_initial_config_main.sh completada / Installation 00_initial_config_main.sh completed"


# Ejecutar web_installation.sh como último paso.
# Run web_installation.sh as the last step.
echo "Instalando WebGUI... / Installing WebGUI..."
./web_installation.sh
echo "Instalación web_installation.sh completada / Installation web_installation.sh completed"
