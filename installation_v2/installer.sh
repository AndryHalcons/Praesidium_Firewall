#!/bin/bash
set -e

# Dar permisos de ejecución / Make scripts executable
echo "Dando permisos a los scripts... / Granting execution permissions..."
chmod +x uninstall_unnecessary.sh
chmod +x system_requirements.sh
chmod +x system_configuration.sh
chmod +x initial_config/00_initial_config_main.sh
chmod +x install_bpfilter.sh
chmod +x configure_bpfilter.sh
chmod +x configure_logs.sh
chmod +x configure_dnsmasq.sh
chmod +x web_installation.sh
chmod +x praesidium_modules_installer/00_praesidium_modules_main_task_installer.py
chmod +x praesidium_modules_installer/01_praesidium_fastapi_host_storage_installer.py
chmod +x praesidium_modules_installer/02_praesidium_install_fastapi.py
chmod +x praesidium_modules_installer/03_praesidium_generate_initial_certs.py



# Ejecutar uninstall_unnecessary.sh / Run uninstall_unnecessary.sh
echo "Desinstalando dependencias innecesarias... / Uninstalling unnecessary dependencies..."
./uninstall_unnecessary.sh
echo "Desinstalación uninstall_unnecessary.sh completada / uninstall_unnecessary.sh completed"

# Ejecutar system_requirements.sh / Run system_requirements.sh
echo "Instalando dependencias del sistema... / Installing system dependencies..."
./system_requirements.sh
echo "Instalación system_requirements.sh completada / Installation system_requirements.sh completed"

# Ejecutar configure_dnsmasq.sh / Run configure_dnsmasq.sh
echo "Configurando dnsmasq solo para DHCP... / Configuring dnsmasq for DHCP only..."
./configure_dnsmasq.sh
echo "Instalación configure_dnsmasq.sh completada / Installation configure_dnsmasq.sh completed"

# Ejecutar instalador modular Praesidium / Run Praesidium modular installer
echo "Instalando estructura modular Praesidium... / Installing Praesidium modular structure..."
python3 praesidium_modules_installer/00_praesidium_modules_main_task_installer.py
echo "Instalación modular Praesidium completada / Praesidium modular installation completed"

# Ejecutar system_configuration.sh / Run system_configuration.sh
echo "Instalando system_configuration... / Installing system_configuration..."
./system_configuration.sh
echo "Instalación system_configuration.sh completada / Installation system_configuration.sh completed"



# Ejecutar install_bpfilter.sh / Run install_bpfilter.sh
echo "Instalando bpfilter / Installing bpfilter"
./install_bpfilter.sh
echo "Instalación install_bpfilter.sh completada / Installation install_bpfilter.sh completed"


# Ejecutar configure_bpfilter.sh / Run configure_bpfilter.sh
echo "Configurando bpfilter / Configuring bpfilter"
./configure_bpfilter.sh
echo "Configuración configure_bpfilter.sh completada / configure_bpfilter.sh completed"


# Ejecutar configure_logs.sh / Run configure_logs.sh
echo "Configurando logs / Configuring logs"
./configure_logs.sh
echo "Instalación configure_logs.sh completada / Installation configure_logs.sh completed"



# Ejecutar initial_config/00_initial_config_main.sh al final de toda la instalación.
# Run initial_config/00_initial_config_main.sh at the end of the whole installation.
echo "Generando configuración inicial... / Generating initial configuration..."
./initial_config/00_initial_config_main.sh
echo "Instalación 00_initial_config_main.sh completada / Installation 00_initial_config_main.sh completed"


# Ejecutar web_installation.sh como último paso.
# Run web_installation.sh as the last step.
echo "Instalando WebGUI... / Installing WebGUI..."
./web_installation.sh
echo "Instalación web_installation.sh completada / Installation web_installation.sh completed"
