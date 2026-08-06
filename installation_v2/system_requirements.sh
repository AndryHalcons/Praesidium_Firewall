#!/bin/bash
set -e

# Función para instalar dependencias del sistema
# Function to install system dependencies
instalar_dependencias() {
    echo "Actualizando repositorios..."
    # Updating repositories...
    apt update

    echo "Instalando paquetes desde requirements_ubuntu.txt..."
    # Installing packages from requirements_ubuntu.txt...
    xargs -a requirements_ubuntu.txt apt install -y
}

enable_services() {
    # Habilita solo servicios base instalados por este script.
    # Enables only base services installed by this script.
    echo "Habilitando y arrancando el servicio nftables..."
    sudo systemctl enable nftables
    sudo systemctl start nftables
}

# Ejecutar la función
# Run the function
instalar_dependencias
enable_services
