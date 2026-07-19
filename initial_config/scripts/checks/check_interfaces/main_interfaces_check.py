import sys
import os
sys.path.append('/var/lib/praesidium/scripts/checks/check_interfaces')

from check_generate_first_interfaces_json import generate_interfaces_json
from check_delete_old_interfaces import check_delete_old_interfaces
from check_new_interfaces import run_check_new_interfaces
from check_generate_physical_interfaces_list import check_generate_physical_interfaces_list
from check_generate_all_interfaces_list import check_generate_all_interfaces_list


def start_checks_interfaces():

    # Este script genera un listado de interfaces físicas en formato JSON, será el que se use en los formularios de la GUI  (incluido ifindex)
    # This script generates a list of physical interfaces in JSON format; it will be used in the GUI forms (include ifindex)
    check_generate_physical_interfaces_list()
     # Este script genera un listado de TODAS las interfaces  en formato JSON, será el que se use en los formularios de la GUI
    # This script generates a list of ALL interfaces in JSON format; it will be used in the GUI forms
    check_generate_all_interfaces_list()


    ### Este script genera el archivo json con el que se va a trabajar en la gui, copiando el del sistema, solo primer uso
    # This script generates the JSON file that will be used in the GUI by copying it from the system, first use only
    generate_interfaces_json()

    #Este script añade las interfaces FISICAS nuevas detectadas por el sistema al archivo interfaces
    #This script adds newly detected physical interfaces from the system to the interfaces file.
    run_check_new_interfaces()

    #Este script borra las interfaces fisicas que han sido desconectadas/quitadas del sistema
    #This script removes physical interfaces that have been disconnected or removed from the system.
    check_delete_old_interfaces()


start_checks_interfaces()