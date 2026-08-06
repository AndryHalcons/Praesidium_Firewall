from task_gen_json_entry import gen_json_entry
from task_gen_json_mkdir import gen_json_mkdir
from task_gen_interface_config import gen_interface_config
from task_gen_nftables_policies import gen_nftables_policies
from task_gen_bpfilter_policies import gen_bpfilter_policies
from task_gen_dhcp_config import gen_dhcp_config
from task_gen_wireguard_config import gen_wireguard_config
from task_gen_management_apache import gen_management_apache
from task_apply_nftables_policies import apply_nftables_policies
from task_apply_bpfilter_policies import apply_bpfilter_policies
from task_apply_interface_config import apply_interface_config
from task_apply_dhcp_config import apply_dhcp_config
from task_apply_system_logging import apply_system_logging
from task_apply_wireguard_config import apply_wireguard_config
from task_apply_services import apply_services_config
from task_apply_management_apache import apply_management_apache


def start_commit_process(user, date):

    ################################################################################################################################
    ###################################### Section Generate Config #################################################################
    ################################################################################################################################
    # genera la entrada en /var/lib/praesidium/commits/commit_history.json
    # generates the entry in /var/lib/praesidium/commits/commit_history.json
    gen_json_entry(user, date)

    #copia la configuracion actual a un directorio en /var/lib/praesidium/commits con formato commit_date
    #y tambien genera los archivos de la carpeta config_running
    #Copy the current configuration to a directory at /var/lib/praesidium/commits using the format commit_date,
    #and also generate the files in the config_running folder.
    gen_json_mkdir(user, date)#dividr en dos

    # Genera la configuración de las interfaces de red
    # Generate the network interface configuration
    gen_interface_config(user, date)


    # Genera las reglas de nftables, verifica, limpia
    # Generate the nftables rules, verify, clean up.
    gen_nftables_policies(user, date)

    # Genera las reglas de bpfilter, verifica, limpia y aplica.
    # Generate the bpfilter rules: verifies, flushes, and then applies.
    gen_bpfilter_policies(user, date)

    # Genera la configuración DHCP/dnsmasq
    # Generate DHCP/dnsmasq configuration
    gen_dhcp_config(user, date)

    # Genera y valida la configuración WireGuard
    # Generate and validate WireGuard configuration
    gen_wireguard_config(user, date)

    # Genera la configuración Apache del plano de gestión.
    # Generate Apache configuration for the management plane.
    gen_management_apache(user, date)

    ################################################################################################################################
    ###################################### Section APPLY ###########################################################################
    ################################################################################################################################
    #Esta configuracion aplica los cambios solo si toda la generacion de configuracion ha concluido con éxtio,
    #con el objetivo de que solo se apliquen los cambios si toda la configuracion es correcta.
    #This configuration applies changes only if the entire configuration generation process has completed successfully,
    #ensuring that changes are applied only when the full setup is correct.

    #aplica la configuracion de red
    #apply network settings
    apply_interface_config(user,date)

    #aplica las reglas de nftables,
    #apply the rules of nftables,
    apply_nftables_policies(user, date)

    #aplica las reglas de bpfilter,
    #apply the rules of bpfilter,
    apply_bpfilter_policies(user,date)

    # aplica la configuración DHCP/dnsmasq
    # apply DHCP/dnsmasq configuration
    apply_dhcp_config(user,date)

    # aplica la configuración de logs del sistema
    # apply system logging configuration
    apply_system_logging(user,date)

    # aplica el estado deseado de los servicios del sistema
    # apply the desired state for system services
    apply_services_config(user,date)

    # aplica la configuración WireGuard gestionada por Praesidium
    # apply Praesidium-managed WireGuard configuration
    apply_wireguard_config(user,date)

    # Aplica la configuración Apache del plano de gestión.
    # Apply Apache configuration for the management plane.
    apply_management_apache(user, date)





#only devops
#start_commit_process("praesidium", "19700101000000000")

#{"commit":{"date":"20250824142408","user":"praesidium"}}
