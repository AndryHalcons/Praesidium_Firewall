"""
ES: Aplicador de configuración dnsmasq para el módulo DHCP.
    Toma el archivo generado en config_running, verifica dnsmasq, instala la
    configuración activa y reinicia el servicio siguiendo el patrón Praesidium.
EN: dnsmasq configuration applier for the DHCP module.
    Takes the generated config_running file, verifies dnsmasq, installs the
    active configuration and restarts the service following the Praesidium pattern.
"""
import shutil
import subprocess
from pathlib import Path
from task_update_json import task_update_json

GENERATED = Path('/var/lib/praesidium/running/dnsmasq/praesidium-dhcp.conf')
ACTIVE = Path('/etc/dnsmasq.d/praesidium-dhcp.conf')


# ES: Guarda copia de rollback de la configuración dnsmasq activa.
# EN: Save a rollback copy of the active dnsmasq configuration.
def backup_dnsmasq_config(user, date):
    commit_dir = Path(f'/var/lib/praesidium/commits/commit_{user}_{date}')
    backup = commit_dir / 'dnsmasq_rollback.conf'
    marker = commit_dir / 'dnsmasq_rollback.missing'
    try:
        commit_dir.mkdir(parents=True, exist_ok=True)
        if ACTIVE.exists():
            shutil.copy2(ACTIVE, backup)
            task_update_json(date, 'backup_dnsmasq_config', 'success')
            return backup
        marker.write_text('active config did not exist\n', encoding='utf-8')
        task_update_json(date, 'backup_dnsmasq_config', 'missing_active')
        return marker
    except OSError:
        task_update_json(date, 'backup_dnsmasq_config', 'fail')
        return None


# ES: Restaura la configuración anterior si apply falla.
# EN: Restore the previous configuration if apply fails.
def rollback_dnsmasq_config(date, backup_path):
    try:
        if backup_path and Path(backup_path).suffix == '.missing':
            subprocess.run(['sudo', 'rm', '-f', str(ACTIVE)], check=True)
        elif backup_path and Path(backup_path).exists():
            subprocess.run(['sudo', 'cp', str(backup_path), str(ACTIVE)], check=True)
        else:
            task_update_json(date, 'rollback_dnsmasq_config', 'missing_backup')
            return False
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], check=True)
        task_update_json(date, 'rollback_dnsmasq_config', 'success')
        return True
    except subprocess.CalledProcessError:
        task_update_json(date, 'rollback_dnsmasq_config', 'fail')
        return False


# ES: Verifica que la configuración candidata sea aceptada por dnsmasq.
# EN: Verify that the candidate configuration is accepted by dnsmasq.
def verify_dnsmasq_config(date):
    try:
        subprocess.run(['sudo', 'dnsmasq', '--test', f'--conf-file={GENERATED}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        task_update_json(date, 'verify_dnsmasq_config_apply', 'success')
    except subprocess.CalledProcessError:
        task_update_json(date, 'verify_dnsmasq_config_apply', 'fail')
        raise SystemExit(1)


# ES: Entrada llamada por la fase apply_config del commit Praesidium.
# EN: Entry point called by Praesidium commit apply_config phase.
def apply_dhcp_config(user, date):
    if not GENERATED.exists():
        task_update_json(date, 'apply_dnsmasq_config', 'missing_generated')
        raise SystemExit(1)
    verify_dnsmasq_config(date)
    backup = backup_dnsmasq_config(user, date)
    try:
        subprocess.run(['sudo', 'cp', str(GENERATED), str(ACTIVE)], check=True)
        subprocess.run(['sudo', 'chown', 'root:root', str(ACTIVE)], check=True)
        subprocess.run(['sudo', 'chmod', '0644', str(ACTIVE)], check=True)
        task_update_json(date, 'apply_dnsmasq_config', 'success')
        subprocess.run(['sudo', 'systemctl', 'restart', 'dnsmasq'], check=True)
        subprocess.run(['systemctl', 'is-active', '--quiet', 'dnsmasq'], check=True)
        task_update_json(date, 'verify_dnsmasq_service', 'success')
    except subprocess.CalledProcessError:
        task_update_json(date, 'apply_dnsmasq_config', 'fail')
        rollback_dnsmasq_config(date, backup)
        raise SystemExit(1)
