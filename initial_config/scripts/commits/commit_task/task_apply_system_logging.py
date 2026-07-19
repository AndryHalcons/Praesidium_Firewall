import json
import subprocess
from pathlib import Path
from task_update_json import task_update_json

CONFIG_PATH = Path('/var/lib/praesidium/running/system_logging.json')
JOURNALD_DROPIN_DIR = Path('/etc/systemd/journald.conf.d')
JOURNALD_DROPIN = JOURNALD_DROPIN_DIR / '10-praesidium-limits.conf'
RSYSLOG_LOGROTATE = Path('/etc/logrotate.d/rsyslog')
NFTABLES_RSYSLOG = Path('/etc/rsyslog.d/nftables_rsyslog.conf')
NFTABLES_LOGROTATE = Path('/etc/logrotate.d/nftables_logrotate.conf')
LOG_DIR = Path('/var/log/praesidium')

ALLOWED_SIZES = {'10M', '25M', '50M', '100M', '250M', '500M', '1G', '2G'}
ALLOWED_RETENTION = {'1day', '3day', '7day', '14day', '30day'}
ALLOWED_ROTATION = {'daily', 'weekly'}


def _require_choice(section, key, value, allowed):
    if value not in allowed:
        raise ValueError(f'Invalid value for {section}.{key}')
    return value


def _require_bool(section, key, value):
    if not isinstance(value, bool):
        raise ValueError(f'Invalid boolean for {section}.{key}')
    return value


def _require_rotate(section, key, value):
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if not isinstance(value, int) or value < 1 or value > 30:
        raise ValueError(f'Invalid rotation for {section}.{key}')
    return value


def load_and_validate_system_logging_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f'{CONFIG_PATH} not found')
    data = json.loads(CONFIG_PATH.read_text())
    journald = data.get('journald', {})
    system_logs = data.get('system_logs', {})
    nftables_logs = data.get('nftables_logs', {})
    return {
        'journald': {
            'system_max_use': _require_choice('journald', 'system_max_use', journald.get('system_max_use'), ALLOWED_SIZES),
            'system_keep_free': _require_choice('journald', 'system_keep_free', journald.get('system_keep_free'), ALLOWED_SIZES),
            'runtime_max_use': _require_choice('journald', 'runtime_max_use', journald.get('runtime_max_use'), ALLOWED_SIZES),
            'max_retention_sec': _require_choice('journald', 'max_retention_sec', journald.get('max_retention_sec'), ALLOWED_RETENTION),
            'compress': _require_bool('journald', 'compress', journald.get('compress')),
        },
        'system_logs': {
            'enabled': _require_bool('system_logs', 'enabled', system_logs.get('enabled')),
            'rotation': _require_choice('system_logs', 'rotation', system_logs.get('rotation'), ALLOWED_ROTATION),
            'rotate': _require_rotate('system_logs', 'rotate', system_logs.get('rotate')),
            'maxsize': _require_choice('system_logs', 'maxsize', system_logs.get('maxsize'), ALLOWED_SIZES),
            'compress': _require_bool('system_logs', 'compress', system_logs.get('compress')),
            'delaycompress': _require_bool('system_logs', 'delaycompress', system_logs.get('delaycompress')),
        },
        'nftables_logs': {
            'enabled': _require_bool('nftables_logs', 'enabled', nftables_logs.get('enabled')),
            'size': _require_choice('nftables_logs', 'size', nftables_logs.get('size'), ALLOWED_SIZES),
            'rotate': _require_rotate('nftables_logs', 'rotate', nftables_logs.get('rotate')),
            'compress': _require_bool('nftables_logs', 'compress', nftables_logs.get('compress')),
            'delaycompress': _require_bool('nftables_logs', 'delaycompress', nftables_logs.get('delaycompress')),
        },
    }


def render_journald(config):
    compress = 'yes' if config['compress'] else 'no'
    return f'''[Journal]
# Límite duro para el journal persistente en disco.
# Hard limit for persistent on-disk journal storage.
SystemMaxUse={config['system_max_use']}

# Mantiene siempre espacio libre en disco para evitar llenados por logs.
# Always keep free disk space so logs cannot consume the whole filesystem.
SystemKeepFree={config['system_keep_free']}

# Límite para el journal temporal en /run cuando aplique.
# Limit for runtime journal storage under /run when applicable.
RuntimeMaxUse={config['runtime_max_use']}

# Retención máxima de eventos del journal.
# Maximum journal event retention.
MaxRetentionSec={config['max_retention_sec']}

# Comprimir entradas antiguas del journal.
# Compress older journal entries.
Compress={compress}
'''


def render_system_logrotate(config):
    lines = [
        '/var/log/syslog', '/var/log/mail.log', '/var/log/kern.log', '/var/log/auth.log',
        '/var/log/user.log', '/var/log/cron.log', '/var/log/daemon.log', '/var/log/debug', '/var/log/messages',
        '{', f"    {config['rotation']}", f"    rotate {config['rotate']}", f"    maxsize {config['maxsize']}",
        '    missingok', '    su syslog adm', '    notifempty',
    ]
    if config['compress']:
        lines.append('    compress')
    if config['delaycompress']:
        lines.append('    delaycompress')
    lines += ['    sharedscripts', '    create 640 syslog adm', '    postrotate', '        /usr/lib/rsyslog/rsyslog-rotate', '    endscript', '}']
    return '\n'.join(lines) + '\n'


def render_nftables_rsyslog(enabled):
    if not enabled:
        return '# Praesidium nftables dedicated log disabled by system_logging.json\n'
    return ':msg, contains, "nftables" -/var/log/praesidium/nftables.log\n& stop\n'


def render_nftables_logrotate(config):
    lines = ['/var/log/praesidium/nftables.log {', f"    size {config['size']}", '    missingok', f"    rotate {config['rotate']}"]
    if config['compress']:
        lines.append('    compress')
    if config['delaycompress']:
        lines.append('    delaycompress')
    lines += ['    notifempty', '    create 640 syslog adm', '    postrotate', '        kill -HUP $(pidof rsyslogd)', '    endscript', '}']
    return '\n'.join(lines) + '\n'


def run_checked(command):
    subprocess.run(command, check=True)


def apply_system_logging(user, date):
    try:
        config = load_and_validate_system_logging_config()
        task_update_json(date, 'system_logging_validate', 'success')
        JOURNALD_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        JOURNALD_DROPIN.write_text(render_journald(config['journald']))
        task_update_json(date, 'system_logging_write_journald', 'success')
        if config['system_logs']['enabled']:
            RSYSLOG_LOGROTATE.write_text(render_system_logrotate(config['system_logs']))
        task_update_json(date, 'system_logging_write_rsyslog_logrotate', 'success')
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        NFTABLES_RSYSLOG.write_text(render_nftables_rsyslog(config['nftables_logs']['enabled']))
        NFTABLES_LOGROTATE.write_text(render_nftables_logrotate(config['nftables_logs']))
        task_update_json(date, 'system_logging_write_nftables_logging', 'success')
        run_checked(['logrotate', '-d', str(RSYSLOG_LOGROTATE)])
        run_checked(['logrotate', '-d', str(NFTABLES_LOGROTATE)])
        task_update_json(date, 'system_logging_validate_logrotate', 'success')
        run_checked(['chown', 'syslog:adm', str(LOG_DIR)])
        run_checked(['chmod', '750', str(LOG_DIR)])
        run_checked(['systemctl', 'restart', 'systemd-journald'])
        subprocess.run(['journalctl', f"--vacuum-size={config['journald']['system_max_use']}"], check=False)
        run_checked(['systemctl', 'restart', 'rsyslog'])
        task_update_json(date, 'system_logging_restart_services', 'success')
    except Exception as exc:
        task_update_json(date, 'system_logging_apply', f'fail: {exc}')
        raise
