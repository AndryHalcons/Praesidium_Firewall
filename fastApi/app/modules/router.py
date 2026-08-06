"""
Router agregador de módulos Praesidium.
Praesidium modules router aggregator.
"""

from __future__ import annotations

from fastapi import APIRouter

from modules.alias_ip.router import router as alias_ip_router
from modules.alias_services.router import router as alias_services_router
from modules.auth.router import router as auth_router
from modules.bpfilter.router import router as bpfilter_router
from modules.certificates.router import router as certificates_router
from modules.commit.router import router as commit_router
from modules.dashboard.router import router as dashboard_router
from modules.dnsmasq.router import router as dnsmasq_router
from modules.interfaces.router import router as interfaces_router
from modules.login_attempts.router import router as login_attempts_router
from modules.management.router import router as management_router
from modules.monitor_logs.router import router as monitor_logs_router
from modules.monitor_session.router import router as monitor_session_router
from modules.nftables.router import router as nftables_router
from modules.password_policy.router import router as password_policy_router
from modules.routing.router import router as routing_router
from modules.services.router import router as services_router
from modules.system_logging.router import router as system_logging_router
from modules.users.router import router as users_router
from modules.wireguard.router import router as wireguard_router


modules_router = APIRouter()

for router in (
    auth_router,
    alias_ip_router,
    alias_services_router,
    nftables_router,
    bpfilter_router,
    interfaces_router,
    wireguard_router,
    dnsmasq_router,
    dashboard_router,
    services_router,
    routing_router,
    users_router,
    password_policy_router,
    login_attempts_router,
    certificates_router,
    management_router,
    monitor_logs_router,
    monitor_session_router,
    commit_router,
    system_logging_router,
):
    modules_router.include_router(router)
