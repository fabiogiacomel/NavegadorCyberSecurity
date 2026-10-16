"""
Registro central de módulos de auditoria de segurança.
Permite carregar todos os módulos ativos ou registrar novos dinamicamente.
"""

from typing import List
from modules.base import BaseAuditModule, AuditFinding, AuditContext, Severity, OwaspCategory
from modules.a01_broken_access import BrokenAccessControlModule
from modules.a02_crypto_failures import CryptographicFailuresModule
from modules.a03_injection import InjectionAndDomXssModule
from modules.a04_insecure_design import InsecureDesignModule
from modules.a05_misconfiguration import SecurityMisconfigurationModule
from modules.a06_vulnerable_components import VulnerableComponentsModule
from modules.a07_auth_failures import AuthAndSessionFailuresModule
from modules.a08_integrity import SoftwareIntegrityModule
from modules.a09_logging_monitoring import LoggingAndMonitoringModule
from modules.a10_ssrf import ServerSideRequestForgeryModule
from modules.vibe_coding_leaks import VibeCodingLeaksModule
from modules.api_security_auditor import ApiSecurityAuditorModule
from modules.multi_tenant_rls_auditor import MultiTenantRlsAuditorModule
from modules.llm_ai_security_auditor import LlmAiSecurityAuditorModule


def get_default_modules() -> List[BaseAuditModule]:
    """Retorna instâncias de todos os módulos de auditoria integrados (OWASP Top 10 Completo + Vibe Coding + API + RLS + LLM)."""
    return [
        BrokenAccessControlModule(),
        CryptographicFailuresModule(),
        InjectionAndDomXssModule(),
        InsecureDesignModule(),
        SecurityMisconfigurationModule(),
        VulnerableComponentsModule(),
        AuthAndSessionFailuresModule(),
        SoftwareIntegrityModule(),
        LoggingAndMonitoringModule(),
        ServerSideRequestForgeryModule(),
        VibeCodingLeaksModule(),
        ApiSecurityAuditorModule(),
        MultiTenantRlsAuditorModule(),
        LlmAiSecurityAuditorModule(),
    ]


__all__ = [
    "BaseAuditModule",
    "AuditFinding",
    "AuditContext",
    "Severity",
    "OwaspCategory",
    "BrokenAccessControlModule",
    "CryptographicFailuresModule",
    "InjectionAndDomXssModule",
    "InsecureDesignModule",
    "SecurityMisconfigurationModule",
    "VulnerableComponentsModule",
    "AuthAndSessionFailuresModule",
    "SoftwareIntegrityModule",
    "LoggingAndMonitoringModule",
    "ServerSideRequestForgeryModule",
    "VibeCodingLeaksModule",
    "ApiSecurityAuditorModule",
    "MultiTenantRlsAuditorModule",
    "LlmAiSecurityAuditorModule",
    "get_default_modules",
]
