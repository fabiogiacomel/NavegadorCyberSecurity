"""
Registro central de módulos de auditoria de segurança.
Permite carregar todos os módulos ativos ou registrar novos dinamicamente.
"""

from typing import List
from modules.base import BaseAuditModule, AuditFinding, AuditContext, Severity, OwaspCategory
from modules.a01_broken_access import BrokenAccessControlModule
from modules.a02_crypto_failures import CryptographicFailuresModule
from modules.a03_injection import InjectionAndDomXssModule
from modules.a05_misconfiguration import SecurityMisconfigurationModule
from modules.a07_auth_failures import AuthAndSessionFailuresModule
from modules.a08_integrity import SoftwareIntegrityModule
from modules.vibe_coding_leaks import VibeCodingLeaksModule
from modules.api_security_auditor import ApiSecurityAuditorModule


def get_default_modules() -> List[BaseAuditModule]:
    """Retorna instâncias de todos os módulos de auditoria integrados."""
    return [
        SecurityMisconfigurationModule(),
        AuthAndSessionFailuresModule(),
        InjectionAndDomXssModule(),
        CryptographicFailuresModule(),
        SoftwareIntegrityModule(),
        BrokenAccessControlModule(),
        VibeCodingLeaksModule(),
        ApiSecurityAuditorModule(),
    ]


__all__ = [
    "BaseAuditModule",
    "AuditFinding",
    "AuditContext",
    "Severity",
    "OwaspCategory",
    "ApiSecurityAuditorModule",
    "get_default_modules",
]
