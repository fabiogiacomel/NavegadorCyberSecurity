"""
Definições base para o sistema de auditoria modular do Navegador CyberSecurity.
Estrutura inspirada nas diretrizes do OWASP Top 10 e padrões de Vibe Coding.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "#f85149",  # Red
            Severity.HIGH: "#f0883e",      # Orange
            Severity.MEDIUM: "#d29922",    # Amber/Yellow
            Severity.LOW: "#58a6ff",       # Blue
            Severity.INFO: "#8b949e",      # Gray
        }
        return colors.get(self, "#8b949e")

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return weights.get(self, 0)

    @property
    def label_pt(self) -> str:
        labels = {
            Severity.CRITICAL: "CRÍTICA",
            Severity.HIGH: "ALTA",
            Severity.MEDIUM: "MÉDIA",
            Severity.LOW: "BAIXA",
            Severity.INFO: "INFORMATIVA",
        }
        return labels.get(self, self.value)


class OwaspCategory(Enum):
    A01_BROKEN_ACCESS = "A01:2021 - Quebra de Controle de Acesso"
    A02_CRYPTO = "A02:2021 - Falhas Criptográficas"
    A03_INJECTION = "A03:2021 - Injeção e DOM XSS"
    A04_INSECURE_DESIGN = "A04:2021 - Design Inseguro"
    A05_SECURITY_MISCONFIG = "A05:2021 - Configuração Insegura"
    A06_VULN_COMPONENTS = "A06:2021 - Componentes Vulneráveis e Desatualizados"
    A07_AUTH_FAILURES = "A07:2021 - Falhas de Identificação e Autenticação"
    A08_INTEGRITY_FAILURES = "A08:2021 - Falhas de Integridade de Software e Dados"
    A09_LOGGING_FAILURES = "A09:2021 - Falhas de Registro e Monitoramento"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"
    VIBE_CODING_PATTERNS = "VIBE-CODING - Vazamentos e Padrões Inseguros de IA"
    API_SECURITY_TOP_10 = "OWASP API:2023 - Segurança de APIs"


@dataclass
class AuditFinding:
    id: str
    title: str
    category: OwaspCategory
    severity: Severity
    url: str
    description: str
    evidence: str
    remediation: str
    vibe_coding_context: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "vibe_coding_context": self.vibe_coding_context,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class AuditContext:
    url: str
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    html: str = ""
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    scripts: List[str] = field(default_factory=list)
    script_srcs: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    console_logs: List[str] = field(default_factory=list)
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    openapi_spec: Optional[Dict[str, Any]] = None


class BaseAuditModule(ABC):
    """
    Classe base para todos os módulos de auditoria de segurança.
    Cada regra/verificação OWASP ou Vibe Coding herda desta classe.
    """

    def __init__(self):
        self.enabled: bool = True

    @property
    @abstractmethod
    def module_id(self) -> str:
        """Identificador único do módulo (ex: 'mod_a05_headers')"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome legível do módulo"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Descrição do que este módulo audita"""
        pass

    @property
    @abstractmethod
    def owasp_category(self) -> OwaspCategory:
        """Categoria OWASP correspondente"""
        pass

    @abstractmethod
    def run(self, context: AuditContext) -> List[AuditFinding]:
        """
        Executa a auditoria sobre o contexto atual da página.
        Retorna a lista de vulnerabilidades encontradas.
        """
        pass
