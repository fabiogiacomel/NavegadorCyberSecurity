"""
Motor de Auditoria de Segurança (Audit Engine).
Coordena a execução dos módulos, compila relatórios e calcula o Security Score da aplicação.
"""

from typing import List, Dict, Any, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from modules.base import BaseAuditModule, AuditFinding, AuditContext, Severity
from modules import get_default_modules


class AuditEngine(QObject):
    # Sinais do Qt para notificação da interface em tempo real
    audit_started = pyqtSignal(str)              # URL
    audit_completed = pyqtSignal(dict)           # Resumo completo dos resultados
    module_executed = pyqtSignal(str, int)       # Nome do módulo, quantidade de findings

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.modules: List[BaseAuditModule] = get_default_modules()
        self.current_findings: List[AuditFinding] = []
        self.current_score: int = 100
        self.current_grade: str = "A+"
        self.current_summary: Dict[str, Any] = {}

    def register_module(self, module: BaseAuditModule) -> None:
        """Adiciona um novo módulo à engine."""
        self.modules.append(module)

    def set_module_enabled(self, module_id: str, enabled: bool) -> None:
        """Habilita ou desabilita um módulo específico."""
        for mod in self.modules:
            if mod.module_id == module_id:
                mod.enabled = enabled
                break

    def run_audit(self, context: AuditContext) -> Dict[str, Any]:
        """
        Executa todos os módulos de auditoria ativos sobre o contexto fornecido.
        Retorna um dicionário estruturado com os resultados e estatísticas.
        """
        self.audit_started.emit(context.url)
        all_findings: List[AuditFinding] = []

        for module in self.modules:
            if not module.enabled:
                continue
            try:
                mod_findings = module.run(context)
                all_findings.extend(mod_findings)
                self.module_executed.emit(module.name, len(mod_findings))
            except Exception as e:
                # Módulo com erro não derruba o navegador
                print(f"[AuditEngine] Erro ao executar módulo {module.name}: {e}")

        # Ordena por severidade (CRITICAL primeiro, depois HIGH, etc.)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        self.current_findings = all_findings

        # Cálculo do Security Score
        score, grade = self._calculate_score(all_findings)
        self.current_score = score
        self.current_grade = grade

        # Estatísticas por severidade
        counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0
        }
        for f in all_findings:
            counts[f.severity.value] += 1

        self.current_summary = {
            "url": context.url,
            "score": score,
            "grade": grade,
            "counts": counts,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "context": context
        }

        self.audit_completed.emit(self.current_summary)
        return self.current_summary

    def _calculate_score(self, findings: List[AuditFinding]) -> tuple[int, str]:
        """
        Calcula o Security Score (0 a 100) e a nota correspondente (A+, A, B, C, D, F).
        """
        deductions = 0
        for f in findings:
            deductions += f.severity.weight

        score = max(0, 100 - deductions)

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        return score, grade
