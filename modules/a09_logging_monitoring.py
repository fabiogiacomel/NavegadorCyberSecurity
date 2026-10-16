"""
Módulo de Auditoria: A09:2021 - Falhas de Registro e Monitoramento de Segurança (Security Logging and Monitoring Failures)
Analisa vazamento de dados sensíveis no console do navegador (console.log / mensagens ativas do Chromium),
silenciamento de exceções críticas (empty catch blocks) e exposição de arquivos/endpoints de log.
"""

import re
from typing import List, Tuple
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class LoggingAndMonitoringModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # Chamadas console.log/debug/info no código que imprimem variáveis ou chaves sensíveis
    SENSITIVE_CONSOLE_CODE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"\bconsole\.(?:log|debug|info|warn|table)\s*\([^)]*\b(?:token|jwt|access_?token|refresh_?token|password|senha|secret|api_?key|apiKey|private_?key|cpf|credit_?card|authorization|session_?id)\b[^)]*\)",
                re.IGNORECASE
            ),
            "Impressão de variável sensível via console.log/debug"
        ),
        (
            re.compile(
                r"\bconsole\.(?:log|debug|info)\s*\(\s*(?:user|currentUser|req\.headers|res\.data|localStorage)\s*\)",
                re.IGNORECASE
            ),
            "Dump completo de objeto de sessão/autenticação no console"
        ),
    ]

    # Padrões para inspecionar mensagens reais capturadas em runtime no console do Chromium (context.console_logs)
    LIVE_CONSOLE_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}"),
            "Token JWT impresso no console em tempo de execução"
        ),
        (
            re.compile(r"\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{25,}|AIza[0-9A-Za-z_-]{30,})\b"),
            "Chave de API impressa no console em tempo de execução"
        ),
        (
            re.compile(r"\b(?:password|senha|secret|access_token|api_key)\s*[:=]\s*['\"]?[^\s'\"]{4,}", re.IGNORECASE),
            "Credencial ou token em texto claro no log do console"
        ),
    ]

    # Blocos catch vazios ou promessas que engolem falhas silenciosamente
    SILENT_CATCH_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"\bcatch\s*(?:\(\s*\w+\s*\))?\s*\{\s*(?://[^\n]*\s*|/\*.*?\*/\s*)*\}", re.DOTALL),
            "Bloco try/catch vazio que descarta a exceção silenciosamente"
        ),
        (
            re.compile(r"\.catch\s*\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)"),
            "Promise .catch(() => {}) que ignora falhas de rede/API"
        ),
    ]

    # Exposição de arquivos de log ou flags de debug verboso
    EXPOSED_LOG_AND_DEBUG_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"['\"`](/(?:logs?|debug\.log|error\.log|app\.log|laravel\.log|npm-debug\.log|actuator/logfile)(?:/[\w\-\.]*)?)['\"`]",
                re.IGNORECASE
            ),
            "Referência a arquivo ou endpoint de log de servidor"
        ),
        (
            re.compile(r"localStorage\.setItem\s*\(\s*['\"]debug['\"]\s*,\s*['\"][^*'\"]*\*['\"]\s*\)", re.IGNORECASE),
            "Ativação de log verboso global (localStorage debug='*')"
        ),
    ]

    @property
    def module_id(self) -> str:
        return "mod_a09_logging_monitoring"

    @property
    def name(self) -> str:
        return "Falhas de Registro e Monitoramento (OWASP A09)"

    @property
    def description(self) -> str:
        return (
            "Audita vazamento de tokens e credenciais no console do navegador, silenciamento de exceções "
            "(empty catch blocks) e exposição de arquivos de log ou debug verboso."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A09_LOGGING_FAILURES

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        # 1. Vazamento de dados sensíveis em console.log (código estático + logs em runtime do Chromium)
        findings.extend(self._check_sensitive_console_logging(context.url, all_text, context.console_logs or []))

        # 2. Silenciamento de exceções (Empty Catch Blocks)
        findings.extend(self._check_silent_error_swallowing(context.url, all_text))

        # 3. Endpoints/arquivos de log expostos ou debug verboso ativo
        findings.extend(self._check_exposed_logs_and_debug_mode(context.url, all_text))

        return findings

    @staticmethod
    def _clean_snippet(text: str, max_len: int = 75) -> str:
        cleaned = " ".join(text.strip().split())
        return cleaned[:max_len - 3] + "..." if len(cleaned) > max_len else cleaned

    def _check_sensitive_console_logging(
        self, current_url: str, all_text: str, console_logs: List[str]
    ) -> List[AuditFinding]:
        evidences: List[str] = []
        has_live_secret = False

        # A. Verifica chamadas console.log no código JS da página
        for pattern, label in self.SENSITIVE_CONSOLE_CODE_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        # B. Verifica mensagens reais capturadas pelo navegador em tempo de execução
        for log_entry in console_logs:
            for pattern, label in self.LIVE_CONSOLE_SECRET_PATTERNS:
                match = pattern.search(log_entry)
                if match:
                    has_live_secret = True
                    evidences.append(f"{label}: {self._clean_snippet(log_entry)}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A09-SENSITIVE-CONSOLE-LOGGING",
            title="Vazamento de Dados Sensíveis ou Credenciais no Console do Navegador",
            category=self.owasp_category,
            severity=Severity.HIGH if has_live_secret else Severity.MEDIUM,
            url=current_url,
            description=(
                "A aplicação registra tokens de autenticação, senhas, chaves de API ou objetos completos de usuário "
                "diretamente no console do navegador (console.log). Esses registros ficam acessíveis para extensões "
                "do navegador, scripts de terceiros, ferramentas de gravação de sessão (Session Replay) e pessoas "
                "com acesso físico à máquina."
            ),
            evidence="Ocorrências identificadas: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "1. Remova todas as instruções 'console.log' que imprimem tokens, cabeçalhos Authorization ou dados pessoais.\n"
                "2. Configure o bundler (Vite/Webpack/Terser) para remover chamadas 'console.*' automaticamente em produção "
                "(ex.: 'esbuild: { drop: [\"console\", \"debugger\"] }' no vite.config.ts)."
            ),
            vibe_coding_context=(
                "Durante o desenvolvimento assistido por IA, é padrão inserir 'console.log(\"Token recebido:\", token)' "
                "para depurar o login, esquecendo essas linhas no código que vai para produção."
            )
        )]

    def _check_silent_error_swallowing(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.SILENT_CATCH_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A09-SILENT-ERROR-SWALLOWING",
            title=f"Silenciamento de Exceções Sem Registro ou Monitoramento ({len(unique_evidences)} bloco(s))",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description=(
                "Foram encontrados blocos 'catch (e) {}' vazios que descartam exceções silenciosamente sem registrar "
                "o evento ou notificar serviços de telemetria. Na categoria OWASP A09, suprimir erros de autenticação, "
                "falhas de validação de token ou erros 401/403/500 impede a detecção de ataques em andamento e "
                "compromete a resposta a incidentes."
            ),
            evidence="Blocos detectados: " + " | ".join(unique_evidences[:4]),
            remediation=(
                "Trate os erros explicitamente e envie falhas inesperadas ou eventos de segurança para uma plataforma "
                "centralizada de observabilidade e monitoramento (ex.: Sentry, Datadog, OpenTelemetry)."
            ),
            vibe_coding_context=(
                "Para evitar que erros parem a execução da tela, modelos de IA frequentemente envolvem chamadas "
                "críticas em blocos 'try { ... } catch (e) {}' completamente vazios."
            )
        )]

    def _check_exposed_logs_and_debug_mode(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.EXPOSED_LOG_AND_DEBUG_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A09-DEBUG-LOGGING-ENABLED",
            title="Exposição de Endpoints de Log ou Modo de Depuração Verboso no Cliente",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "O código faz referência direta a arquivos de log do servidor (ex.: /debug.log, /error.log, /actuator/logfile) "
                "ou ativa flags de log verboso global no cliente. Arquivos de log acessíveis publicamente revelam "
                "caminhos internos do servidor, endereços IP, tokens de sessão e histórico de erros."
            ),
            evidence="Referências detectadas: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "Bloqueie o acesso externo a qualquer arquivo '.log' ou endpoint '/actuator/*' no proxy reverso (Nginx/Cloudflare) "
                "e armazene logs fora da raiz pública (webroot) da aplicação."
            ),
            vibe_coding_context=(
                "Aplicações que gravam logs em arquivos locais (como 'app.log' ou 'debug.log') na mesma pasta do projeto "
                "acabam servindo esses arquivos estaticamente quando mal configuradas."
            )
        )]
