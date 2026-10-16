"""
Módulo de Auditoria: A05:2021 - Configuração Incorreta de Segurança (Security Misconfiguration)
Audita cabeçalhos HTTP de segurança (HSTS, CSP, X-Frame-Options, CORS, X-Content-Type-Options),
vazamento de banners de tecnologia (Server / X-Powered-By) e exposição de stack traces no cliente.
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class SecurityMisconfigurationModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")
    LOCALHOST_HOSTS: Set[str] = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

    # Mínimo recomendado pela OWASP para HSTS: 1 ano (em segundos)
    MIN_HSTS_MAX_AGE = 31536000
    HSTS_MAX_AGE_REGEX = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

    # Cabeçalhos que expõem detalhes internos da stack tecnológica
    TECH_DISCLOSURE_HEADERS: Tuple[str, ...] = (
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
    )

    # Regex para detectar versão explícita no cabeçalho Server (ex: Apache/2.4.41, nginx/1.18.0)
    SERVER_VERSION_REGEX = re.compile(r"[a-zA-Z0-9_\-]+/\d+\.\d+", re.IGNORECASE)

    # Padrões de Stack Trace / Debug Mode vazados no HTML em produção
    DEBUG_TRACE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
            "Stack trace Python (Django/Flask/FastAPI)"
        ),
        (
            re.compile(r"You're seeing this error because you have\s+<code>DEBUG = True</code>", re.IGNORECASE),
            "Modo DEBUG=True do Django ativo"
        ),
        (
            re.compile(r"(?:ReferenceError|TypeError|SyntaxError|Error):[^\n]+at\s+[\w\./\\]+\s*\([^\n]+:\d+:\d+\)", re.IGNORECASE),
            "Stack trace Node.js / Express"
        ),
        (
            re.compile(r"\b(?:Fatal error|Warning):\s+Uncaught\s+[A-Za-z0-9_\\]+\s+in\s+/[\w/\-\.]+\.php\s+on\s+line\s+\d+", re.IGNORECASE),
            "Erro fatal PHP com caminho de diretório exposto"
        ),
    ]

    @property
    def module_id(self) -> str:
        return "mod_a05_misconfiguration"

    @property
    def name(self) -> str:
        return "Cabeçalhos HTTP, CORS & Configuração de Segurança (OWASP A05)"

    @property
    def description(self) -> str:
        return "Audita HSTS, CSP, Clickjacking (X-Frame-Options), CORS permissivo, headers verbosos e modo debug exposto."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A05_SECURITY_MISCONFIG

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        parsed_url = urlparse(context.url)
        is_https = parsed_url.scheme.lower() == "https"
        hostname = (parsed_url.hostname or "").lower()
        is_localhost = hostname in self.LOCALHOST_HOSTS or hostname.endswith(".localhost")

        headers = self._extract_normalized_headers(context)
        html_content = context.html or ""
        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # Só audita ausência de cabeçalhos HTTP se o contexto realmente capturou os headers da resposta
        if headers:
            if is_https and not is_localhost:
                findings.extend(self._check_hsts(context.url, headers))

            findings.extend(self._check_csp(context.url, headers, soup))
            findings.extend(self._check_clickjacking(context.url, headers))
            findings.extend(self._check_cors(context.url, headers))
            findings.extend(self._check_hardening_headers(context.url, headers))
            findings.extend(self._check_tech_disclosure_headers(context.url, headers))

        # Verificação de modo debug/stack trace no corpo HTML (independe dos headers)
        if html_content:
            findings.extend(self._check_debug_exposure(context.url, html_content))

        return findings

    @staticmethod
    def _extract_normalized_headers(context: AuditContext) -> Dict[str, str]:
        """Extrai cabeçalhos do contexto e normaliza todas as chaves para minúsculas."""
        raw_headers = getattr(context, "headers", None) or getattr(context, "response_headers", None) or {}
        if not isinstance(raw_headers, dict):
            return {}
        return {str(k).strip().lower(): str(v).strip() for k, v in raw_headers.items()}

    def _check_hsts(self, current_url: str, headers: Dict[str, str]) -> List[AuditFinding]:
        hsts = headers.get("strict-transport-security")
        if not hsts:
            return [AuditFinding(
                id="SEC-A05-HSTS-MISSING",
                title="Cabeçalho HSTS (Strict-Transport-Security) Ausente",
                category=self.owasp_category,
                severity=Severity.MEDIUM,
                url=current_url,
                description=(
                    "A página é servida via HTTPS, mas não envia o cabeçalho Strict-Transport-Security (HSTS). "
                    "Isso permite que atacantes realizem ataques de SSL Stripping na primeira conexão HTTP do usuário."
                ),
                evidence="Cabeçalho 'Strict-Transport-Security' não encontrado na resposta HTTPS.",
                remediation="Adicione o cabeçalho: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                vibe_coding_context="Deploys automatizados costumam ativar o certificado HTTPS no proxy, mas não configuram o cabeçalho HSTS na aplicação."
            )]

        match = self.HSTS_MAX_AGE_REGEX.search(hsts)
        max_age = int(match.group(1)) if match else 0
        if max_age < self.MIN_HSTS_MAX_AGE:
            return [AuditFinding(
                id="SEC-A05-HSTS-WEAK",
                title="Cabeçalho HSTS com Tempo de Expiração (max-age) Insuficiente",
                category=self.owasp_category,
                severity=Severity.LOW,
                url=current_url,
                description=(
                    f"O cabeçalho HSTS está presente, mas define um 'max-age' de {max_age} segundos "
                    f"(inferior a 1 ano / {self.MIN_HSTS_MAX_AGE}s) ou está desativado (max-age=0)."
                ),
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Aumente o valor de max-age para pelo menos 31536000 (1 ano) e inclua 'includeSubDomains'.",
                vibe_coding_context="Configurações copiadas de exemplos de teste frequentemente utilizam 'max-age=300' ou 'max-age=0'."
            )]

        return []

    def _check_csp(
        self, current_url: str, headers: Dict[str, str], soup: Optional[BeautifulSoup]
    ) -> List[AuditFinding]:
        csp_value = headers.get("content-security-policy", "")

        # Fallback: verifica se o CSP foi declarado via <meta http-equiv="Content-Security-Policy">
        if not csp_value and soup:
            meta_csp = soup.find(
                "meta",
                attrs={"http-equiv": re.compile(r"^Content-Security-Policy$", re.IGNORECASE)}
            )
            if meta_csp and meta_csp.get("content"):
                csp_value = str(meta_csp["content"]).strip()

        if not csp_value:
            return [AuditFinding(
                id="SEC-A05-CSP-MISSING",
                title="Política de Segurança de Conteúdo (CSP) Ausente",
                category=self.owasp_category,
                severity=Severity.MEDIUM,
                url=current_url,
                description=(
                    "A aplicação não define o cabeçalho 'Content-Security-Policy'. Sem o CSP, o navegador "
                    "não possui restrições de origem para execução de scripts, agravando o impacto de falhas XSS."
                ),
                evidence="Cabeçalho 'Content-Security-Policy' e meta tag equivalente ausentes.",
                remediation=(
                    "Implemente um cabeçalho Content-Security-Policy restritivo, como: "
                    "\"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\"."
                ),
                vibe_coding_context="Frameworks gerados por IA raramente configuram CSP por padrão para evitar que scripts ou fontes externas de CDNs sejam bloqueados durante o desenvolvimento."
            )]

        weaknesses: List[str] = []
        csp_lower = csp_value.lower()

        if "'unsafe-inline'" in csp_lower:
            weaknesses.append("uso de 'unsafe-inline' (permite execução de scripts inline injetados via XSS)")
        if "'unsafe-eval'" in csp_lower:
            weaknesses.append("uso de 'unsafe-eval' (permite execução de código dinâmico a partir de strings)")
        if re.search(r"(?:default-src|script-src)[^;]*\s\*(?:\s|;|$)", csp_lower):
            weaknesses.append("uso de curinga '*' em default-src ou script-src (permite scripts de qualquer domínio)")

        if weaknesses:
            return [AuditFinding(
                id="SEC-A05-CSP-PERMISSIVE",
                title="Política de Segurança de Conteúdo (CSP) Excessivamente Permissiva",
                category=self.owasp_category,
                severity=Severity.MEDIUM,
                url=current_url,
                description=(
                    "O cabeçalho Content-Security-Policy está presente, mas contém diretivas inseguras que "
                    "neutralizam a proteção contra Cross-Site Scripting (XSS)."
                ),
                evidence=f"Problemas detectados: {', '.join(weaknesses)} | Valor atual: {csp_value[:140]}",
                remediation="Substitua 'unsafe-inline' pelo uso de nonces criptográficos ('nonce-...') ou hashes SHA-256, e remova curingas '*' de script-src.",
                vibe_coding_context="Quando um script externo é bloqueado pelo navegador, a sugestão mais comum da IA é adicionar \"'unsafe-inline' 'unsafe-eval' *\" no CSP para fazer funcionar rapidamente."
            )]

        return []

    def _check_clickjacking(self, current_url: str, headers: Dict[str, str]) -> List[AuditFinding]:
        xfo = headers.get("x-frame-options", "").upper()
        csp = headers.get("content-security-policy", "").lower()

        has_valid_xfo = xfo in ("DENY", "SAMEORIGIN")
        has_frame_ancestors = "frame-ancestors" in csp

        if not has_valid_xfo and not has_frame_ancestors:
            return [AuditFinding(
                id="SEC-A05-CLICKJACKING-MISSING",
                title="Ausência de Proteção contra Clickjacking (X-Frame-Options / frame-ancestors)",
                category=self.owasp_category,
                severity=Severity.LOW,
                url=current_url,
                description=(
                    "A página não define o cabeçalho 'X-Frame-Options' (DENY/SAMEORIGIN) nem a diretiva "
                    "'frame-ancestors' no CSP. Isso permite que a interface seja embutida em um <iframe> "
                    "transparente dentro de um site malicioso para induzir cliques involuntários."
                ),
                evidence=f"X-Frame-Options='{xfo or 'Ausente'}', CSP frame-ancestors='Ausente'",
                remediation="Adicione 'X-Frame-Options: DENY' (ou SAMEORIGIN) e inclua \"frame-ancestors 'none'\" (ou 'self') no cabeçalho Content-Security-Policy.",
                vibe_coding_context="Aplicações SPA (React/Vue/Next) servidas sem middlewares de segurança (como o Helmet.js) não bloqueiam renderização em iframes de terceiros."
            )]

        return []

    def _check_cors(self, current_url: str, headers: Dict[str, str]) -> List[AuditFinding]:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if not acao:
            return []

        # Caso 1: Wildcard ou origem 'null' combinada com Credentials=true (Crítico)
        if (acao == "*" or acao.lower() == "null") and acac == "true":
            return [AuditFinding(
                id="SEC-A05-CORS-CRITICAL-MISCONFIG",
                title="Configuração Crítica de CORS (Origem Permissiva com Credenciais Ativas)",
                category=self.owasp_category,
                severity=Severity.HIGH,
                url=current_url,
                description=(
                    "O servidor combina 'Access-Control-Allow-Origin: *' (ou 'null') com "
                    "'Access-Control-Allow-Credentials: true'. Isso indica uma política de CORS mal "
                    "configurada que tenta expor respostas autenticadas para origens arbitrárias."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
                remediation="Defina uma lista estrita de domínios confiáveis no CORS e nunca combine origens curinga ('*' ou 'null') com suporte a credenciais.",
                vibe_coding_context="Ao enfrentar erros de CORS no frontend, é muito comum pedir ajuda à IA e receber um middleware 'cors({ origin: true, credentials: true })' ou '*'."
            )]

        # Caso 2: Wildcard aberto geral ou origem 'null'
        if acao == "*" or acao.lower() == "null":
            return [AuditFinding(
                id="SEC-A05-CORS-WILDCARD",
                title=f"Política de CORS Permissiva (Access-Control-Allow-Origin: {acao})",
                category=self.owasp_category,
                severity=Severity.LOW,
                url=current_url,
                description=(
                    "O cabeçalho 'Access-Control-Allow-Origin' permite que qualquer site externo ('*') "
                    "ou origens em sandbox ('null') leiam as respostas desta rota via JavaScript."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Se a rota não for uma API pública intencional, restrinja o cabeçalho Access-Control-Allow-Origin apenas ao domínio oficial do seu frontend.",
                vibe_coding_context="O uso de 'app.use(cors())' sem parâmetros no Express/FastAPI libera 'Access-Control-Allow-Origin: *' para todas as rotas da aplicação."
            )]

        return []

    def _check_hardening_headers(self, current_url: str, headers: Dict[str, str]) -> List[AuditFinding]:
        missing: List[str] = []

        if headers.get("x-content-type-options", "").lower() != "nosniff":
            missing.append("X-Content-Type-Options: nosniff (previne MIME-sniffing)")

        if "referrer-policy" not in headers:
            missing.append("Referrer-Policy (previne vazamento de URLs internas no cabeçalho Referer)")

        if "permissions-policy" not in headers:
            missing.append("Permissions-Policy (restringe acesso a câmera, microfone e geolocalização)")

        if not missing:
            return []

        return [AuditFinding(
            id="SEC-A05-HARDENING-HEADERS-MISSING",
            title=f"Cabeçalhos de Hardening do Navegador Ausentes ({len(missing)} cabeçalhos)",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description="A resposta HTTP não inclui cabeçalhos complementares de defesa em profundidade recomendados pela OWASP.",
            evidence="Ausentes: " + " | ".join(missing),
            remediation=(
                "Configure no servidor web ou middleware:\n"
                "- X-Content-Type-Options: nosniff\n"
                "- Referrer-Policy: strict-origin-when-cross-origin\n"
                "- Permissions-Policy: camera=(), microphone=(), geolocation=()"
            ),
            vibe_coding_context="Projetos criados do zero sem bibliotecas de hardening (como Helmet no Node.js ou Talisman/Secure no Python) omitem esses cabeçalhos por padrão."
        )]

    def _check_tech_disclosure_headers(self, current_url: str, headers: Dict[str, str]) -> List[AuditFinding]:
        leaked: List[str] = []

        for h in self.TECH_DISCLOSURE_HEADERS:
            if h in headers and headers[h]:
                leaked.append(f"{h}: {headers[h]}")

        server_val = headers.get("server", "")
        if server_val and self.SERVER_VERSION_REGEX.search(server_val):
            leaked.append(f"server: {server_val}")

        if not leaked:
            return []

        return [AuditFinding(
            id="SEC-A05-TECH-DISCLOSURE-HEADERS",
            title="Exposição de Versão e Tecnologia via Cabeçalhos HTTP (Fingerprinting)",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description=(
                "O servidor expõe nomes e versões exatas do framework ou servidor web nos cabeçalhos de resposta. "
                "Essas informações facilitam o mapeamento automatizado de vulnerabilidades conhecidas (CVEs)."
            ),
            evidence="Cabeçalhos verbosos: " + ", ".join(leaked),
            remediation="Desative o cabeçalho 'X-Powered-By' (ex.: 'app.disable(\"x-powered-by\")' no Express) e oculte a versão do servidor web ('server_tokens off' no Nginx).",
            vibe_coding_context="Frameworks como Express, PHP e ASP.NET enviam 'X-Powered-By' habilitado de fábrica se não forem explicitamente desativados."
        )]

    def _check_debug_exposure(self, current_url: str, html_content: str) -> List[AuditFinding]:
        detected_traces: List[str] = []

        for pattern, label in self.DEBUG_TRACE_PATTERNS:
            match = pattern.search(html_content)
            if match:
                snippet = match.group(0).strip()[:70]
                detected_traces.append(f"{label} ('{snippet}...')")

        if not detected_traces:
            return []

        return [AuditFinding(
            id="SEC-A05-DEBUG-STACK-TRACE-EXPOSED",
            title="Modo Debug Ativo ou Stack Trace Exposto na Página",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A página HTML contém rastros de pilha (stack traces) detalhados ou telas de depuração ativas. "
                "Isso revela caminhos internos de arquivos no servidor, versões de bibliotecas, consultas SQL "
                "e variáveis de ambiente."
            ),
            evidence="Indícios encontrados: " + " | ".join(detected_traces),
            remediation="Desative imediatamente o modo debug em produção (ex.: DEBUG=False, NODE_ENV=production) e configure páginas de erro genéricas (500/404).",
            vibe_coding_context="Aplicações subidas para produção com a mesma configuração do ambiente de desenvolvimento local deixam o modo debug ligado."
        )]
