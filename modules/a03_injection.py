"""
Módulo de Auditoria: A03:2021 - Injeção & Cross-Site Scripting (Injection / XSS)
Detecta sinks perigosos de DOM XSS com atribuição dinâmica, bypass de sanitização em frameworks
(React/Vue/Angular/Svelte), execução de código via eval(), listeners postMessage inseguros,
interpolação direta de strings em queries e formulários POST sem token CSRF.
"""

import re
from typing import List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class InjectionXssModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # 1. Sinks nativos de DOM XSS: ignora atribuições estáticas simples (ex: innerHTML = "" ou "<b>Texto</b>")
    # Captura apenas variáveis, concatenações ou template literals com ${...}
    DYNAMIC_DOM_SINKS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"\.(?:innerHTML|outerHTML)\s*\+?=\s*(?:`[^`]*\$\{[^`]+`|[a-zA-Z_$][\w\.\[\]()]*|['\"][^'\"]*['\"]\s*\+)",
                re.IGNORECASE
            ),
            "Atribuição dinâmica em innerHTML/outerHTML"
        ),
        (
            re.compile(
                r"\.insertAdjacentHTML\s*\(\s*['\"`][^'\"`]+['\"`]\s*,\s*(?:`[^`]*\$\{[^`]+`|[a-zA-Z_\$][\w\.\[\]()]*)",
                re.IGNORECASE
            ),
            "Inserção dinâmica via insertAdjacentHTML"
        ),
        (
            re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*(?!['\"`]\s*['\"`]\s*\))[^)]+\)", re.IGNORECASE),
            "Escrita direta no DOM via document.write()"
        ),
    ]

    # 2. Desativação explícita de proteção XSS em frameworks (React, Vue, Angular, Svelte)
    FRAMEWORK_XSS_SINKS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"\bdangerouslySetInnerHTML\s*[:=]\s*\{\s*\{\s*__html\s*:", re.IGNORECASE),
            "React dangerouslySetInnerHTML"
        ),
        (
            re.compile(r"\bv-html\s*=\s*['\"`][^'\"`]+['\"`]", re.IGNORECASE),
            "Diretiva Vue v-html"
        ),
        (
            re.compile(r"\bbypassSecurityTrust(?:Html|Script|ResourceUrl|Url)\s*\(", re.IGNORECASE),
            "Bypass de DomSanitizer no Angular"
        ),
        (
            re.compile(r"\{\s*@html\s+[^}]+\}", re.IGNORECASE),
            "Renderização bruta Svelte {@html}"
        ),
    ]

    # 3. Sinks de execução de código arbitrário (Eval / Code Injection)
    CODE_EXECUTION_SINKS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"(?<![\.\w])eval\s*\(\s*[^)]+\)", re.IGNORECASE),
            "Execução dinâmica via eval()"
        ),
        (
            re.compile(r"\bnew\s+Function\s*\(\s*[^)]+\)", re.IGNORECASE),
            "Construtor dinâmico new Function()"
        ),
        (
            re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"`][^'\"`]+['\"`]", re.IGNORECASE),
            "setTimeout/setInterval avaliando string como código"
        ),
    ]

    # 4. Interpolação direta de variáveis em queries (GraphQL / SQL em Template Strings)
    QUERY_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"`\s*(?:query|mutation)\s*[^{]*\{[^`]*\$\{[^}]+\}[^`]*`",
                re.IGNORECASE
            ),
            "Interpolação direta de string em query GraphQL (sem GraphQL Variables)"
        ),
        (
            re.compile(
                r"`\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[^`]*\$\{[^}]+\}[^`]*`",
                re.IGNORECASE
            ),
            "Concatenação direta de variável em consulta SQL"
        ),
    ]

    # 5. Listener de postMessage para verificar se há checagem de event.origin
    POSTMESSAGE_LISTENER_REGEX = re.compile(
        r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(?:async\s*)?(?:function\s*\(\s*(\w+)\s*\)|(?:\(\s*(\w+)\s*\)|(\w+))\s*=>)\s*\{([^}]{1,450})\}",
        re.IGNORECASE | re.DOTALL
    )

    @property
    def module_id(self) -> str:
        return "mod_a03_injection_xss"

    @property
    def name(self) -> str:
        return "Injeção de Código & Cross-Site Scripting (OWASP A03)"

    @property
    def description(self) -> str:
        return "Detecta sinks de DOM XSS (innerHTML, dangerouslySetInnerHTML, eval), postMessage sem validação de origem e injeção em queries."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A03_INJECTION

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # 1. Sinks Nativos de DOM XSS e Escape Hatches de Frameworks
        findings.extend(self._check_dom_and_framework_sinks(context.url, all_text, soup))

        # 2. Sinks de Execução de Código (eval, new Function, setTimeout com string)
        findings.extend(self._check_code_execution_sinks(context.url, all_text))

        # 3. Listeners de postMessage sem verificação de origem
        findings.extend(self._check_insecure_postmessage(context.url, all_text))

        # 4. Interpolação de Strings em Queries (GraphQL / SQL)
        findings.extend(self._check_query_interpolation(context.url, all_text))

        # 5. Parâmetros da URL refletidos dentro de tags <script>
        if soup:
            findings.extend(self._check_reflected_params_in_scripts(context.url, soup))
            # 6. Formulários POST sem proteção Anti-CSRF
            findings.extend(self._check_csrf_forms(context.url, soup))

        return findings

    @staticmethod
    def _clean_snippet(text: str, max_len: int = 75) -> str:
        cleaned = " ".join(text.strip().split())
        return cleaned[:max_len - 3] + "..." if len(cleaned) > max_len else cleaned

    def _check_dom_and_framework_sinks(
        self, current_url: str, all_text: str, soup: Optional[BeautifulSoup]
    ) -> List[AuditFinding]:
        evidences: List[str] = []

        # Checa sinks nativos dinâmicos
        for pattern, label in self.DYNAMIC_DOM_SINKS:
            match = pattern.search(all_text)
            if match:
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        # Checa sinks de frameworks (React, Vue, Angular, Svelte)
        for pattern, label in self.FRAMEWORK_XSS_SINKS:
            match = pattern.search(all_text)
            if match:
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        # Checa links com esquema javascript: ativo no DOM (ignorando void(0) ou vazios)
        if soup:
            for tag in soup.find_all(["a", "iframe", "area"], href=True):
                href = tag["href"].strip()
                if href.lower().startswith("javascript:"):
                    payload = href[11:].strip().lower()
                    if payload and not payload.startswith(("void(0)", "void 0", ";", "false")):
                        evidences.append(f"URI javascript: ativa em tag <{tag.name}>: {self._clean_snippet(href)}")
                        break

        if not evidences:
            return []

        return [AuditFinding(
            id="SEC-A03-DOM-XSS-SINKS",
            title=f"Sinks Perigosos de DOM XSS Detectados ({len(evidences)} padrão(ões))",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "O código cliente insere conteúdo dinâmico diretamente no DOM sem a garantia de sanitização "
                "nativa (usando innerHTML, document.write, dangerouslySetInnerHTML ou v-html). Se esses valores "
                "tiverem origem em parâmetros da URL, entradas de usuário ou respostas da API não sanitizadas, "
                "um invasor poderá executar JavaScript arbitrário (XSS) na sessão da vítima."
            ),
            evidence="Sinks identificados: " + " | ".join(evidences[:6]),
            remediation=(
                "1. Para inserir apenas texto, substitua 'innerHTML' por 'textContent' ou 'innerText'.\n"
                "2. Se precisar renderizar HTML rico ou Markdown, sanitize o conteúdo previamente com 'DOMPurify.sanitize()' "
                "antes de passá-lo para innerHTML ou dangerouslySetInnerHTML."
            ),
            vibe_coding_context=(
                "Ao pedir para a IA renderizar textos formatados, respostas de chat ou Markdown no React/Vue, "
                "ela frequentemente usa dangerouslySetInnerHTML ou innerHTML direto sem acoplar o DOMPurify."
            )
        )]

    def _check_code_execution_sinks(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.CODE_EXECUTION_SINKS:
            match = pattern.search(all_text)
            if match:
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        if not evidences:
            return []

        return [AuditFinding(
            id="SEC-A03-DYNAMIC-CODE-EVAL",
            title="Execução Dinâmica de Código JavaScript (eval / Function)",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "Foram identificadas chamadas que compilam e executam strings como código JavaScript em tempo de execução "
                "(eval, new Function ou setTimeout com string). Além de impedir a aplicação de uma política CSP segura, "
                "qualquer dado controlado pelo usuário nessas funções resulta em execução imediata de código (XSS)."
            ),
            evidence="Ocorrências: " + " | ".join(evidences),
            remediation=(
                "Substitua 'eval()' por 'JSON.parse()' ao processar dados estruturados e utilize sempre "
                "funções anônimas (arrow functions) no 'setTimeout(() => ...)' em vez de strings."
            ),
            vibe_coding_context=(
                "IAs frequentemente recorrem ao 'eval()' quando o usuário pede uma calculadora rápida, "
                "interpretador de fórmulas ou parser dinâmico de objetos no frontend."
            )
        )]

    def _check_insecure_postmessage(self, current_url: str, all_text: str) -> List[AuditFinding]:
        vulnerable_listeners: List[str] = []

        for match in self.POSTMESSAGE_LISTENER_REGEX.finditer(all_text):
            event_var = match.group(1) or match.group(2) or match.group(3) or "event"
            handler_body = match.group(4)

            # Verifica se o corpo da função checa .origin no objeto do evento
            origin_check_regex = re.compile(rf"\b{re.escape(event_var)}\.origin\b")
            if not origin_check_regex.search(handler_body):
                vulnerable_listeners.append(self._clean_snippet(match.group(0), 90))

        if not vulnerable_listeners:
            return []

        return [AuditFinding(
            id="SEC-A03-INSECURE-POSTMESSAGE",
            title="Listener de window.postMessage Sem Validação de Origem",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A página registra um listener para eventos 'message' (window.addEventListener('message', ...)), "
                "mas não valida a propriedade 'event.origin' antes de processar os dados recebidos. Qualquer site "
                "malicioso aberto em outra aba pode enviar mensagens forjadas para esta janela."
            ),
            evidence="Handler sem checagem de .origin: " + " | ".join(vulnerable_listeners[:3]),
            remediation=(
                "Valide estritamente a origem no início do listener: "
                "\"if (event.origin !== 'https://seu-dominio-confiavel.com') return;\"."
            ),
            vibe_coding_context=(
                "Ao comunicar um iframe de checkout ou popup de login com a janela pai via postMessage, "
                "o código gerado por IA quase sempre consome 'event.data' direto sem validar 'event.origin'."
            )
        )]

    def _check_query_interpolation(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.QUERY_INJECTION_PATTERNS:
            match = pattern.search(all_text)
            if match:
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        if not evidences:
            return []

        return [AuditFinding(
            id="SEC-A03-CLIENT-QUERY-INTERPOLATION",
            title="Interpolação Direta de Variáveis em Consulta GraphQL ou SQL",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "O código constrói consultas GraphQL ou SQL concatenando variáveis diretamente dentro de "
                "template strings (${...}). Isso permite ataques de injeção para alterar a lógica da consulta "
                "e extrair dados não autorizados."
            ),
            evidence="Consultas vulneráveis: " + " | ".join(evidences),
            remediation=(
                "Utilize sempre consultas parametrizadas (Prepared Statements / '$1, $2' em SQL) ou o objeto "
                "nativo 'variables' nas requisições GraphQL em vez de interpolar strings."
            ),
            vibe_coding_context=(
                "É muito comum a IA montar queries GraphQL usando template strings (`query { user(id: \"${id}\") }`) "
                "por ser mais curto do que declarar o esquema de variáveis tipadas."
            )
        )]

    def _check_reflected_params_in_scripts(
        self, current_url: str, soup: BeautifulSoup
    ) -> List[AuditFinding]:
        parsed = urlparse(current_url)
        query_params = parse_qs(parsed.query)
        if not query_params:
            return []

        inline_scripts = "\n".join(
            s.get_text() for s in soup.find_all("script") if not s.get("src") and s.get_text()
        )
        if not inline_scripts:
            return []

        reflected: List[str] = []
        for param, values in query_params.items():
            for val in values:
                # Considera apenas valores com pelo menos 4 caracteres não numéricos para evitar falsos positivos
                if len(val) >= 4 and not val.isdigit() and val in inline_scripts:
                    reflected.append(f"{param}={self._clean_snippet(val, 30)}")

        if not reflected:
            return []

        return [AuditFinding(
            id="SEC-A03-REFLECTED-PARAM-IN-SCRIPT",
            title="Parâmetro da URL Refletido Diretamente Dentro de Bloco Script",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "Valores passados na query string da URL estão sendo inseridos diretamente dentro de um "
                "bloco <script> inline na resposta HTML. Se caracteres como aspas ou '</script>' não forem "
                "escapados pelo servidor, um invasor pode quebrar o contexto da string e executar XSS Refletido."
            ),
            evidence="Parâmetros refletidos no script: " + ", ".join(reflected[:5]),
            remediation=(
                "Nunca injete parâmetros da requisição diretamente em blocos <script>. Passe dados para o frontend "
                "via atributos 'data-*' devidamente codificados em HTML ou consuma-os via JSON seguro."
            ),
            vibe_coding_context=(
                "Templates SSR (EJS, Jinja2, Blade, PHP) gerados por IA frequentemente fazem "
                "'const search = \"{{ request.args.q }}\";' dentro do <script>, abrindo brecha imediata para XSS."
            )
        )]

    def _check_csrf_forms(self, current_url: str, soup: Optional[BeautifulSoup]) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not soup:
            return findings

        forms = soup.find_all("form")
        for idx, form in enumerate(forms, 1):
            method = form.get("method", "get").strip().upper()
            action = form.get("action", "").strip()

            if method == "POST":
                inputs = form.find_all("input")
                has_csrf_token = False

                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    if any(csrf_name in name for csrf_name in ["csrf", "xsrf", "_token", "authenticity_token"]):
                        has_csrf_token = True
                        break

                if not has_csrf_token:
                    findings.append(AuditFinding(
                        id=f"SEC-A03-FORM-MISSING-CSRF-{idx}",
                        title=f"Formulário POST #{idx} Sem Token Anti-CSRF",
                        category=self.owasp_category,
                        severity=Severity.HIGH,
                        url=current_url,
                        description="Formulários com método POST que alteram estado da aplicação devem incluir um token aleatório anti-CSRF para validar a autenticidade da requisição.",
                        evidence=f"<form action='{action}' method='POST'> (total inputs: {len(inputs)})",
                        remediation="Inclua um token CSRF único por sessão/requisição no formulário e valide no backend.",
                        vibe_coding_context="Quase 100% dos formulários gerados em vibe coding com HTML básico omitem tokens CSRF."
                    ))

        return findings


# Alias para retrocompatibilidade
InjectionAndDomXssModule = InjectionXssModule

__all__ = ["InjectionXssModule", "InjectionAndDomXssModule"]
