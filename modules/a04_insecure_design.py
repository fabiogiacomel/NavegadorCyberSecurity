"""
Módulo de Auditoria: A04:2021 - Design Inseguro (Insecure Design)
Analisa falhas de arquitetura e lógica de negócio no cliente:
- Confiança no cliente para cálculo de preços, descontos, saldos ou permissões (campos hidden/payloads)
- Fluxos críticos (login, registro, recuperação de senha, transferência) sem proteção anti-automação (CAPTCHA/Turnstile)
- Inputs de upload de arquivos sem restrição de extensões seguras
- Padrões de Mass Assignment (envio irrestrito de objetos de estado ou campos de privilégio)
"""

import re
from typing import List, Set, Tuple, Optional
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class InsecureDesignModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # Campos críticos de negócio que nunca devem ser confiados a inputs ocultos (<input type="hidden">)
    SENSITIVE_HIDDEN_FIELDS: Set[str] = {
        "price", "preco", "total", "total_price", "valor", "valor_total", "amount_total",
        "discount", "desconto", "discount_rate", "coupon_value",
        "balance", "saldo", "credits", "creditos",
        "role", "papel", "is_admin", "isadmin", "admin", "permissions", "permissoes",
        "plan", "plano", "tier", "verified", "is_verified", "approved"
    }

    # Padrões em JS que enviam preços/descontos/flags de aprovação calculados no frontend direto para a API
    CLIENT_TRUST_JS_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\b(?:totalPrice|finalPrice|precoTotal|valorFinal|discountAmount|isPaid|isApproved|isVerified)\s*:",
                re.IGNORECASE
            ),
            "Envio de preço final ou status de aprovação calculado no cliente"
        ),
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\.\.\.(?:user|currentUser|profile|state)\b[^}]*\}",
                re.IGNORECASE
            ),
            "Spread completo de objeto de usuário/estado para API (Risco de Mass Assignment)"
        ),
    ]

    # Palavras-chave que identificam formulários de fluxos críticos (sujeitos a brute-force / stuffing / fraude)
    CRITICAL_FORM_KEYWORDS: Set[str] = {
        "login", "signin", "sign-in", "auth", "register", "signup", "sign-up",
        "forgot", "reset", "recover", "password", "senha", "transfer", "transferir",
        "checkout", "payment", "pagamento", "withdraw", "saque"
    }

    # Assinaturas de provedores de CAPTCHA / Anti-Bot no HTML ou scripts
    BOT_PROTECTION_SIGNATURES: Tuple[str, ...] = (
        "g-recaptcha", "recaptcha", "cf-turnstile", "turnstile",
        "h-captcha", "hcaptcha", "arkoselabs", "funcaptcha", " friendly-captcha"
    )

    # Extensões perigosas se permitidas em <input type="file">
    DANGEROUS_FILE_EXTENSIONS: Set[str] = {
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".php", ".phtml",
        ".jsp", ".asp", ".aspx", ".py", ".rb", ".pl", ".cgi", ".js", ".html", ".htm", ".svg"
    }

    @property
    def module_id(self) -> str:
        return "mod_a04_insecure_design"

    @property
    def name(self) -> str:
        return "Design Inseguro & Lógica de Negócio (OWASP A04)"

    @property
    def description(self) -> str:
        return (
            "Audita falhas de lógica de negócio no cliente, manipulação de preços/permissões em campos ocultos, "
            "ausência de proteção anti-bot em fluxos sensíveis, uploads irrestritos e vetores de Mass Assignment."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A04_INSECURE_DESIGN

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # 1. Campos ocultos ou payloads JS manipulando preços, descontos ou privilégios
        findings.extend(self._check_client_side_business_trust(context.url, soup, all_text))

        # 2. Fluxos críticos sem proteção contra automação / força bruta (CAPTCHA / Turnstile)
        if soup:
            findings.extend(self._check_missing_bot_protection(context.url, soup, all_text))

            # 3. Upload de arquivos sem restrição segura de tipo
            findings.extend(self._check_unrestricted_file_uploads(context.url, soup))

        return findings

    def _check_client_side_business_trust(
        self, current_url: str, soup: Optional[BeautifulSoup], all_text: str
    ) -> List[AuditFinding]:
        evidences: List[str] = []

        if soup:
            for hidden in soup.find_all("input", attrs={"type": re.compile(r"^hidden$", re.IGNORECASE)}):
                name = (hidden.get("name") or hidden.get("id") or "").strip()
                val = (hidden.get("value") or "").strip()
                name_clean = name.lower().replace("-", "_")
                if name_clean in self.SENSITIVE_HIDDEN_FIELDS:
                    evidences.append(f"<input type='hidden' name='{name}' value='{val[:30]}'>")

        for pattern, label in self.CLIENT_TRUST_JS_PATTERNS:
            match = pattern.search(all_text)
            if match:
                snippet = " ".join(match.group(0).strip().split())
                if len(snippet) > 70:
                    snippet = snippet[:67] + "..."
                evidences.append(f"{label}: {snippet}")

        if not evidences:
            return []

        return [AuditFinding(
            id="SEC-A04-CLIENT-SIDE-TRUST-PRICING",
            title="Confiança Insegura no Cliente para Regras de Negócio, Preços ou Privilégios",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A aplicação transmite valores críticos de negócio (como preço total, desconto, saldo, plano ou "
                "papel do usuário) através de campos ocultos (<input type='hidden'>) ou payloads JSON montados no "
                "frontend. Um usuário mal-intencionado pode interceptar a requisição ou editar o DOM no navegador "
                "para comprar itens por R$ 0,01 ou elevar seus próprios privilégios (Mass Assignment)."
            ),
            evidence="Vetores de manipulação identificados: " + " | ".join(evidences[:6]),
            remediation=(
                "1. Envie apenas o identificador do produto/plano e a quantidade a partir do cliente; calcule preços, "
                "impostos e descontos exclusivamente no backend consultando o banco de dados.\n"
                "2. Utilize schemas de entrada estritos (DTOs no Pydantic/Zod) no servidor para ignorar campos como "
                "'role', 'isAdmin', 'balance' ou 'isPaid' enviados pelo cliente."
            ),
            vibe_coding_context=(
                "Em protótipos gerados por IA, é muito comum calcular o 'totalPrice' do carrinho no React e enviá-lo "
                "direto para a rota '/api/checkout', ou usar 'User.update(req.body)' permitindo Mass Assignment."
            )
        )]

    def _check_missing_bot_protection(
        self, current_url: str, soup: BeautifulSoup, all_text: str
    ) -> List[AuditFinding]:
        text_lower = all_text.lower()
        if any(sig in text_lower for sig in self.BOT_PROTECTION_SIGNATURES):
            return []

        unprotected_forms: List[str] = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "get").strip().upper()
            if method != "POST":
                continue

            action = (form.get("action") or "").strip()
            input_names = [
                (inp.get("name") or inp.get("id") or inp.get("type") or "").lower()
                for inp in form.find_all("input")
            ]
            combined_form_meta = f"{action.lower()} {' '.join(input_names)}"

            if any(kw in combined_form_meta for kw in self.CRITICAL_FORM_KEYWORDS):
                unprotected_forms.append(f"<form action='{action or current_url}' method='POST'>")

        if not unprotected_forms:
            return []

        return [AuditFinding(
            id="SEC-A04-MISSING-BOT-PROTECTION",
            title=f"Fluxo Crítico Sem Proteção Contra Automação / Bots ({len(unprotected_forms)} formulário(s))",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description=(
                "Foram detectados formulários sensíveis (autenticação, cadastro, recuperação de senha ou transações) "
                "sem indícios de desafios anti-automação (como Cloudflare Turnstile, hCaptcha ou reCAPTCHA). "
                "A ausência de defesa contra bots facilita ataques de Credential Stuffing, criação massiva de contas "
                "falsas e exaustão de recursos."
            ),
            evidence="Formulários desprotegidos: " + ", ".join(unprotected_forms[:4]),
            remediation=(
                "Integre proteção anti-bot invisível ou adaptativa (ex.: Cloudflare Turnstile ou reCAPTCHA v3) "
                "combinada com Rate Limiting progressivo e bloqueio temporário por IP/conta no backend."
            ),
            vibe_coding_context=(
                "Assistentes de IA criam telas de login, cadastro e reset de senha funcionais, mas nunca adicionam "
                "CAPTCHA ou limitação de tentativas a menos que o desenvolvedor peça explicitamente."
            )
        )]

    def _check_unrestricted_file_uploads(
        self, current_url: str, soup: BeautifulSoup
    ) -> List[AuditFinding]:
        risky_uploads: List[str] = []

        for file_input in soup.find_all("input", attrs={"type": re.compile(r"^file$", re.IGNORECASE)}):
            name = file_input.get("name") or file_input.get("id") or "unnamed_file"
            accept = (file_input.get("accept") or "").strip().lower()

            if not accept or accept == "*/*" or accept == "*":
                risky_uploads.append(f"<input type='file' name='{name}'> (sem atributo 'accept' restritivo)")
            else:
                accepted_parts = [p.strip() for p in accept.split(",")]
                dangerous_found = [ext for ext in self.DANGEROUS_FILE_EXTENSIONS if ext in accepted_parts]
                if dangerous_found:
                    risky_uploads.append(
                        f"<input type='file' name='{name}' accept='{accept}'> (permite {', '.join(dangerous_found)})"
                    )

        if not risky_uploads:
            return []

        return [AuditFinding(
            id="SEC-A04-UNRESTRICTED-FILE-UPLOAD",
            title="Campo de Upload de Arquivo Sem Restrição Segura de Tipo",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "A página contém campos de envio de arquivo (<input type='file'>) que não restringem os tipos "
                "permitidos ou aceitam formatos executáveis/ativos (como .html, .svg, .js, .php, .exe). "
                "Se o backend confiar apenas na extensão ou salvar o arquivo em diretório público, invasores "
                "podem realizar Stored XSS (via SVG/HTML) ou Execução Remota de Código (Web Shell)."
            ),
            evidence="Inputs identificados: " + " | ".join(risky_uploads[:5]),
            remediation=(
                "1. No frontend, defina o atributo 'accept' com uma lista restrita (ex.: accept='.pdf,.png,.jpg').\n"
                "2. No backend, valide os Magic Bytes (assinatura binária real do arquivo), renomeie o arquivo para "
                "um UUID aleatório e sirva uploads a partir de um domínio segregado (S3/CDN) com 'Content-Disposition: attachment'."
            ),
            vibe_coding_context=(
                "Ao pedir um 'upload de avatar ou comprovante', a IA gera um '<input type=\"file\">' genérico "
                "e no backend salva o arquivo usando 'file.filename' original diretamente na pasta '/static/uploads'."
            )
        )]
