"""
Módulo de Auditoria: A01:2021 - Quebra de Controle de Acesso (Broken Access Control)
Analisa rotas administrativas expostas no frontend, links com parâmetros de redirecionamento aberto (Open Redirect),
vetores de IDOR (referência direta a objetos), tokens na URL e checagens de permissão inseguras no cliente.
"""

import re
from typing import List, Set, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class BrokenAccessControlModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    REDIRECT_PARAMS: Set[str] = {
        "redirect", "redirect_to", "redirect_uri", "next", "return",
        "return_url", "return_to", "url", "goto", "dest", "destination",
        "continue", "target", "view", "out", "callback"
    }

    # Parâmetros que jamais deveriam trafegar na Query String da URL
    SENSITIVE_URL_PARAMS: Set[str] = {
        "token", "access_token", "auth_token", "id_token", "refresh_token",
        "api_key", "apikey", "secret", "jwt", "session_id", "sid",
        "reset_token", "password", "passwd", "bearer"
    }

    # Assinatura de token JWT (header.payload.signature em Base64URL)
    JWT_REGEX = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")

    SENSITIVE_ROUTE_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"['\"`](/api/(?:v\d+/)?(?:debug|admin|users|seed|test|reset|internal)(?:/[\w\-\./?=&\${}]*)?)['\"`]", re.IGNORECASE),
            "Endpoint de API Sensível / Debug"
        ),
        (
            re.compile(r"['\"`](/(?:admin|administrator|superadmin|internal|backoffice|dashboard)(?:/[\w\-\./?=&\${}]*)?)['\"`]", re.IGNORECASE),
            "Rota de Painel Administrativo"
        ),
        (
            re.compile(r"['\"`](/(?:docs|swagger|redoc|api-docs|graphql|\.env(?:\.\w+)?|\.git(?:/config)?)(?:/[\w\-\./]*)?)['\"`]", re.IGNORECASE),
            "Documentação ou Arquivo de Configuração"
        ),
    ]

    CLIENT_SIDE_AUTH_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"(?:localStorage|sessionStorage)\.getItem\(\s*['\"`](?:role|is_?admin|user_?role|permissions)['\"`]\s*\)", re.IGNORECASE),
            "Leitura de privilégio via Storage do navegador"
        ),
        (
            re.compile(r"\b(?:user|currentUser|profile)\.(?:is_?admin|role)\s*===\s*['\"`]?admin['\"`]?", re.IGNORECASE),
            "Verificação condicional de perfil administrativo no cliente"
        ),
    ]

    # Padrões para detecção de possíveis vetores de IDOR
    IDOR_URL_PATH_REGEX = re.compile(
        r"/(?:api/(?:v\d+/)?)?(?:users?|accounts?|profiles?|orders?|invoices?|documents?|wallets?|messages?|tickets?)/(\d{1,10})(?:/|$|\?)",
        re.IGNORECASE
    )
    IDOR_QUERY_PARAM_REGEX = re.compile(
        r"^(?:user_?id|account_?id|profile_?id|order_?id|invoice_?id|doc_?id|customer_?id|owner_?id)$",
        re.IGNORECASE
    )
    # Detecta código cliente enviando user_id dinamicamente para a API (ex: `/api/orders?userId=${user.id}`)
    IDOR_JS_CLIENT_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"['\"`]/api/[\w\-/]+[?&](?:user_?id|account_?id|owner_?id)=\$\{[^}]+\}", re.IGNORECASE),
            "Envio de ID de usuário via Query String dinâmica na API"
        ),
        (
            re.compile(r"['\"`]/api/(?:v\d+/)?(?:users|accounts|profiles)/\$\{(?:user\.id|currentUser\.id|localStorage\.[^}]+)\}", re.IGNORECASE),
            "Interpolação direta do ID do usuário logado na rota da API"
        ),
    ]

    @property
    def module_id(self) -> str:
        return "mod_a01_broken_access"

    @property
    def name(self) -> str:
        return "Controle de Acesso & Rotas Sensíveis (OWASP A01)"

    @property
    def description(self) -> str:
        return "Identifica rotas sensíveis expostas, riscos de Open Redirect, vetores de IDOR, tokens na URL e checagens inseguras no frontend."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A01_BROKEN_ACCESS

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        parsed_base_url = urlparse(context.url)
        base_host = parsed_base_url.netloc.lower()
        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        # Coleta URLs da página (URL atual + links <a href> do DOM) para evitar múltiplos parses do HTML
        candidate_urls = self._extract_candidate_urls(context.url, html_content)

        # 1. Análise de Open Redirect
        findings.extend(self._check_open_redirects(context.url, candidate_urls, base_host))

        # 2. Exposição de Tokens e Credenciais na URL
        findings.extend(self._check_tokens_in_url(context.url, candidate_urls))

        # 3. Análise de Vetores de IDOR (URLs e código JS)
        findings.extend(self._check_idor_vectors(context.url, candidate_urls, all_text))

        # 4. Exposição de Rotas e Endpoints Sensíveis no Frontend
        findings.extend(self._check_sensitive_routes(context.url, all_text))

        # 5. Controle de Acesso Baseado Apenas no Cliente
        findings.extend(self._check_client_side_auth(context.url, all_text))

        return findings

    def _extract_candidate_urls(self, current_url: str, html_content: str) -> Set[str]:
        urls = {current_url}
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                urls.add(a_tag["href"])
        return urls

    @staticmethod
    def _mask_secret(value: str) -> str:
        """Ofusca parte do token para não vazar credenciais reais no relatório."""
        if len(value) <= 8:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    def _is_external_or_dangerous_redirect(self, target_url: str, base_host: str) -> bool:
        decoded = unquote(target_url).strip()
        if decoded.lower().startswith(("javascript:", "data:", "vbscript:")):
            return True
        if decoded.startswith(("\\\\", "/\\", "\\/")):
            return True
        if decoded.startswith(("http://", "https://", "//")):
            parsed_target = urlparse(decoded)
            target_host = parsed_target.netloc.lower()
            return bool(target_host and target_host != base_host)
        return False

    def _check_open_redirects(self, current_url: str, candidate_urls: Set[str], base_host: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        flagged_params: Set[str] = set()

        for target in candidate_urls:
            try:
                parsed = urlparse(target)
                query_params = parse_qs(parsed.query)
            except ValueError:
                continue

            for raw_param, values in query_params.items():
                param_lower = raw_param.lower()
                if param_lower in self.REDIRECT_PARAMS and param_lower not in flagged_params:
                    for val in values:
                        if self._is_external_or_dangerous_redirect(val, base_host):
                            flagged_params.add(param_lower)
                            findings.append(AuditFinding(
                                id=f"SEC-A01-OPEN-REDIRECT-{param_lower.upper()}",
                                title=f"Possível Vetor de Redirecionamento Aberto (Open Redirect) no parâmetro '{raw_param}'",
                                category=self.owasp_category,
                                severity=Severity.MEDIUM,
                                url=current_url,
                                description=(
                                    f"O parâmetro '{raw_param}' recebe um destino externo ou esquema não seguro. "
                                    "Se a aplicação redirecionar o usuário sem validar o domínio contra uma lista "
                                    "de permissões, invasores podem criar links de phishing utilizando o seu domínio."
                                ),
                                evidence=f"Parâmetro detectado: {raw_param}={val}",
                                remediation="Permita apenas caminhos relativos (iniciados por '/' simples) ou valide o domínio de destino contra uma allowlist estrita no backend.",
                                vibe_coding_context="Padrão muito comum ao criar fluxo de login 'após logar redirecione para ?next=...'. A IA implementa o redirect direto sem checar se a URL aponta para outro domínio."
                            ))
                            break
        return findings

    def _check_tokens_in_url(self, current_url: str, candidate_urls: Set[str]) -> List[AuditFinding]:
        exposed_items: List[str] = []
        seen_keys: Set[str] = set()

        for target in candidate_urls:
            try:
                parsed = urlparse(target)
                # Verifica tanto a query (?token=...) quanto o fragmento (#access_token=...)
                params_sources = [parse_qs(parsed.query), parse_qs(parsed.fragment)]
            except ValueError:
                continue

            for params in params_sources:
                for raw_param, values in params.items():
                    param_lower = raw_param.lower()
                    for val in values:
                        is_sensitive_name = param_lower in self.SENSITIVE_URL_PARAMS
                        is_jwt_value = bool(self.JWT_REGEX.match(val))

                        if (is_sensitive_name or is_jwt_value) and param_lower not in seen_keys:
                            seen_keys.add(param_lower)
                            masked = self._mask_secret(val)
                            reason = "Formato JWT" if is_jwt_value else "Parâmetro sensível"
                            exposed_items.append(f"{raw_param}={masked} ({reason})")

        if not exposed_items:
            return []

        return [AuditFinding(
            id="SEC-A01-TOKEN-IN-URL",
            title="Token de Autenticação ou Credencial Exposta na URL",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "Foram detectados tokens de sessão, chaves de API ou JWTs trafegando diretamente em parâmetros de URL. "
                "Dados na URL ficam gravados no histórico do navegador, em logs de servidores/proxies e vazam para sites "
                "externos através do cabeçalho HTTP Referer."
            ),
            evidence="Parâmetros expostos: " + ", ".join(exposed_items[:6]),
            remediation="Trafegue tokens exclusivamente via cabeçalhos HTTP (Authorization: Bearer) ou cookies seguros com as flags HttpOnly, Secure e SameSite.",
            vibe_coding_context="Ao implementar OAuth, recuperação de senha ou redirecionamento pós-login, a IA frequentemente passa '?token=jwt_aqui' na URL para facilitar a leitura pelo frontend."
        )]

    def _check_idor_vectors(self, current_url: str, candidate_urls: Set[str], all_text: str) -> List[AuditFinding]:
        idor_evidences: List[str] = []

        # 1. Verifica IDs sequenciais em rotas e query strings nas URLs coletadas
        for target in candidate_urls:
            try:
                parsed = urlparse(target)
            except ValueError:
                continue

            path_match = self.IDOR_URL_PATH_REGEX.search(parsed.path)
            if path_match:
                idor_evidences.append(f"Rota com ID sequencial: {path_match.group(0)}")

            for raw_param, values in parse_qs(parsed.query).items():
                if self.IDOR_QUERY_PARAM_REGEX.match(raw_param):
                    for val in values:
                        if val.isdigit():
                            idor_evidences.append(f"Parâmetro sequencial: {raw_param}={val}")

        # 2. Verifica padrões de código cliente enviando userId dinamicamente para a API
        for pattern, label in self.IDOR_JS_CLIENT_PATTERNS:
            for match in pattern.findall(all_text):
                idor_evidences.append(f"{match} [{label}]")

        # Remove duplicatas preservando a ordem
        unique_evidences = list(dict.fromkeys(idor_evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A01-POTENTIAL-IDOR-VECTOR",
            title="Possível Vetor de IDOR (Referência Direta Insegura a Objetos)",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "A aplicação expõe identificadores numéricos sequenciais em rotas/parâmetros de recursos sensíveis "
                "ou envia o ID do usuário diretamente pelo frontend nas chamadas de API. Se o backend não validar se o "
                "recurso pertence ao usuário autenticado na sessão, qualquer pessoa poderá acessar dados de terceiros "
                "apenas incrementando o número do ID."
            ),
            evidence="Vetores identificados: " + " | ".join(unique_evidences[:6]),
            remediation=(
                "1. No backend, valide a propriedade do recurso comparando o dono do registro com o ID do usuário extraído "
                "do token/sessão no servidor (nunca confie no user_id vindo do cliente).\n"
                "2. Substitua IDs numéricos sequenciais por identificadores não enumeráveis (UUID v4 ou ULID)."
            ),
            vibe_coding_context=(
                "Erro clássico de Vibe Coding: pedir para a IA 'buscar os pedidos do usuário logado' geralmente resulta "
                "em um endpoint '/api/orders?user_id=123' que faz apenas 'SELECT * FROM orders WHERE user_id = req.query.user_id' "
                "sem checar quem está fazendo a requisição."
            )
        )]

    def _check_sensitive_routes(self, current_url: str, all_text: str) -> List[AuditFinding]:
        found_routes: dict[str, str] = {}

        for pattern, label in self.SENSITIVE_ROUTE_PATTERNS:
            for match in pattern.findall(all_text):
                if match not in found_routes:
                    found_routes[match] = label

        if not found_routes:
            return []

        evidence_items = [f"{route} ({label})" for route, label in list(found_routes.items())[:8]]

        return [AuditFinding(
            id="SEC-A01-SENSITIVE-ENDPOINTS-EXPOSED",
            title=f"Rotas e Endpoints Sensíveis Referenciados no Código Cliente ({len(found_routes)} rotas)",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description="O código HTML ou JavaScript do cliente contém referências diretas a rotas administrativas, documentações internas, arquivos sensíveis ou endpoints de debug.",
            evidence="Rotas encontradas: " + ", ".join(evidence_items),
            remediation="Garanta que todas essas rotas exijam autenticação e controle de acesso (RBAC) no backend. Desative endpoints de debug e documentações interativas (Swagger/Redoc) em produção.",
            vibe_coding_context="Ao programar com IA, o código frequentemente expõe todas as rotas da aplicação no bundle principal do frontend, mesmo para usuários não autenticados."
        )]

    def _check_client_side_auth(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidence_matches: List[str] = []

        for pattern, label in self.CLIENT_SIDE_AUTH_PATTERNS:
            match = pattern.search(all_text)
            if match:
                evidence_matches.append(f"{match.group(0)} [{label}]")

        if not evidence_matches:
            return []

        return [AuditFinding(
            id="SEC-A01-CLIENT-SIDE-AUTH-CHECK",
            title="Indício de Controle de Acesso Baseado no Lado do Cliente",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description="Foram identificadas verificações de perfil administrativo ou leitura de permissões diretamente no armazenamento do navegador (localStorage/sessionStorage) ou estado do frontend.",
            evidence="Trechos encontrados: " + " | ".join(evidence_matches),
            remediation="Nunca confie no estado do cliente ou no localStorage para autorizar ações. Valide permissões e papéis (roles) no backend a cada requisição usando tokens assinados (JWT) ou sessões seguras em cookies HttpOnly.",
            vibe_coding_context="Ferramentas de IA costumam salvar 'role: admin' no localStorage após o login para ocultar botões ou bloquear páginas no React/Vue, esquecendo de validar a permissão na API."
        )]
