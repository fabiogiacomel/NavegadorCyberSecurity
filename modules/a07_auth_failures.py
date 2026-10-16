"""
Módulo de Auditoria: A07:2021 - Falhas de Identificação e Autenticação
Verifica flags de segurança em Cookies de sessão (HttpOnly, Secure, SameSite),
detecção de tokens JWT/senhas em localStorage/sessionStorage e parâmetros na URL.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import List
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class AuthAndSessionFailuresModule(BaseAuditModule):
    @property
    def module_id(self) -> str:
        return "mod_a07_auth_failures"

    @property
    def name(self) -> str:
        return "Autenticação, Sessões & Armazenamento Seguro (OWASP A07)"

    @property
    def description(self) -> str:
        return "Audita a segurança de cookies de autenticação (HttpOnly, Secure, SameSite) e armazenamento de credenciais no navegador."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A07_AUTH_FAILURES

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith("chrome://") or context.url.startswith("about:"):
            return findings

        # 1. Auditoria de Cookies
        session_cookie_names = {"session", "sessionid", "connect.sid", "phpsessid", "jsessionid", "token", "auth", "jwt", "access_token"}
        
        for cookie in context.cookies:
            c_name = cookie.get("name", "")
            c_name_lower = c_name.lower()
            http_only = cookie.get("httpOnly", False)
            secure = cookie.get("secure", False)
            same_site = str(cookie.get("sameSite", "")).lower()

            is_likely_session = any(s in c_name_lower for s in session_cookie_names)

            # Cookie sem HttpOnly
            if not http_only:
                severity = Severity.HIGH if is_likely_session else Severity.MEDIUM
                findings.append(AuditFinding(
                    id=f"SEC-A07-COOKIE-NO-HTTPONLY-{c_name}",
                    title=f"Cookie '{c_name}' Sem Flag HttpOnly",
                    category=self.owasp_category,
                    severity=severity,
                    url=context.url,
                    description=f"O cookie '{c_name}' pode ser lido diretamente por scripts JavaScript via document.cookie. Se houver qualquer vulnerabilidade XSS na aplicação, o invasor poderá roubar a sessão da vítima imediatamente.",
                    evidence=f"Cookie: {c_name} | HttpOnly: False | Secure: {secure}",
                    remediation=f"Defina a flag HttpOnly ao emitir o cookie no servidor: Set-Cookie: {c_name}=...; HttpOnly; Path=/",
                    vibe_coding_context="Em código gerado por IA, é muito comum criar rotas de login que retornam 'res.cookie(...)' sem especificar { httpOnly: true }."
                ))

            # Cookie sem Secure em página HTTPS
            if context.url.startswith("https://") and not secure:
                findings.append(AuditFinding(
                    id=f"SEC-A07-COOKIE-NO-SECURE-{c_name}",
                    title=f"Cookie '{c_name}' Sem Flag Secure em HTTPS",
                    category=self.owasp_category,
                    severity=Severity.MEDIUM,
                    url=context.url,
                    description=f"O cookie '{c_name}' não possui a diretiva 'Secure'. Ele poderá ser transmitido em texto claro se o usuário fizer qualquer requisição HTTP não criptografada para o mesmo domínio.",
                    evidence=f"Cookie: {c_name} | Secure: False",
                    remediation=f"Adicione a flag Secure no servidor: Set-Cookie: {c_name}=...; Secure; HttpOnly",
                    vibe_coding_context="Durante o desenvolvimento local (localhost) sem SSL, IAs frequentemente instruem a desativar 'secure: false' e o desenvolvedor sobe para produção dessa forma."
                ))

            # Cookie SameSite None sem Secure ou sem SameSite
            if same_site == "none" and not secure:
                findings.append(AuditFinding(
                    id=f"SEC-A07-COOKIE-SAMESITE-NONE-INSECURE-{c_name}",
                    title=f"Cookie '{c_name}' com SameSite=None sem Flag Secure",
                    category=self.owasp_category,
                    severity=Severity.HIGH,
                    url=context.url,
                    description="Cookies com SameSite=None exigem a flag Secure para evitar abusos em contextos de terceiros e ataques CSRF.",
                    evidence=f"Cookie: {c_name} | SameSite: {same_site} | Secure: {secure}",
                    remediation="Configure SameSite=Lax ou SameSite=Strict, ou adicione a flag Secure.",
                    vibe_coding_context="Para contornar bloqueios de cookies entre portas locais (ex: 3000 e 8000), o código gerado por IA frequentemente aplica SameSite=None."
                ))

        # 2. Auditoria de LocalStorage e SessionStorage (Anti-padrão clássico de Vibe Coding)
        all_storage = {
            "localStorage": context.local_storage,
            "sessionStorage": context.session_storage
        }

        jwt_regex = re.compile(r"^eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+")

        for storage_type, data in all_storage.items():
            for key, val in data.items():
                key_lower = key.lower()
                val_str = str(val)

                # Detecção de JWT no Web Storage
                is_jwt = bool(jwt_regex.search(val_str))
                is_auth_key = any(k in key_lower for k in ["token", "auth", "jwt", "access_token", "id_token", "session"])

                if is_jwt or (is_auth_key and len(val_str) > 20):
                    findings.append(AuditFinding(
                        id=f"SEC-A07-STORAGE-TOKEN-EXPOSURE-{storage_type}-{key}",
                        title=f"Token de Autenticação / JWT Armazenado em {storage_type}",
                        category=self.owasp_category,
                        severity=Severity.HIGH,
                        url=context.url,
                        description=f"Foi detectado um token de sessão/JWT armazenado na chave '{key}' de {storage_type}. Diferente de cookies com HttpOnly, o Web Storage é acessível por qualquer código JavaScript executado na página (incluindo dependências npm comprometidas ou falhas XSS).",
                        evidence=f"{storage_type}['{key}'] = {val_str[:40]}... (tamanho: {len(val_str)})",
                        remediation="Migre o armazenamento do token de autenticação para Cookies HTTP seguros com as flags 'HttpOnly', 'Secure' e 'SameSite=Lax'.",
                        vibe_coding_context="O erro nº 1 de vibe coding: a grande maioria dos tutoriais e templates gerados por IA em React/Vue/Next.js usam 'localStorage.setItem(\"token\", ...)' por facilidade de implementação, criando vulnerabilidade direta a roubo de sessão via XSS."
                    ))

        # 3. Credenciais sensíveis passadas via Query Params na URL
        parsed_url = urlparse(context.url)
        query_params = parse_qs(parsed_url.query)
        sensitive_params = ["password", "senha", "token", "auth_token", "apikey", "api_key", "secret", "access_token"]
        
        for sp in sensitive_params:
            if sp in query_params:
                findings.append(AuditFinding(
                    id=f"SEC-A07-CREDENTIAL-IN-URL-{sp}",
                    title=f"Credencial / Segredo Transmitido na URL (Query Param '{sp}')",
                    category=self.owasp_category,
                    severity=Severity.HIGH,
                    url=context.url,
                    description=f"O parâmetro sensível '{sp}' foi exposto diretamente na barra de endereços (URL). URLs ficam gravadas no histórico do navegador, nos logs do servidor web, proxies corporativos e no cabeçalho HTTP Referer.",
                    evidence=f"Parâmetro detectado na URL: ?{sp}=******",
                    remediation="Transmita dados sensíveis e autenticação no corpo (body) de requisições POST com HTTPS ou em cabeçalhos Authorization: Bearer.",
                    vibe_coding_context="IAs por vezes geram links rápidos de ativação, callbacks ou buscas passando tokens ou senhas direto em query string."
                ))

        return findings
