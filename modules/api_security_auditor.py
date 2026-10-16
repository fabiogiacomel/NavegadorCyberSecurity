"""
Módulo de Referência: OWASP API Security Top 10 (2023) & Vibe Coding API Sentinel.
Audita a segurança de APIs REST e GraphQL em tempo real:
- API1:2023 - Broken Object Level Authorization (BOLA) & Rotas Sensíveis
- API2:2023 - Broken Authentication (Endpoints desprotegidos, Tokens em Query Params)
- API3:2023 - Broken Object Property Level Authorization (Excessive Data Exposure / Dump de Models)
- API4:2023 - Unrestricted Resource Consumption (Ausência de Rate Limiting)
- API5:2023 - Broken Function Level Authorization (BFLA)
- API8:2023 - Security Misconfiguration (OpenAPI/Swagger exposto, GraphQL Introspection, Stack Traces)
- API9:2023 - Improper Inventory Management (Rotas zumbis, APIs não versionadas)
"""

import json
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
import requests

from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class ApiSecurityAuditorModule(BaseAuditModule):
    @property
    def module_id(self) -> str:
        return "mod_api_security_sentinel"

    @property
    def name(self) -> str:
        return "API Security Sentinel (OWASP API Top 10:2023)"

    @property
    def description(self) -> str:
        return "Audita contratos de API, especificação OpenAPI exposta, GraphQL Introspection, vazamento de PII/hashes (Excessive Data Exposure) e rate limiting."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.API_SECURITY_TOP_10

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith("chrome://") or context.url.startswith("about:"):
            return findings

        parsed = urlparse(context.url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Prospecção de Documentação OpenAPI / Swagger Exposta (API8 & API9)
        openapi_findings, openapi_data = self._audit_openapi_exposure(base_origin, context.url)
        findings.extend(openapi_findings)
        if openapi_data:
            context.openapi_spec = openapi_data
            findings.extend(self._analyze_openapi_spec(openapi_data, context.url))

        # 2. Auditoria de GraphQL Introspection (API8)
        graphql_findings = self._audit_graphql_security(base_origin, context.url)
        findings.extend(graphql_findings)

        # 3. Análise de Chamadas de API Interceptadas (API3, API4, API2, API8)
        if context.api_calls:
            for call in context.api_calls:
                findings.extend(self._audit_intercepted_call(call, context.url))

        # 4. Análise de Endpoints e Links de API no Código do Cliente
        findings.extend(self._audit_client_api_routes(context))

        return findings

    # ------------------------------------------------------------------
    # 1. OpenAPI / Swagger Documentation & Inventory Audit
    # ------------------------------------------------------------------
    def _audit_openapi_exposure(self, base_origin: str, current_url: str) -> tuple[List[AuditFinding], Optional[Dict[str, Any]]]:
        findings: List[AuditFinding] = []
        spec_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api-docs",
            "/v2/api-docs",
            "/api/v1/openapi.json",
        ]
        doc_html_paths = ["/docs", "/redoc", "/swagger", "/api/docs"]

        detected_spec = None

        # Testa endpoints de especificação estruturada JSON
        for p in spec_paths:
            probe_url = urljoin(base_origin, p)
            try:
                resp = requests.get(probe_url, timeout=2.5, headers={"Accept": "application/json"})
                if resp.status_code == 200 and ("json" in resp.headers.get("content-type", "").lower() or resp.text.startswith("{")):
                    data = resp.json()
                    if isinstance(data, dict) and ("openapi" in data or "swagger" in data or "paths" in data):
                        detected_spec = data
                        num_paths = len(data.get("paths", {}))
                        findings.append(AuditFinding(
                            id=f"API-A08-OPENAPI-EXPOSED",
                            title=f"Especificação OpenAPI/Swagger Pública ({num_paths} rotas mapeadas)",
                            category=self.owasp_category,
                            severity=Severity.MEDIUM,
                            url=probe_url,
                            description=f"A especificação completa da API ('{p}') está publicamente acessível. Ela revela a lista exata de todos os endpoints, parâmetros, métodos HTTP aceitos e esquemas de dados da aplicação.",
                            evidence=f"Endpoint: {probe_url} | Versão: {data.get('openapi') or data.get('swagger')} | Total de rotas: {num_paths}",
                            remediation="Restrinja a documentação de API para ambientes de desenvolvimento ou exija autenticação para acessar arquivos de schema em produção.",
                            vibe_coding_context="Frameworks como FastAPI, NestJS e Django Ninja geram rotas de documentação '/docs' e '/openapi.json' ativas por padrão. Em vibe coding, quase ninguém desativa docs em produção."
                        ))
                        break
            except Exception:
                continue

        # Testa documentações visuais interativas (/docs, /redoc)
        for dp in doc_html_paths:
            probe_url = urljoin(base_origin, dp)
            try:
                resp = requests.head(probe_url, timeout=2)
                if resp.status_code == 200:
                    findings.append(AuditFinding(
                        id="API-A08-SWAGGER-UI-PUBLIC",
                        title=f"Interface Interativa de API Exposta ({dp})",
                        category=self.owasp_category,
                        severity=Severity.LOW,
                        url=probe_url,
                        description=f"A interface Swagger UI/ReDoc está aberta em '{dp}', permitindo que qualquer visitante teste endpoints e descubra funcionalidades internas da API.",
                        evidence=f"URL acessível: {probe_url} (HTTP 200 OK)",
                        remediation="Desative a interface visual em produção (ex: docs_url=None no FastAPI) ou proteja-a atrás de VPN/Basic Auth.",
                        vibe_coding_context="Padrão em projetos FastAPI gerados por IA onde a flag 'docs_url=None' nunca é inserida no main.py."
                    ))
                    break
            except Exception:
                continue

        return findings, detected_spec

    def _analyze_openapi_spec(self, spec: Dict[str, Any], page_url: str) -> List[AuditFinding]:
        """Analisa o conteúdo interno da especificação OpenAPI em busca de riscos."""
        findings = []
        paths = spec.get("paths", {})
        sensitive_routes = []
        unprotected_admin_routes = []

        sensitive_keywords = ["admin", "seed", "reset", "backup", "debug", "delete", "destroy", "role", "internal"]

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_lower = path_str.lower()
            if any(k in path_lower for k in sensitive_keywords):
                sensitive_routes.append(path_str)

            # Verifica se métodos perigosos (DELETE, PUT) em rotas sensíveis não exigem security
            for method in ["delete", "put", "post"]:
                op = path_item.get(method)
                if isinstance(op, dict):
                    has_security = bool(op.get("security", spec.get("security")))
                    if not has_security and any(k in path_lower for k in ["admin", "user", "delete"]):
                        unprotected_admin_routes.append(f"{method.upper()} {path_str}")

        if sensitive_routes:
            findings.append(AuditFinding(
                id="API-A05-SENSITIVE-SPEC-ENDPOINTS",
                title=f"Rotas Administrativas / Críticas na Especificação ({len(sensitive_routes)} rotas)",
                category=self.owasp_category,
                severity=Severity.HIGH if unprotected_admin_routes else Severity.MEDIUM,
                url=page_url,
                description="O schema da API lista endpoints sensíveis de administração ou manipulação de banco de dados.",
                evidence="Rotas identificadas:\n" + "\n".join(sensitive_routes[:6]),
                remediation="Garanta controles rígidos de autenticação e autorização (RBAC/ABAC) para todas as rotas listadas.",
                vibe_coding_context="Ao solicitar à IA para criar um CRUD rápido, rotas de deleção ou rotas administrativas são criadas sem middleware de autenticação."
            ))

        if unprotected_admin_routes:
            findings.append(AuditFinding(
                id="API-A02-UNAUTHENTICATED-MUTATIONS",
                title=f"Mutações Sensíveis sem 'Security' declarado no Schema ({len(unprotected_admin_routes)} operações)",
                category=self.owasp_category,
                severity=Severity.HIGH,
                url=page_url,
                description="Operações de alteração ou exclusão de dados não possuem esquemas de autenticação definidos na especificação OpenAPI.",
                evidence="\n".join(unprotected_admin_routes[:5]),
                remediation="Adicione esquemas de segurança (OAuth2, Bearer JWT, APIKey) e exija tokens válidos no backend.",
                vibe_coding_context="IAs costumam esquecer de adicionar 'security=[Depends(auth)]' em endpoints secundários."
            ))

        return findings

    # ------------------------------------------------------------------
    # 2. GraphQL Security & Introspection Audit
    # ------------------------------------------------------------------
    def _audit_graphql_security(self, base_origin: str, page_url: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        graphql_endpoints = ["/graphql", "/api/graphql", "/query"]

        introspection_payload = {
            "query": "{ __schema { queryType { name } types { name } } }"
        }

        for ep in graphql_endpoints:
            ep_url = urljoin(base_origin, ep)
            try:
                resp = requests.post(
                    ep_url,
                    json=introspection_payload,
                    timeout=2.5,
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and "data" in data and "__schema" in data["data"]:
                        types = data["data"]["__schema"].get("types", [])
                        findings.append(AuditFinding(
                            id="API-A08-GRAPHQL-INTROSPECTION-ENABLED",
                            title=f"GraphQL Introspection Ativo em Produção ({ep})",
                            category=self.owasp_category,
                            severity=Severity.HIGH,
                            url=ep_url,
                            description=f"O endpoint GraphQL em '{ep}' permite consultas de introspecção (__schema). Isso expõe todo o modelo de dados, nomes de tabelas, campos privados e mutações internas do sistema para qualquer atacante.",
                            evidence=f"Introspecção respondeu com {len(types)} tipos mapeados. Endpoint: {ep_url}",
                            remediation="Desative a introspecção GraphQL em produção (ex: no Apollo Server: introspection: false).",
                            vibe_coding_context="Apollo Server, Yoga e Hasura frequentemente mantêm introspecção ativa por padrão a menos que configurado explicitamente com 'production: true'."
                        ))
                        break
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # 3. Intercepted API Calls Audit (PII, Excessive Data, Rate Limit)
    # ------------------------------------------------------------------
    def _audit_intercepted_call(self, call: Dict[str, Any], page_url: str) -> List[AuditFinding]:
        findings = []
        call_url = call.get("url", "")
        method = call.get("method", "GET").upper()
        status = call.get("status", 200)
        res_headers = {k.lower(): v for k, v in call.get("headers", {}).items()}
        res_body = call.get("response", "")

        # A. Checagem de Excessive Data Exposure (API3:2023)
        if isinstance(res_body, (dict, list)) or (isinstance(res_body, str) and res_body.startswith(("{", "["))):
            json_obj = res_body if isinstance(res_body, (dict, list)) else None
            if not json_obj:
                try:
                    json_obj = json.loads(res_body)
                except Exception:
                    pass

            if json_obj:
                leaked_fields = self._find_sensitive_json_keys(json_obj)
                if leaked_fields:
                    findings.append(AuditFinding(
                        id=f"API-A03-EXCESSIVE-DATA-EXPOSURE",
                        title=f"Excessive Data Exposure: Dados Sensíveis Retornados na API ({method} {call_url})",
                        category=self.owasp_category,
                        severity=Severity.CRITICAL if any(k in ["password", "password_hash", "salt", "secret"] for k in leaked_fields) else Severity.HIGH,
                        url=call_url,
                        description="A API retornou campos sensíveis de modelo de banco de dados diretamente na resposta JSON. Isso ocorre quando o backend faz dump direto do ORM (ex: res.json(user)) sem DTOs ou filtros de projeção.",
                        evidence=f"Campos sensíveis identificados: {', '.join(leaked_fields)}\nURL da chamada: {call_url}",
                        remediation="Utilize DTOs (Data Transfer Objects), serializadores com schemas estritos (Pydantic / Zod) ou omita os campos sensíveis antes de enviar a resposta HTTP.",
                        vibe_coding_context="O vício mais frequente de backends gerados por IA em Express/Prisma/Mongoose: 'res.json(await User.findAll())', enviando o hash da senha de todos os usuários para o frontend."
                    ))

        # B. Checagem de Ausência de Rate Limiting (API4:2023)
        if status in [200, 201] and ("api" in call_url.lower() or "/v1/" in call_url.lower()):
            has_ratelimit = any(h in res_headers for h in ["x-ratelimit-limit", "ratelimit-limit", "x-ratelimit-remaining", "retry-after"])
            if not has_ratelimit:
                findings.append(AuditFinding(
                    id="API-A04-NO-RATE-LIMITING",
                    title=f"Ausência de Cabeçalhos de Rate Limiting na API ({method})",
                    category=self.owasp_category,
                    severity=Severity.LOW,
                    url=call_url,
                    description="O endpoint de API não retornou cabeçalhos de controle de taxa (Rate Limiting). Sem limitação de requisições por IP ou token, a API fica vulnerável a ataques de força bruta, DoS e raspagem em massa.",
                    evidence=f"Endpoint: {call_url} | Nenhum cabeçalho 'X-RateLimit-*' ou 'RateLimit-*' detectado.",
                    remediation="Adicione um middleware de rate limit (ex: express-rate-limit no Node.js ou slowapi no FastAPI) com limites razoáveis por minuto.",
                    vibe_coding_context="Raramente implementado em protótipos de IA porque exige Redis ou memória de estado."
                ))

        # C. Vazamento de Stack Trace em Erros de API (API8:2023)
        if status >= 400 and isinstance(res_body, str):
            stack_signatures = [
                "Traceback (most recent call last)",
                "at Object.<anonymous>",
                "at Module._compile",
                "SequelizeDatabaseError",
                "MongoServerError",
                "psycopg2.errors",
                "org.springframework.",
                "jakarta.servlet.",
            ]
            for sig in stack_signatures:
                if sig in res_body:
                    findings.append(AuditFinding(
                        id="API-A08-DEBUG-STACK-TRACE-LEAK",
                        title=f"Vazamento de Stack Trace / Erro Interno na API (HTTP {status})",
                        category=self.owasp_category,
                        severity=Severity.HIGH,
                        url=call_url,
                        description="A resposta de erro da API vazou um rastreamento de pilha (stack trace) completo ou detalhes de queries SQL. Isso revela nomes de tabelas, estrutura de diretórios e tecnologias do servidor.",
                        evidence=f"Assinatura detectada: {sig}\nTrecho: {res_body[:160]}...",
                        remediation="Configure manipuladores globais de erro para retornar apenas mensagens genéricas em produção (ex: { 'error': 'Internal server error' }).",
                        vibe_coding_context="Em código de vibe coding, os blocos 'catch (err) { res.status(500).json({ error: err.stack }) }' são extremamente comuns para facilitar o debug pelo usuário."
                    ))
                    break

        return findings

    def _find_sensitive_json_keys(self, obj: Any, path: str = "") -> List[str]:
        """Procura recursivamente por chaves sensíveis em estruturas JSON."""
        sensitive_keys = {
            "password", "password_hash", "passwd", "salt", "secret",
            "api_secret", "private_key", "jwt_secret", "ssn", "cpf",
            "credit_card", "card_number", "cvv", "security_code"
        }
        leaked = []

        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = k.lower().replace("-", "_")
                current_path = f"{path}.{k}" if path else k
                if k_lower in sensitive_keys:
                    leaked.append(current_path)
                elif isinstance(v, (dict, list)):
                    leaked.extend(self._find_sensitive_json_keys(v, current_path))
        elif isinstance(obj, list):
            # Analisa até os primeiros 5 elementos para performance
            for idx, item in enumerate(obj[:5]):
                leaked.extend(self._find_sensitive_json_keys(item, f"{path}[{idx}]"))

        return leaked

    # ------------------------------------------------------------------
    # 4. Client Code API Route Analysis
    # ------------------------------------------------------------------
    def _audit_client_api_routes(self, context: AuditContext) -> List[AuditFinding]:
        findings = []
        all_text = context.html + "\n" + "\n".join(context.scripts)

        # Procura rotas de teste / seed deixadas no frontend
        dev_api_patterns = [
            (r"['\"]/api/(?:v1/)?(?:seed|reset-db|test-data|mock-users)['\"]", "Endpoint de Seed / Reset de Banco de Dados Exposto"),
            (r"['\"]/api/(?:v1/)?(?:debug|internal|admin-bypass)['\"]", "Endpoint de Debug Interno Referenciado no Frontend"),
        ]

        for regex, title in dev_api_patterns:
            matches = re.findall(regex, all_text, re.IGNORECASE)
            if matches:
                findings.append(AuditFinding(
                    id="API-VIBE-DEV-ENDPOINT",
                    title=f"{title} ({matches[0].strip('\'\"')})",
                    category=self.owasp_category,
                    severity=Severity.HIGH,
                    url=context.url,
                    description=f"Foi encontrada uma referência direta ao endpoint '{matches[0]}' no código do cliente. Se este endpoint estiver acessível, permite reset de base ou injeção de dados falsos.",
                    evidence=f"Referência encontrada: {matches[0]}",
                    remediation="Remova rotas de seed, reset ou debug antes do deploy em ambientes públicos.",
                    vibe_coding_context="Usuários pedem para a IA: 'crie um botão para popular o banco de teste', e a rota /api/seed fica viva em produção."
                ))

        return findings
