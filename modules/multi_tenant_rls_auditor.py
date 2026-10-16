"""
Módulo Especializado: Isolamento Multi-Tenant, BOLA Avançado & Auditoria de Row-Level Security (RLS)
Baseado nas melhores práticas de isolamento de dados em arquiteturas SaaS, PostgreSQL RLS e Supabase/PostgREST:
- Detecção de manipulação de tenant_id / organization_id enviado pelo cliente (URL, Headers X-Tenant-ID, Storage, JSON)
- Detecção de bypass crítico de RLS por exposição de chave JWT 'service_role' do Supabase no frontend
- Auditoria de consultas diretas ao banco via cliente (supabase.from().select() / PostgREST /rest/v1/)
- Detecção ativa de vazamento Cross-Tenant (múltiplos tenant_id/owner_id distintos retornados na mesma resposta de API)
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class MultiTenantRlsAuditorModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # Parâmetros de identificação de inquilino (tenant) que nunca devem ser confiados sem validação contra o token da sessão
    TENANT_IDENTIFIER_KEYS: Set[str] = {
        "tenant_id", "tenantid", "org_id", "orgid", "organization_id", "organizationid",
        "workspace_id", "workspaceid", "company_id", "companyid", "empresa_id", "empresaid"
    }

    # Padrões no código cliente que enviam o tenant_id manipulável via Header, Query ou Body
    CLIENT_TENANT_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"['\"`]x-(?:tenant|organization|org|workspace|company)-id['\"`]\s*:", re.IGNORECASE),
            "Cabeçalho HTTP 'X-Tenant-ID' / 'X-Organization-ID' controlado pelo cliente"
        ),
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\b(?:tenant_?id|organization_?id|org_?id|workspace_?id|empresa_?id)\s*:",
                re.IGNORECASE
            ),
            "Envio de 'tenant_id' / 'organization_id' diretamente no payload JSON do cliente"
        ),
        (
            re.compile(
                r"['\"`]/(api|tenants|empresas|organizations|workspaces)/\$\{[^}]+\}/(?:orders|pedidos|users|invoices|faturas|documentos)",
                re.IGNORECASE
            ),
            "Rota multi-tenant parametrizada pelo cliente (Risco de Cross-Tenant IDOR)"
        ),
    ]

    # Chamadas diretas do SDK Supabase / PostgREST no navegador
    SUPABASE_DIRECT_QUERY_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"\bsupabase\s*\.\s*from\s*\(\s*['\"`]([^'\"`]+)['\"`]\s*\)\s*\.\s*(select|delete|update|insert|upsert)\s*\(",
                re.IGNORECASE
            ),
            "Query direta Supabase no cliente"
        ),
        (
            re.compile(r"https?://[a-z0-9-]+\.supabase\.co/rest/v1/([a-z0-9_-]+)", re.IGNORECASE),
            "Endpoint PostgREST (/rest/v1/) acessado diretamente pelo navegador"
        ),
    ]

    # Regex para localizar tokens JWT no código/storage
    JWT_FINDER_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{8,}\b")

    @property
    def module_id(self) -> str:
        return "mod_multi_tenant_rls"

    @property
    def name(self) -> str:
        return "Isolamento Multi-Tenant, BOLA & Supabase RLS"

    @property
    def description(self) -> str:
        return (
            "Audita isolamento de inquilinos (Multi-Tenancy), manipulação de tenant_id pelo cliente, "
            "exposição de chaves 'service_role' que ignoram RLS e vazamentos Cross-Tenant em respostas de API."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.MULTI_TENANT_RLS

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        storage_content = json.dumps(context.local_storage or {}) + "\n" + json.dumps(context.session_storage or {})
        all_text = f"{html_content}\n{scripts_content}\n{storage_content}"

        # 1. Exposição de JWT com role 'service_role' ou 'postgres' (Bypass Total de RLS)
        findings.extend(self._check_service_role_rls_bypass(context.url, all_text))

        # 2. Manipulação de tenant_id / organization_id pelo cliente (URL, Storage, Headers, Body)
        findings.extend(self._check_client_supplied_tenant_id(context, all_text))

        # 3. Queries diretas do cliente ao banco (Supabase / PostgREST)
        findings.extend(self._check_direct_db_queries(context.url, all_text))

        # 4. Detecção de Vazamento Cross-Tenant real nas respostas de API interceptadas
        if context.api_calls:
            findings.extend(self._check_cross_tenant_api_leaks(context.url, context.api_calls))

        return findings

    @staticmethod
    def _decode_jwt_payload(payload_b64: str) -> Optional[Dict[str, Any]]:
        try:
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            data = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def _check_service_role_rls_bypass(self, current_url: str, all_text: str) -> List[AuditFinding]:
        bypass_evidences: List[str] = []

        # Verifica variável explícita SUPABASE_SERVICE_ROLE_KEY
        if re.search(r"SUPABASE_SERVICE_ROLE_KEY|service_role_key", all_text, re.IGNORECASE):
            bypass_evidences.append("Referência explícita a 'SUPABASE_SERVICE_ROLE_KEY' no cliente")

        # Decodifica o payload de todos os JWTs encontrados para inspecionar a claim 'role'
        for match in self.JWT_FINDER_REGEX.finditer(all_text):
            full_jwt = match.group(0)
            payload_b64 = match.group(1)
            claims = self._decode_jwt_payload(payload_b64)
            if not claims:
                continue

            role_claim = str(claims.get("role", "")).lower()
            if role_claim in ("service_role", "postgres", "supabase_admin"):
                masked_jwt = f"{full_jwt[:14]}...{full_jwt[-8:]}"
                bypass_evidences.append(f"JWT com claim '{{\"role\": \"{role_claim}\"}}' ({masked_jwt})")

        unique_evidences = list(dict.fromkeys(bypass_evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="RLS-02-SUPABASE-SERVICE-ROLE-BYPASS",
            title="Bypass Crítico de Row-Level Security (RLS): Chave 'service_role' Exposta no Cliente",
            category=self.owasp_category,
            severity=Severity.CRITICAL,
            url=current_url,
            description=(
                "Foi detectado um token JWT administrativo ('role: service_role' ou 'postgres') exposto no código "
                "ou armazenamento do navegador. No Supabase/PostgreSQL, a chave 'service_role' possui o privilégio "
                "BYPASSRLS, ignorando 100% das políticas de Row-Level Security. Qualquer visitante pode ler, alterar "
                "ou apagar todos os registros de todos os tenants do banco de dados."
            ),
            evidence="Credenciais com bypass de RLS: " + " | ".join(unique_evidences[:4]),
            remediation=(
                "1. Revogue imediatamente a chave 'service_role' comprometida no painel do banco/Supabase.\n"
                "2. No frontend, utilize exclusivamente a chave pública 'anon' combinada com autenticação de usuário.\n"
                "3. Habilite RLS em todas as tabelas ('ALTER TABLE nome ENABLE ROW LEVEL SECURITY; ALTER TABLE nome FORCE ROW LEVEL SECURITY;')."
            ),
            vibe_coding_context=(
                "Quando uma query falha no frontend por bloqueio de RLS ('new row violates row-level security policy'), "
                "muitos desenvolvedores e assistentes de IA trocam a chave 'anon' pela 'service_role' no '.env' público "
                "(NEXT_PUBLIC_ / VITE_) para 'fazer funcionar rápido'."
            )
        )]

    def _check_client_supplied_tenant_id(self, context: AuditContext, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        # A. Verifica parâmetros de query na URL atual
        try:
            parsed = urlparse(context.url)
            for k, vals in parse_qs(parsed.query).items():
                if k.lower().replace("-", "_") in self.TENANT_IDENTIFIER_KEYS:
                    evidences.append(f"Query String: {k}={vals[0]}")
        except ValueError:
            pass

        # B. Verifica chaves soltas de tenant_id no localStorage/sessionStorage
        for store_name, store_dict in [("localStorage", context.local_storage), ("sessionStorage", context.session_storage)]:
            if isinstance(store_dict, dict):
                for k, v in store_dict.items():
                    if k.lower().replace("-", "_") in self.TENANT_IDENTIFIER_KEYS:
                        evidences.append(f"{store_name}['{k}'] = '{str(v)[:30]}'")

        # C. Verifica padrões de código enviando X-Tenant-ID ou tenant_id no JSON
        for pattern, label in self.CLIENT_TENANT_INJECTION_PATTERNS:
            match = pattern.search(all_text)
            if match:
                snippet = " ".join(match.group(0).strip().split())
                evidences.append(f"{label}: {snippet[:65]}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="RLS-01-CLIENT-SUPPLIED-TENANT-ID",
            title="Vetor de Quebra de Isolamento Multi-Tenant (tenant_id Controlado pelo Cliente)",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=context.url,
            description=(
                "A aplicação armazena ou transmite o identificador da organização/inquilino ('tenant_id', 'org_id', "
                "'X-Tenant-ID') diretamente a partir de parâmetros controlados pelo cliente. Em arquiteturas Multi-Tenant, "
                "se o backend filtrar consultas usando o 'tenant_id' enviado no payload/header sem validar se o usuário "
                "autenticado realmente pertence àquela organização, um usuário da Empresa A poderá acessar ou modificar "
                "dados confidenciais da Empresa B."
            ),
            evidence="Vetores Multi-Tenant identificados: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "1. Extraia o 'tenant_id' exclusivamente das claims assinadas do token de sessão (JWT) no backend.\n"
                "2. Implemente Row-Level Security (RLS) no PostgreSQL vinculando a sessão da transação: "
                "\"SET LOCAL app.current_tenant_id = :tenant_id\" e crie políticas com "
                "\"USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)\"."
            ),
            vibe_coding_context=(
                "Em sistemas SaaS gerados por IA, é comum salvar 'tenant_id' no localStorage e enviá-lo no header "
                "'X-Tenant-ID' ou '?tenant_id=', aplicando RBAC apenas no papel (ex: GERENTE) sem validar o isolamento do tenant."
            )
        )]

    def _check_direct_db_queries(self, current_url: str, all_text: str) -> List[AuditFinding]:
        queried_tables: List[str] = []

        for pattern, label in self.SUPABASE_DIRECT_QUERY_PATTERNS:
            for match in pattern.finditer(all_text):
                table_name = match.group(1)
                op = match.group(2).upper() if match.lastindex and match.lastindex >= 2 else "REST"
                queried_tables.append(f"Tabela '{table_name}' ({op}) — {label}")

        unique_tables = list(dict.fromkeys(queried_tables))
        if not unique_tables:
            return []

        return [AuditFinding(
            id="RLS-03-DIRECT-DB-QUERY-EXPOSURE",
            title=f"Consultas Diretas do Navegador ao Banco de Dados ({len(unique_tables)} tabela(s) exposta(s))",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "O código frontend realiza consultas diretas a tabelas do banco de dados via PostgREST/Supabase SDK "
                "('supabase.from(...).select/update/delete'). Nessa arquitetura, toda a segurança depende 100% de "
                "políticas Row-Level Security (RLS) perfeitamente configuradas no banco para cada operação (SELECT, "
                "INSERT, UPDATE, DELETE). Qualquer tabela criada sem RLS ativo expõe toda a base publicamente."
            ),
            evidence="Tabelas acessadas diretamente pelo cliente: " + " | ".join(unique_tables[:6]),
            remediation=(
                "1. Audite o catálogo do PostgreSQL ('pg_tables' / 'pg_policies') garantindo que 100% das tabelas "
                "possuam 'relrowsecurity = true' e políticas tanto com cláusula 'USING' quanto 'WITH CHECK'.\n"
                "2. Adicione um hook de pre-commit e meta-teste no CI para bloquear migrações (Alembic/Supabase) "
                "que criem tabelas sem 'ENABLE ROW LEVEL SECURITY'."
            ),
            vibe_coding_context=(
                "Plataformas como Lovable, Bolt e v0 conectam o React diretamente ao Supabase no cliente. "
                "Muitas vezes as tabelas são criadas no SQL Editor sem ativar o RLS ou com políticas 'USING (true)'."
            )
        )]

    def _check_cross_tenant_api_leaks(self, current_url: str, api_calls: List[Dict[str, Any]]) -> List[AuditFinding]:
        leaks: List[str] = []

        for call in api_calls:
            call_url = call.get("url", "")
            res_body = call.get("response", "")
            if not res_body:
                continue

            data = res_body if isinstance(res_body, list) else None
            if not data and isinstance(res_body, str) and res_body.strip().startswith("["):
                try:
                    parsed = json.loads(res_body)
                    if isinstance(parsed, list):
                        data = parsed
                except Exception:
                    continue

            if not data or len(data) < 2:
                continue

            # Verifica se uma lista de objetos JSON retornada pela API mistura múltiplos tenant_id distintos
            for tenant_key in ("tenant_id", "tenantId", "organization_id", "organizationId", "empresa_id"):
                distinct_tenants = {
                    str(item.get(tenant_key))
                    for item in data
                    if isinstance(item, dict) and item.get(tenant_key) is not None
                }
                if len(distinct_tenants) > 1:
                    sample_ids = ", ".join(list(distinct_tenants)[:3])
                    leaks.append(
                        f"Endpoint {call_url} retornou registros de {len(distinct_tenants)} tenants distintos "
                        f"no campo '{tenant_key}' (ex: {sample_ids})"
                    )

        if not leaks:
            return []

        return [AuditFinding(
            id="RLS-04-CROSS-TENANT-DATA-LEAK",
            title="Vazamento Cross-Tenant Confirmado: API Retornou Dados de Múltiplos Inquilinos",
            category=self.owasp_category,
            severity=Severity.CRITICAL,
            url=current_url,
            description=(
                "Uma chamada de API interceptada retornou uma coleção de registros pertencentes a múltiplos "
                "'tenant_id' / 'organization_id' diferentes na mesma resposta. Isso comprova uma falha grave "
                "de isolamento Multi-Tenant (ausência de filtro WHERE tenant_id ou política RLS inativa)."
            ),
            evidence="Vazamentos detectados: " + " | ".join(leaks[:4]),
            remediation=(
                "Isole imediatamente as consultas pelo 'tenant_id' da sessão autenticada e ative Row-Level Security "
                "(RLS) forçado no banco de dados ('ALTER TABLE ... FORCE ROW LEVEL SECURITY')."
            ),
            vibe_coding_context=(
                "Ocorre quando o backend executa 'db.query(Model).all()' ou quando uma tabela do Supabase está "
                "com RLS desativado ou usando a política permissiva 'ENABLE READ ACCESS FOR ALL USERS'."
            )
        )]
