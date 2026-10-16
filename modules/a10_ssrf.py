"""
Módulo de Auditoria: A10:2021 - Server-Side Request Forgery (SSRF)
Identifica vetores de SSRF em parâmetros de URL, formulários de Webhooks/Importação,
endpoints de Proxy/Fetch remoto no cliente e vazamento de endereços internos (RFC 1918 / Cloud Metadata IMDS).
"""

import re
from typing import List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class ServerSideRequestForgeryModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # Parâmetros tipicamente consumidos pelo backend para buscar recursos externos (SSRF)
    SSRF_PARAM_NAMES: Set[str] = {
        "webhook", "webhook_url", "webhookurl", "callback_url", "callbackurl",
        "proxy", "proxy_url", "proxyurl", "fetch", "fetch_url", "fetchurl",
        "source_url", "sourceurl", "import_url", "importurl", "pdf_url", "pdfurl",
        "image_url", "imageurl", "avatar_url", "avatarurl", "media_url",
        "feed", "feed_url", "rss", "rss_url", "xml_url", "wsdl",
        "target_host", "remote_url", "endpoint_url", "dest_url"
    }

    # Rotas de backend que atuam como buscadores/proxies de URL
    SSRF_ROUTE_KEYWORDS: Tuple[str, ...] = (
        "/proxy", "/fetch", "/scrape", "/preview", "/webhook",
        "/import-url", "/url-preview", "/link-preview", "/pdf-from-url", "/avatar-from-url"
    )

    # Padrões em JavaScript de chamadas de API que instruem o servidor a requisitar uma URL arbitrária
    CLIENT_SSRF_JS_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"['\"`](/api/(?:v\d+/)?(?:proxy|fetch|scrape|preview|webhook|import|pdf)[^'\"`]*[?&](?:url|uri|target|source|endpoint)=[^'\"`]+)['\"`]",
                re.IGNORECASE
            ),
            "Endpoint de API recebendo URL arbitrária via Query String"
        ),
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\b(?:webhookUrl|webhook_url|proxyUrl|proxy_url|fetchUrl|fetch_url|targetUrl|target_url|importUrl|import_url| callbackUrl)\s*:",
                re.IGNORECASE
            ),
            "Payload JSON enviando URL de destino para processamento no servidor"
        ),
    ]

    # Endereços de Cloud Metadata (AWS/GCP/Azure/Alibaba IMDS) — Risco Crítico
    CLOUD_METADATA_REGEX = re.compile(
        r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)",
        re.IGNORECASE
    )

    # Endereços de rede interna privada (RFC 1918, Docker interno, Kubernetes, domínios .internal/.corp)
    INTERNAL_INFRA_REGEX = re.compile(
        r"https?://(?:"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
        r"host\.docker\.internal|"
        r"kubernetes\.default\.svc|"
        r"[\w.-]+\.(?:internal|corp|lan|intranet)"
        r")(?::\d+)?(?:/[^\s'\"`<>]*)?",
        re.IGNORECASE
    )

    @property
    def module_id(self) -> str:
        return "mod_a10_ssrf"

    @property
    def name(self) -> str:
        return "Server-Side Request Forgery — SSRF (OWASP A10)"

    @property
    def description(self) -> str:
        return (
            "Identifica vetores de SSRF em parâmetros de proxy/webhook/importação, chamadas de fetch remoto "
            "pelo servidor e exposição de endereços internos ou Cloud Metadata (169.254.169.254)."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A10_SSRF

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # 1. Parâmetros de URL e Inputs de Formulário que aceitam URLs para processamento no backend
        findings.extend(self._check_ssrf_parameters_and_forms(context.url, soup))

        # 2. Chamadas de API/Proxy no código cliente que delegam busca de URL ao servidor
        findings.extend(self._check_client_remote_fetch_proxies(context.url, all_text, context.api_calls or []))

        # 3. Referências a Cloud Metadata (IMDS) ou infraestrutura de rede privada (RFC 1918)
        findings.extend(self._check_internal_infra_and_metadata(context.url, all_text))

        return findings

    def _check_ssrf_parameters_and_forms(
        self, current_url: str, soup: Optional[BeautifulSoup]
    ) -> List[AuditFinding]:
        evidences: List[str] = []

        # A. Verifica URL atual e links <a href> na página
        candidate_urls = {current_url}
        if soup:
            for a_tag in soup.find_all("a", href=True):
                candidate_urls.add(a_tag["href"])

        for target in candidate_urls:
            try:
                parsed = urlparse(target)
                path_lower = parsed.path.lower()
                query_params = parse_qs(parsed.query)
            except ValueError:
                continue

            is_ssrf_route = any(kw in path_lower for kw in self.SSRF_ROUTE_KEYWORDS)

            for raw_param, values in query_params.items():
                param_clean = raw_param.lower().replace("-", "_")
                for val in values:
                    decoded_val = unquote(val).strip()
                    if param_clean in self.SSRF_PARAM_NAMES:
                        evidences.append(f"Parâmetro de SSRF na URL: {raw_param}={decoded_val[:50]}")
                    elif is_ssrf_route and decoded_val.lower().startswith(("http://", "https://", "file://", "gopher://")):
                        evidences.append(f"Rota de Proxy/Fetch com URL: {parsed.path}?{raw_param}={decoded_val[:50]}")

        # B. Verifica campos de formulário que solicitam URLs de Webhook, Importação ou Avatar remoto
        if soup:
            for inp in soup.find_all("input"):
                name = (inp.get("name") or inp.get("id") or "").strip()
                name_clean = name.lower().replace("-", "_")
                if name_clean in self.SSRF_PARAM_NAMES:
                    evidences.append(f"Campo de formulário SSRF: <input name='{name}'>")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A10-POTENTIAL-SSRF-PARAM",
            title="Vetor Potencial de SSRF em Parâmetro ou Campo de Busca Remota",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A aplicação expõe parâmetros ou campos de formulário destinados a fornecer URLs para que o "
                "servidor busque recursos remotos (como Webhooks, proxies de CORS, geração de PDF, preview de links "
                "ou importação de imagens por URL). Se o backend requisitar a URL informada sem filtrar o endereço "
                "IP resolvido, um atacante pode forçar o servidor a acessar serviços internos (Redis, bancos de dados) "
                "ou roubar credenciais de nuvem via Instance Metadata Service (169.254.169.254)."
            ),
            evidence="Vetores identificados: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "1. Valide o esquema (permita apenas 'https://') e compare o domínio contra uma allowlist estrita.\n"
                "2. Resolva o DNS da URL no backend e bloqueie conexões para faixas de IP privadas/reservadas "
                "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 e 169.254.169.254).\n"
                "3. Desative redirecionamentos HTTP automáticos ('allow_redirects=False') no cliente HTTP do servidor."
            ),
            vibe_coding_context=(
                "Para contornar erros de CORS no navegador ou gerar 'link previews', desenvolvedores pedem à IA "
                "para criar uma rota '/api/proxy?url=...' que faz 'requests.get(url)' sem nenhuma validação de destino."
            )
        )]

    def _check_client_remote_fetch_proxies(
        self, current_url: str, all_text: str, api_calls: List[dict]
    ) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.CLIENT_SSRF_JS_PATTERNS:
            for match in pattern.finditer(all_text):
                snippet = " ".join(match.group(0).strip().split())
                if len(snippet) > 75:
                    snippet = snippet[:72] + "..."
                evidences.append(f"{label}: {snippet}")

        for call in api_calls:
            call_url = call.get("url", "")
            if any(kw in call_url.lower() for kw in self.SSRF_ROUTE_KEYWORDS):
                evidences.append(f"Chamada interceptada para endpoint de busca remota: {call_url}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A10-CLIENT-REMOTE-FETCH-PROXY",
            title="Endpoint de Proxy / Fetch Remoto Detectado no Código Cliente",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "O código JavaScript do cliente realiza chamadas para rotas de proxy, scraping, webhook ou "
                "busca de URL remota no backend. Endpoints que atuam como proxies abertos no servidor são "
                "o principal ponto de entrada para exploração de Server-Side Request Forgery (SSRF)."
            ),
            evidence="Ocorrências: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "Substitua proxies genéricos ('/api/proxy?url=...') por integrações específicas com domínios "
                "fixos no backend e isole o serviço de busca de URLs (egress proxy) fora da VPC interna."
            ),
            vibe_coding_context=(
                "Quando uma chamada 'fetch()' falha por CORS no frontend, a sugestão número 1 de assistentes de IA "
                "é criar um endpoint '/api/proxy?url=' no Next.js/Express/FastAPI que repassa qualquer URL."
            )
        )]

    def _check_internal_infra_and_metadata(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []
        has_cloud_metadata = False

        for match in self.CLOUD_METADATA_REGEX.finditer(all_text):
            has_cloud_metadata = True
            evidences.append(f"Endereço de Cloud Metadata (IMDS): {match.group(0)}")

        for match in self.INTERNAL_INFRA_REGEX.finditer(all_text):
            evidences.append(f"Host/IP de rede interna privada: {match.group(0)}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A10-INTERNAL-INFRA-REFERENCE",
            title="Exposição de Endereço de Rede Interna (RFC 1918) ou Cloud Metadata (IMDS)",
            category=self.owasp_category,
            severity=Severity.CRITICAL if has_cloud_metadata else Severity.MEDIUM,
            url=current_url,
            description=(
                "O código da página contém referências diretas a endereços IP de redes privadas (10.x, 192.168.x, "
                "172.16-31.x, host.docker.internal) ou ao serviço de metadados de nuvem (169.254.169.254). "
                "Isso revela a topologia interna da infraestrutura e facilita o mapeamento de alvos para ataques SSRF."
            ),
            evidence="Endereços internos encontrados: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "1. Remova URLs de microsserviços internos e IPs privados do bundle frontend.\n"
                "2. Em ambientes AWS/GCP/Azure, exija IMDSv2 (baseado em token de sessão via PUT) e bloqueie "
                "o acesso ao IP 169.254.169.254 a partir de containers de aplicação."
            ),
            vibe_coding_context=(
                "Configurações de Docker Compose ou variáveis '.env' de rede interna copiadas pela IA para variáveis "
                "NEXT_PUBLIC_* ou VITE_* acabam vazando IPs internos da VPC para o navegador."
            )
        )]
