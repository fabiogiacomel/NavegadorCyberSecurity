"""
Módulo de Auditoria: A06:2021 - Componentes Vulneráveis e Desatualizados (Vulnerable and Outdated Components)
Identifica bibliotecas JavaScript/CSS no cliente com vulnerabilidades públicas conhecidas (CVEs),
dependências carregadas de CDNs sem versionamento fixo (@latest) e exposição de Source Maps / manifestos.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class VulnerableComponentsModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # Catálogo de bibliotecas populares com versões mínimas seguras e CVEs associadas
    # Formato: lib_key -> (Nome Legível, Versão Mínima Segura (major, minor, patch), Severidade, CVE/Resumo)
    VULNERABLE_LIBRARIES_CATALOG: Dict[str, Tuple[str, Tuple[int, int, int], Severity, str]] = {
        "jquery": (
            "jQuery",
            (3, 5, 0),
            Severity.HIGH,
            "CVE-2020-11022 / CVE-2020-11023 (XSS em htmlPrefilter) e CVE-2019-11358 (Prototype Pollution)"
        ),
        "lodash": (
            "Lodash",
            (4, 17, 21),
            Severity.HIGH,
            "CVE-2021-23337 (Command Injection via template) e CVE-2020-8203 (Prototype Pollution)"
        ),
        "bootstrap": (
            "Bootstrap",
            (4, 3, 1),
            Severity.MEDIUM,
            "CVE-2019-8331 / CVE-2018-14040 (XSS em atributos data-template / data-target de Tooltips e Popovers)"
        ),
        "moment": (
            "Moment.js",
            (2, 29, 4),
            Severity.MEDIUM,
            "CVE-2022-31129 (ReDoS em preprocessRFC2822) e biblioteca marcada como legada"
        ),
        "handlebars": (
            "Handlebars.js",
            (4, 7, 7),
            Severity.HIGH,
            "CVE-2021-23369 / CVE-2021-23383 (Prototype Pollution & Remote Code Execution em templates)"
        ),
        "marked": (
            "Marked (Markdown Parser)",
            (4, 0, 10),
            Severity.MEDIUM,
            "CVE-2022-21680 / CVE-2022-21681 (ReDoS e potencial bypass de sanitização Markdown)"
        ),
        "dompurify": (
            "DOMPurify",
            (2, 4, 0),
            Severity.HIGH,
            "Bypasses de mXSS (Mutation XSS) em versões anteriores à 2.4.0"
        ),
        "axios": (
            "Axios",
            (1, 6, 0),
            Severity.MEDIUM,
            "CVE-2023-45857 (Vazamento acidental de XSRF-TOKEN em requisições cross-origin)"
        ),
        "angular": (
            "AngularJS (1.x EoL)",
            (2, 0, 0),
            Severity.HIGH,
            "AngularJS 1.x atingiu End-of-Life (EoL) em 2022 e possui múltiplos vetores de XSS/Sandbox Escape"
        ),
    }

    # Padrões para extrair (nome_biblioteca, string_versao) de URLs de scripts/links
    URL_LIB_VERSION_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("jquery", re.compile(r"jquery(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("lodash", re.compile(r"lodash(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("bootstrap", re.compile(r"bootstrap(?:\.js|\.min|\.bundle)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("moment", re.compile(r"moment(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("handlebars", re.compile(r"handlebars(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("marked", re.compile(r"marked(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("dompurify", re.compile(r"(?:dompurify|purify)(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("axios", re.compile(r"axios(?:\.js|\.min)?[/@-]v?(\d+\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
        ("angular", re.compile(r"angular(?:js)?(?:\.js|\.min)?[/@-]v?(1\.\d+\.\d+)(?:[./-]|$)", re.IGNORECASE)),
    ]

    # Padrões para identificar versões em comentários de cabeçalho ou variáveis inline no código JS
    INLINE_LIB_VERSION_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("jquery", re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
        ("lodash", re.compile(r"lodash(?:\.js)?\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
        ("bootstrap", re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
        ("handlebars", re.compile(r"Handlebars(?:\.js)?\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
        ("angular", re.compile(r"AngularJS\s+v?(1\.\d+\.\d+)", re.IGNORECASE)),
    ]

    # CDNs sem versão fixada (@latest ou script dinâmico direto)
    UNPINNED_CDN_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"https?://cdn\.tailwindcss\.com(?:/|\b)", re.IGNORECASE),
            "Tailwind CSS Play CDN (script de desenvolvimento sem versão fixa em produção)"
        ),
        (
            re.compile(r"https?://(?:unpkg\.com|cdn\.jsdelivr\.net|esm\.sh)/[^\s'\"`>]+@latest\b", re.IGNORECASE),
            "Dependência externa carregada com tag mutável '@latest'"
        ),
        (
            re.compile(
                r"https?://unpkg\.com/@?[a-z0-9_-]+(?:/[a-z0-9_-]+)?(?:\.js|/dist/[^\s'\"`>]+)?(?=[\s'\"`>])",
                re.IGNORECASE
            ),
            "Pacote unpkg.com importado sem especificação de versão (@x.y.z)"
        ),
    ]

    # Source maps e manifestos expostos
    SOURCEMAP_REGEX = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"`]+\.map)", re.IGNORECASE)
    MANIFEST_LINK_REGEX = re.compile(
        r"['\"`](/(?:package\.json|package-lock\.json|requirements\.txt|Pipfile\.lock|composer\.lock))['\"`]",
        re.IGNORECASE
    )

    @property
    def module_id(self) -> str:
        return "mod_a06_vuln_components"

    @property
    def name(self) -> str:
        return "Componentes Vulneráveis e Desatualizados (OWASP A06)"

    @property
    def description(self) -> str:
        return (
            "Detecta bibliotecas frontend desatualizadas com CVEs conhecidas, scripts de CDN com versão "
            "não fixada (@latest) e exposição de Source Maps ou manifestos de pacotes."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A06_VULN_COMPONENTS

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        resource_urls = self._collect_resource_urls(html_content, context.script_srcs or [])

        # 1. Verificação de bibliotecas com versões conhecidamente vulneráveis
        findings.extend(self._check_vulnerable_libraries(context.url, resource_urls, all_text))

        # 2. Dependências externas sem versionamento fixo (@latest ou Play CDN)
        findings.extend(self._check_unpinned_dependencies(context.url, resource_urls, all_text))

        # 3. Exposição de Source Maps ou arquivos de manifesto de dependências
        findings.extend(self._check_sourcemaps_and_manifests(context.url, all_text))

        return findings

    def _collect_resource_urls(self, html_content: str, script_srcs: List[str]) -> Set[str]:
        urls: Set[str] = set(script_srcs)
        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            for script in soup.find_all("script", src=True):
                urls.add(script["src"].strip())
            for link in soup.find_all("link", href=True):
                urls.add(link["href"].strip())
        return urls

    @staticmethod
    def _parse_semver(version_str: str) -> Optional[Tuple[int, int, int]]:
        parts = version_str.strip().split(".")
        if len(parts) < 3:
            return None
        try:
            return int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            return None

    def _is_version_vulnerable(self, lib_key: str, version_tuple: Tuple[int, int, int]) -> bool:
        if lib_key not in self.VULNERABLE_LIBRARIES_CATALOG:
            return False

        # Regra especial para Bootstrap 3.x (seguro a partir de 3.4.1 na branch 3.x, ou >= 4.3.1 na 4.x)
        if lib_key == "bootstrap" and version_tuple[0] == 3:
            return version_tuple < (3, 4, 1)

        min_safe = self.VULNERABLE_LIBRARIES_CATALOG[lib_key][1]
        return version_tuple < min_safe

    def _check_vulnerable_libraries(
        self, current_url: str, resource_urls: Set[str], all_text: str
    ) -> List[AuditFinding]:
        detected_libs: Dict[Tuple[str, str], str] = {}

        # A. Inspeção nas URLs de scripts e estilos carregados
        for res_url in resource_urls:
            for lib_key, regex in self.URL_LIB_VERSION_PATTERNS:
                match = regex.search(res_url)
                if match:
                    ver_str = match.group(1)
                    detected_libs[(lib_key, ver_str)] = res_url

        # B. Inspeção em banners/comentários no código JS/HTML
        for lib_key, regex in self.INLINE_LIB_VERSION_PATTERNS:
            match = regex.search(all_text)
            if match:
                ver_str = match.group(1)
                if (lib_key, ver_str) not in detected_libs:
                    detected_libs[(lib_key, ver_str)] = match.group(0)

        vulnerable_entries: List[str] = []
        highest_severity = Severity.MEDIUM

        for (lib_key, ver_str), source_evidence in detected_libs.items():
            ver_tuple = self._parse_semver(ver_str)
            if not ver_tuple:
                continue

            if self._is_version_vulnerable(lib_key, ver_tuple):
                lib_name, min_safe, sev, cve_info = self.VULNERABLE_LIBRARIES_CATALOG[lib_key]
                min_safe_str = ".".join(map(str, min_safe))
                vulnerable_entries.append(
                    f"{lib_name} v{ver_str} (mínimo seguro: v{min_safe_str}) — {cve_info} [Fonte: {source_evidence}]"
                )
                if sev == Severity.HIGH:
                    highest_severity = Severity.HIGH

        if not vulnerable_entries:
            return []

        return [AuditFinding(
            id="SEC-A06-VULNERABLE-JS-LIBRARY",
            title=f"Biblioteca(s) Frontend com Vulnerabilidades Conhecidas ({len(vulnerable_entries)} detectada(s))",
            category=self.owasp_category,
            severity=highest_severity,
            url=current_url,
            description=(
                "A aplicação carrega versões desatualizadas de bibliotecas JavaScript ou CSS que possuem "
                "vulnerabilidades de segurança públicas catalogadas (CVEs), como Cross-Site Scripting (XSS), "
                "Prototype Pollution ou Regular Expression Denial of Service (ReDoS)."
            ),
            evidence="Componentes vulneráveis:\n" + "\n".join(vulnerable_entries[:6]),
            remediation=(
                "Atualize imediatamente as bibliotecas para suas versões estáveis mais recentes e integre "
                "ferramentas de auditoria de dependências no pipeline CI/CD (ex.: 'npm audit', Dependabot ou Snyk)."
            ),
            vibe_coding_context=(
                "Modelos de IA foram treinados com milhões de exemplos antigos da web e frequentemente geram "
                "tags <script> apontando para jQuery 1.12/2.1, Bootstrap 3.3 ou Lodash antigo por inércia dos dados de treino."
            )
        )]

    def _check_unpinned_dependencies(
        self, current_url: str, resource_urls: Set[str], all_text: str
    ) -> List[AuditFinding]:
        unpinned_evidences: List[str] = []
        combined_targets = "\n".join(resource_urls) + "\n" + all_text

        for pattern, label in self.UNPINNED_CDN_PATTERNS:
            for match in pattern.finditer(combined_targets):
                matched_url = match.group(0)
                # Se for unpkg sem @version, verifica se realmente não possui @x.y.z
                if "unpkg.com" in matched_url.lower() and "@latest" not in matched_url.lower():
                    after_domain = matched_url.split("unpkg.com/", 1)[-1]
                    if re.search(r"@\d+\.\d+", after_domain):
                        continue
                unpinned_evidences.append(f"{matched_url} ({label})")

        unique_unpinned = list(dict.fromkeys(unpinned_evidences))
        if not unique_unpinned:
            return []

        return [AuditFinding(
            id="SEC-A06-UNPINNED-EXTERNAL-DEPENDENCY",
            title=f"Dependência Externa Sem Versão Fixada ou de Desenvolvimento ({len(unique_unpinned)} recurso(s))",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description=(
                "A página importa pacotes externos utilizando tags mutáveis ('@latest'), URLs sem versão explícita "
                "ou scripts JIT de desenvolvimento (como 'cdn.tailwindcss.com'). Isso expõe a aplicação a ataques "
                "de Supply Chain (caso uma nova versão comprometida seja publicada no registro NPM) e impede o uso "
                "de hashes Subresource Integrity (SRI)."
            ),
            evidence="Recursos sem versão fixa:\n" + "\n".join(unique_unpinned[:5]),
            remediation=(
                "Fixe sempre a versão exata da biblioteca (ex.: '@4.17.21'), adicione o hash 'integrity' (SRI) "
                "ou empacote as dependências localmente durante o passo de build (Vite/Webpack)."
            ),
            vibe_coding_context=(
                "Quase todo protótipo HTML gerado por LLMs inclui '<script src=\"https://cdn.tailwindcss.com\"></script>' "
                "ou 'https://unpkg.com/lucide@latest' para funcionar em um único arquivo sem bundler."
            )
        )]

    def _check_sourcemaps_and_manifests(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for match in self.SOURCEMAP_REGEX.findall(all_text):
            evidences.append(f"Source Map referenciado: {match}")

        for match in self.MANIFEST_LINK_REGEX.findall(all_text):
            evidences.append(f"Manifesto de dependências exposto: {match}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="SEC-A06-SOURCEMAP-OR-MANIFEST-EXPOSED",
            title="Exposição de Source Maps (.map) ou Manifesto de Dependências no Cliente",
            category=self.owasp_category,
            severity=Severity.LOW,
            url=current_url,
            description=(
                "Foram identificadas diretivas 'sourceMappingURL' ou referências diretas a arquivos de manifesto "
                "de pacotes (package.json, requirements.txt). Source maps públicos permitem reconstruir integralmente "
                "o código-fonte original TypeScript/React, revelando comentários internos, rotas ocultas e versões "
                "exatas de todas as bibliotecas."
            ),
            evidence="Referências encontradas: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "Desative a geração de source maps públicos no build de produção (ex.: 'productionBrowserSourceMaps: false' "
                "no Next.js ou 'build.sourcemap: false' no Vite) e bloqueie o acesso a arquivos '.map' e 'package.json' no servidor web."
            ),
            vibe_coding_context=(
                "Configurações de build geradas rapidamente costumam manter source maps ativos em produção para facilitar "
                "a leitura de erros no console."
            )
        )]
