"""
Módulo de Auditoria: A08:2021 - Falhas de Integridade de Software e Dados
Verifica a ausência de Subresource Integrity (SRI) em scripts e estilos carregados de CDNs externas.
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class SoftwareIntegrityModule(BaseAuditModule):
    @property
    def module_id(self) -> str:
        return "mod_a08_software_integrity"

    @property
    def name(self) -> str:
        return "Integridade de Scripts & CDNs Externas (OWASP A08)"

    @property
    def description(self) -> str:
        return "Verifica a presença de Subresource Integrity (SRI) em bibliotecas e recursos carregados de provedores externos."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A08_INTEGRITY_FAILURES

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or not context.html or context.url.startswith("chrome://"):
            return findings

        parsed_origin = urlparse(context.url)
        current_host = parsed_origin.netloc.lower()

        try:
            soup = BeautifulSoup(context.html, "html.parser")

            # 1. Scripts externos sem SRI (Subresource Integrity)
            insecure_external_scripts = []
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                script_parsed = urlparse(src)
                script_host = script_parsed.netloc.lower()

                # Verifica se é de um domínio externo (CDN, etc.)
                if script_host and script_host != current_host:
                    integrity = script.get("integrity")
                    if not integrity:
                        insecure_external_scripts.append(src)

            if insecure_external_scripts:
                findings.append(AuditFinding(
                    id="SEC-A08-MISSING-SRI-SCRIPTS",
                    title=f"Scripts Externos Sem Subresource Integrity (SRI) ({len(insecure_external_scripts)} scripts)",
                    category=self.owasp_category,
                    severity=Severity.MEDIUM,
                    url=context.url,
                    description="A página carrega scripts JavaScript de servidores externos (CDNs) sem especificar o atributo 'integrity' (hash criptográfico do arquivo). Se a CDN for comprometida ou sofrer ataque de DNS/spoofing, código malicioso será executado diretamente na sua aplicação.",
                    evidence="Scripts externos sem integridade:\n" + "\n".join(insecure_external_scripts[:5]),
                    remediation="Adicione o atributo 'integrity' e 'crossorigin=\"anonymous\"'. Exemplo: <script src=\"https://cdn...\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>",
                    vibe_coding_context="Em vibe coding, os prompts pedem 'adicione Tailwind/Bootstrap/jQuery via CDN' e a IA gera tags simples sem os hashes SRI para encurtar a resposta."
                ))

            # 2. Folhas de estilo externas sem SRI
            insecure_external_css = []
            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href", "").strip()
                link_parsed = urlparse(href)
                link_host = link_parsed.netloc.lower()

                if link_host and link_host != current_host:
                    if not link.get("integrity"):
                        insecure_external_css.append(href)

            if insecure_external_css:
                findings.append(AuditFinding(
                    id="SEC-A08-MISSING-SRI-CSS",
                    title=f"Estilos CSS Externos Sem SRI ({len(insecure_external_css)} arquivos)",
                    category=self.owasp_category,
                    severity=Severity.LOW,
                    url=context.url,
                    description="Estilos CSS externos sem integridade podem ser adulterados para alterar a interface do usuário ou exfiltrar dados sensíveis via CSS injection.",
                    evidence="Estilos sem SRI:\n" + "\n".join(insecure_external_css[:3]),
                    remediation="Adicione o atributo 'integrity' e 'crossorigin' nas tags <link rel='stylesheet'>.",
                    vibe_coding_context="Geralmente omitido por praticidade durante a prototipagem rápida de interfaces por IA."
                ))

        except Exception:
            pass

        return findings
