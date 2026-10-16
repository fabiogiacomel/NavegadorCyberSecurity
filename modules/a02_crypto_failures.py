"""
Módulo de Auditoria: A02:2021 - Falhas Criptográficas (Cryptographic Failures)
Verifica uso de transporte inseguro (HTTP/WS puro), Mixed Content (Ativo e Passivo),
transmissão insegura de credenciais/formulários e práticas criptográficas fracas no cliente.
"""

import re
from typing import List, Set, Tuple, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class CryptographicFailuresModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")
    LOCALHOST_HOSTS: Set[str] = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

    # Padrões de Mixed Content ou transporte inseguro dentro do código JS
    INSECURE_JS_TRANSPORT_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"\b(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest)\s*\(\s*['\"`](http://[^'\"`]+)['\"`]", re.IGNORECASE),
            "Chamada de API via HTTP em Script"
        ),
        (
            re.compile(r"new\s+WebSocket\s*\(\s*['\"`](ws://[^'\"`]+)['\"`]", re.IGNORECASE),
            "WebSocket não criptografado (ws://)"
        ),
    ]

    # Padrões de falhas criptográficas clássicas no cliente (Vibe Coding)
    WEAK_CRYPTO_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(r"\b(?:CryptoJS|crypto)\.(?:MD5|SHA1|DES|RC4)\s*\(", re.IGNORECASE),
            "Algoritmo criptográfico obsoleto/quebrado (MD5/SHA1/DES/RC4)"
        ),
        (
            re.compile(r"\bbtoa\s*\(\s*[^)]*(?:password|senha|secret|token|pin|cvv)[^)]*\)", re.IGNORECASE),
            "Uso de Base64 (btoa) como pseudo-criptografia para dado sensível"
        ),
        (
            re.compile(r"(?:token|secret|key|salt|nonce|otp|password|id_?sessao)\s*[:=]\s*[^;\n]*Math\.random\s*\(\s*\)", re.IGNORECASE),
            "Geração de valor sensível com PRNG inseguro (Math.random)"
        ),
        (
            re.compile(r"CryptoJS\.AES\.(?:encrypt|decrypt)\s*\([^,]+,\s*['\"`][^'\"`]{3,}['\"`]", re.IGNORECASE),
            "Chave simétrica AES hardcoded diretamente no código cliente"
        ),
        (
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "Chave privada exposta no código cliente"
        ),
    ]

    @property
    def module_id(self) -> str:
        return "mod_a02_crypto_failures"

    @property
    def name(self) -> str:
        return "Criptografia, Transporte & Mixed Content (OWASP A02)"

    @property
    def description(self) -> str:
        return "Audita conexões sem TLS (HTTP/WS), Mixed Content, transmissão insegura de senhas e falhas criptográficas no cliente."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A02_CRYPTO

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        parsed_url = urlparse(context.url)
        scheme = parsed_url.scheme.lower()
        hostname = (parsed_url.hostname or "").lower()

        is_https = scheme == "https"
        is_localhost = self._is_localhost(hostname)

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        soup = BeautifulSoup(html_content, "html.parser") if html_content else None

        # 1. Página acessada via HTTP não seguro (fora de localhost)
        if not is_https and not is_localhost:
            findings.append(self._build_unencrypted_http_finding(context.url))

        # 2. Auditoria de Campos de Senha e Formulários Inseguros (tanto em HTTP quanto em HTTPS)
        if soup:
            findings.extend(self._check_insecure_forms_and_passwords(context.url, soup, is_https, is_localhost))

        # 3. Mixed Content (Ativo, Passivo e WebSockets em páginas HTTPS)
        if is_https:
            findings.extend(self._check_mixed_content(context.url, soup, all_text))

        # 4. Práticas Criptográficas Fracas no Código Cliente (JS/HTML)
        findings.extend(self._check_weak_client_crypto(context.url, all_text))

        return findings

    def _is_localhost(self, hostname: str) -> bool:
        """Verifica de forma estrita se o host é um endereço de loopback local."""
        return hostname in self.LOCALHOST_HOSTS or hostname.endswith(".localhost")

    def _is_insecure_external_url(self, target_url: str) -> bool:
        """Retorna True se a URL usar http:// ou ws:// apontando para fora de localhost."""
        target_clean = target_url.strip()
        if not target_clean.lower().startswith(("http://", "ws://")):
            return False
        try:
            parsed = urlparse(target_clean)
            host = (parsed.hostname or "").lower()
            return not self._is_localhost(host)
        except ValueError:
            return True

    def _build_unencrypted_http_finding(self, current_url: str) -> AuditFinding:
        return AuditFinding(
            id="SEC-A02-UNENCRYPTED-HTTP",
            title="Comunicação Web Não Criptografada (HTTP Puro)",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A aplicação está sendo servida via protocolo HTTP simples sem TLS/HTTPS. "
                "Todo o tráfego, incluindo cookies de sessão, tokens e dados de formulários, "
                "pode ser interceptado ou adulterado em trânsito (Man-In-The-Middle)."
            ),
            evidence=f"Protocolo inseguro em uso: {current_url}",
            remediation=(
                "Configure um certificado TLS válido (ex.: Let's Encrypt), redirecione todo o tráfego "
                "HTTP para HTTPS (status 301/308) e adicione o cabeçalho Strict-Transport-Security (HSTS)."
            ),
            vibe_coding_context="Ambientes de deploy rápido em VPS ou containers expostos diretamente por IP/porta sem proxy reverso TLS deixam a aplicação vulnerável."
        )

    def _check_insecure_forms_and_passwords(
        self, current_url: str, soup: BeautifulSoup, is_https: bool, is_localhost: bool
    ) -> List[AuditFinding]:
        findings: List[AuditFinding] = []

        # Busca case-insensitive por <input type="password">
        password_inputs = soup.find_all(
            "input",
            attrs={"type": re.compile(r"^password$", re.IGNORECASE)}
        )

        # Caso A: Campo de senha servido em página HTTP (fora de localhost)
        if password_inputs and not is_https and not is_localhost:
            findings.append(AuditFinding(
                id="SEC-A02-PASSWORD-OVER-HTTP",
                title="Campo de Senha Servido em Página HTTP Não Criptografada",
                category=self.owasp_category,
                severity=Severity.CRITICAL,
                url=current_url,
                description=(
                    "A página contém campos de senha (<input type='password'>), mas é servida via HTTP puro. "
                    "Credenciais digitadas podem ser capturadas em texto claro na rede e a página está sujeita "
                    "à injeção de keyloggers via rede."
                ),
                evidence=f"Detectados {len(password_inputs)} campo(s) de senha em contexto HTTP.",
                remediation="Sirva todas as páginas de autenticação exclusivamente sob HTTPS com HSTS habilitado.",
                vibe_coding_context="Telas de login geradas para ambiente local publicadas em produção sem configuração de SSL no proxy reverso."
            ))

        # Caso B: Formulário submetendo dados para endpoint HTTP (mesmo se a página atual for HTTPS)
        insecure_forms: List[str] = []
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if self._is_insecure_external_url(action):
                has_pwd = bool(form.find("input", attrs={"type": re.compile(r"^password$", re.IGNORECASE)}))
                label = "com campo de senha" if has_pwd else "geral"
                insecure_forms.append(f"<form action='{action}'> ({label})")

        if insecure_forms:
            findings.append(AuditFinding(
                id="SEC-A02-INSECURE-FORM-ACTION",
                title="Formulário Submetendo Dados para Endpoint HTTP Inseguro",
                category=self.owasp_category,
                severity=Severity.CRITICAL if password_inputs else Severity.HIGH,
                url=current_url,
                description=(
                    "Um ou mais formulários da página possuem o atributo 'action' apontando explicitamente "
                    "para um endereço 'http://'. Os dados submetidos pelo usuário serão transmitidos sem criptografia."
                ),
                evidence="Formulários inseguros: " + ", ".join(insecure_forms[:5]),
                remediation="Altere o atributo 'action' dos formulários para utilizar caminhos relativos ou 'https://'.",
                vibe_coding_context="Ao integrar o frontend com um backend separado, a IA frequentemente fixa a URL absoluta com 'http://' no atributo action ou na variável de ambiente da API."
            ))

        return findings

    def _check_mixed_content(
        self, current_url: str, soup: Optional[BeautifulSoup], all_text: str
    ) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        active_mixed: List[str] = []
        passive_mixed: List[str] = []

        if soup:
            # 1. Mixed Content Ativo no DOM (Scripts, Iframes, CSS, Object, Embed)
            for script in soup.find_all("script", src=True):
                if self._is_insecure_external_url(script["src"]):
                    active_mixed.append(f"Script: {script['src']}")

            for link in soup.find_all("link", href=True):
                rels = [r.lower() for r in (link.get("rel") or [])]
                if "stylesheet" in rels and self._is_insecure_external_url(link["href"]):
                    active_mixed.append(f"CSS: {link['href']}")

            for tag_name, attr in [("iframe", "src"), ("object", "data"), ("embed", "src")]:
                for elem in soup.find_all(tag_name, **{attr: True}):
                    if self._is_insecure_external_url(elem[attr]):
                        active_mixed.append(f"{tag_name.capitalize()}: {elem[attr]}")

            # 2. Mixed Content Passivo no DOM (Imagens, Áudio, Vídeo)
            for tag_name in ("img", "audio", "video", "source"):
                for elem in soup.find_all(tag_name, src=True):
                    if self._is_insecure_external_url(elem["src"]):
                        passive_mixed.append(f"{tag_name.upper()}: {elem['src']}")

        # 3. Mixed Content Ativo no JavaScript (fetch/axios http:// e WebSockets ws://)
        for pattern, label in self.INSECURE_JS_TRANSPORT_PATTERNS:
            for match in pattern.findall(all_text):
                if self._is_insecure_external_url(match):
                    active_mixed.append(f"{label}: {match}")

        active_mixed = list(dict.fromkeys(active_mixed))
        passive_mixed = list(dict.fromkeys(passive_mixed))

        if active_mixed:
            findings.append(AuditFinding(
                id="SEC-A02-MIXED-CONTENT-ACTIVE",
                title=f"Mixed Content Ativo Detectado ({len(active_mixed)} recurso(s) HTTP/WS)",
                category=self.owasp_category,
                severity=Severity.HIGH,
                url=current_url,
                description=(
                    "A página HTTPS carrega scripts, folhas de estilo, iframes ou faz chamadas de API/WebSocket "
                    "através de conexões não criptografadas (HTTP/WS). Isso permite que atacantes na rede interceptem "
                    "a requisição e injetem código arbitrário na sessão segura."
                ),
                evidence="Recursos ativos inseguros:\n" + "\n".join(active_mixed[:6]),
                remediation=(
                    "Substitua todas as referências 'http://' por 'https://' (e 'ws://' por 'wss://') "
                    "e adicione o cabeçalho 'Content-Security-Policy: upgrade-insecure-requests'."
                ),
                vibe_coding_context="Modelos de IA frequentemente geram links de CDNs antigas ou URLs de WebSockets/APIs chumbadas com 'http://' ou 'ws://'."
            ))

        if passive_mixed:
            findings.append(AuditFinding(
                id="SEC-A02-MIXED-CONTENT-PASSIVE",
                title=f"Mixed Content Passivo Detectado ({len(passive_mixed)} mídia(s) HTTP)",
                category=self.owasp_category,
                severity=Severity.LOW,
                url=current_url,
                description=(
                    "A página HTTPS carrega imagens, vídeos ou áudios via HTTP puro. Embora não permita execução direta "
                    "de código, um atacante na rede pode substituir imagens, rastrear os usuários ou quebrar o layout "
                    "quando o navegador bloquear o conteúdo."
                ),
                evidence="Mídias HTTP detectadas:\n" + "\n".join(passive_mixed[:6]),
                remediation="Sirva todos os arquivos de mídia via HTTPS e utilize a diretiva CSP 'upgrade-insecure-requests'.",
                vibe_coding_context="Imagens de placeholder ou avatares externos inseridos pela IA durante a prototipagem muitas vezes usam URLs HTTP."
            ))

        return findings

    def _check_weak_client_crypto(self, current_url: str, all_text: str) -> List[AuditFinding]:
        detected: List[str] = []

        for pattern, label in self.WEAK_CRYPTO_PATTERNS:
            match = pattern.search(all_text)
            if match:
                snippet = match.group(0).strip()
                if len(snippet) > 60:
                    snippet = snippet[:57] + "..."
                detected.append(f"{snippet} [{label}]")

        if not detected:
            return []

        return [AuditFinding(
            id="SEC-A02-WEAK-CLIENT-CRYPTO",
            title="Prática Criptográfica Fraca ou Segredo Exposto no Cliente",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "Foram identificados algoritmos criptográficos obsoletos (MD5/SHA1/DES), uso de codificação Base64 "
                "para proteger dados sensíveis, geração de tokens com Math.random() ou chaves criptográficas "
                "hardcoded no JavaScript do cliente."
            ),
            evidence="Ocorrências detectadas: " + " | ".join(detected[:5]),
            remediation=(
                "1. Realize operações criptográficas sensíveis e hashing de senhas exclusivamente no backend (usando Argon2id ou bcrypt).\n"
                "2. Para geração de números aleatórios no navegador, use 'crypto.getRandomValues()' ou 'crypto.randomUUID()' em vez de 'Math.random()'.\n"
                "3. Nunca armazene chaves privadas ou chaves simétricas AES diretamente no código frontend."
            ),
            vibe_coding_context=(
                "Ao pedir para a IA 'criptografar a senha antes de enviar' ou 'gerar um token único no frontend', "
                "ela frequentemente recorre a btoa(), CryptoJS.MD5() ou Math.random().toString(36)."
            )
        )]
