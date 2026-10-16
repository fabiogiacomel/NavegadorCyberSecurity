"""
Módulo Especializado: Vibe Coding & Vazamento de Segredos de IA.
Audita e localiza com precisão cirúrgica (arquivo, script, número de linha e trecho contextual):
- Chaves de API de IA e Cloud (OpenAI, Anthropic, Supabase, AWS, Firebase).
- Credenciais mock/hardcoded e flags de bypass.
- Fornece instruções exatas de ONDE e COMO corrigir no código e no console do provedor.
"""

import re
from typing import List, Dict, Tuple, Optional
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


def extract_code_context(source_name: str, full_content: str, match_start: int, match_end: int) -> str:
    """
    Extrai o contexto de código ao redor da ocorrência com numeração de linhas,
    indicando exatamente onde a vulnerabilidade está no arquivo ou script.
    """
    lines = full_content.splitlines()
    # Determina o número da linha (1-indexed)
    line_idx = full_content[:match_start].count("\n")
    target_line_num = line_idx + 1

    # Janela de 2 linhas antes e 2 linhas depois
    start_line = max(0, line_idx - 2)
    end_line = min(len(lines), line_idx + 3)

    formatted_lines = [
        f"📍 Localização: {source_name} (Linha {target_line_num})",
        "────────────────────────────────────────────────────────────"
    ]

    for idx in range(start_line, end_line):
        cur_line_num = idx + 1
        line_text = lines[idx] if idx < len(lines) else ""
        if idx == line_idx:
            # Linha vulnerável destacada
            formatted_lines.append(f" > {cur_line_num:4d} | {line_text}")
            formatted_lines.append(f"        | ^^^ [FALHA DE SEGURANÇA LOCALIZADA AQUI]")
        else:
            formatted_lines.append(f"   {cur_line_num:4d} | {line_text}")

    formatted_lines.append("────────────────────────────────────────────────────────────")
    return "\n".join(formatted_lines)


class VibeCodingLeaksModule(BaseAuditModule):
    @property
    def module_id(self) -> str:
        return "mod_vibe_coding_leaks"

    @property
    def name(self) -> str:
        return "Auditoria Vibe-Coding: Chaves de API & Segredos de IA"

    @property
    def description(self) -> str:
        return "Detecta chaves de LLMs (OpenAI, Anthropic), segredos de cloud, credenciais mock e aponta linha e arquivo exatos para correção."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.VIBE_CODING_PATTERNS

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith("chrome://") or context.url.startswith("about:"):
            return findings

        # Lista de fontes rastreáveis individualmente com seus nomes e conteúdos
        sources: List[Tuple[str, str]] = []
        if context.html:
            sources.append(("HTML da Página", context.html))

        for idx, script in enumerate(context.scripts, 1):
            sources.append((f"Script Inline #{idx}", script))

        # Padrões de Chaves de API e Segredos
        secret_specs = [
            {
                "regex": r"sk-proj-[a-zA-Z0-9_\-]{40,}",
                "id": "VIBE-SECRET-OPENAI-KEY",
                "title": "Chave de API OpenAI (sk-proj) Exposta no Frontend",
                "severity": Severity.CRITICAL,
                "desc": "Uma chave de API da OpenAI (sk-proj-...) foi detectada diretamente no código do cliente. Qualquer usuário pode inspecionar o código, roubar esta chave e utilizá-la em sua conta gerando custos altos e acessando dados de prompts.",
                "remediation": (
                    "ONDE E COMO CORRIGIR:\n"
                    "1. ARQUIVO: Procure no seu código frontend (ex: 'src/App.jsx', 'src/services/api.ts' ou no próprio HTML) onde a chave 'sk-proj-' está escrita.\n"
                    "2. REMOÇÃO: NUNCA chame a API da OpenAI direto do navegador ('fetch(\"https://api.openai.com/...\")').\n"
                    "3. BACKEND PROXY: Crie uma rota no seu backend (ex: POST /api/chat em Express/FastAPI) que lê a OPENAI_API_KEY a partir de um arquivo '.env' no servidor e faz a requisição autenticada de lá.\n"
                    "4. REVOGAÇÃO: Revogue esta chave exposta IMEDIATAMENTE no painel da OpenAI (https://platform.openai.com/api-keys)."
                ),
                "vibe_tip": "Em vibe coding, o usuário pede 'crie um chat com a OpenAI' e o assistente de IA sugere a chamada direta no componente React por ser mais rápido."
            },
            {
                "regex": r"sk-[a-zA-Z0-9]{20,48}",
                "id": "VIBE-SECRET-OPENAI-LEGACY-KEY",
                "title": "Chave de API OpenAI Legada (sk-...) Detectada",
                "severity": Severity.CRITICAL,
                "desc": "Possível chave de API da OpenAI encontrada no código do cliente.",
                "remediation": (
                    "ONDE E COMO CORRIGIR:\n"
                    "1. Remova a chave do código cliente e revogue-a no painel da OpenAI.\n"
                    "2. Mova a chamada à IA para um backend seguro protegido por autenticação de sessão."
                ),
                "vibe_tip": "Comum em exemplos gerados por modelos mais antigos que não usam as novas chaves 'sk-proj'."
            },
            {
                "regex": r"sk-ant-[a-zA-Z0-9_\-]{30,}",
                "id": "VIBE-SECRET-ANTHROPIC-KEY",
                "title": "Chave de API Anthropic Claude (sk-ant) Exposta",
                "severity": Severity.CRITICAL,
                "desc": "Chave de API do Claude/Anthropic exposta em código visível pelo navegador.",
                "remediation": (
                    "ONDE E COMO CORRIGIR:\n"
                    "1. ARQUIVO: Localize no frontend a variável que inicializa o Anthropic Client.\n"
                    "2. Mova a inicialização para o backend e guarde a ANTHROPIC_API_KEY no '.env' do servidor.\n"
                    "3. Revogue esta chave no console da Anthropic (https://console.anthropic.com)."
                ),
                "vibe_tip": "Ocorre quando o desenvolvedor pede para a IA gerar um app com Claude sem configurar servidor."
            },
            {
                "regex": r"AKIA[0-9A-Z]{16}",
                "id": "VIBE-SECRET-AWS-KEY",
                "title": "AWS Access Key ID Hardcoded no Cliente",
                "severity": Severity.CRITICAL,
                "desc": "Uma chave de acesso da AWS (AKIA...) foi encontrada no código cliente da página. Isso pode comprometer buckets S3, instâncias EC2 e outros serviços de nuvem.",
                "remediation": (
                    "ONDE E COMO CORRIGIR:\n"
                    "1. Revogue a credencial imediatamente no AWS IAM Console.\n"
                    "2. Se o frontend faz upload de arquivos no S3, utilize URLs pré-assinadas (Presigned S3 URLs) geradas pelo backend em vez de credenciais fixas."
                ),
                "vibe_tip": "IAs costumam gerar código de upload direto para S3 no cliente com chaves hardcoded se o usuário não exigir explicitamente presigned URLs."
            },
            {
                "regex": r"ghp_[a-zA-Z0-9]{36}",
                "id": "VIBE-SECRET-GITHUB-TOKEN",
                "title": "GitHub Personal Access Token Exposto",
                "severity": Severity.CRITICAL,
                "desc": "Um token de acesso pessoal do GitHub (ghp_...) foi encontrado exposto no código.",
                "remediation": (
                    "ONDE E COMO CORRIGIR:\n"
                    "1. Revogue o token no GitHub (Settings > Developer Settings > Personal Access Tokens).\n"
                    "2. Transfira qualquer integração com a API do GitHub para o servidor."
                ),
                "vibe_tip": "Frequentemente esquecido após testes rápidos de integração com a API do GitHub."
            },
            {
                "regex": r"AIza[0-9A-Za-z\-_]{35}",
                "id": "VIBE-SECRET-FIREBASE-KEY",
                "title": "Chave de API Google / Firebase Detectada",
                "severity": Severity.MEDIUM,
                "desc": (
                    "Chave de API do Firebase/Google identificada no código do cliente. "
                    "Embora chaves do Firebase Web Client sejam necessárias no frontend, a sua aplicação fica "
                    "TOTALMENTE VULNERÁVEL se as regras do banco de dados (Firestore / Realtime Database) estiverem abertas."
                ),
                "remediation": (
                    "ONDE E COMO CONSERTAR PASSO A PASSO:\n\n"
                    "1. ONDE ESTÁ NO SEU CÓDIGO:\n"
                    "   Procure no seu projeto pelo arquivo de configuração do Firebase (ex: 'src/firebase.js', 'src/lib/firebase.ts', 'src/config/firebase.ts' ou dentro de <script> no 'index.html').\n"
                    "   Você encontrará o bloco:\n"
                    "   const firebaseConfig = {\n"
                    "       apiKey: \"AIzaSy...\",\n"
                    "       authDomain: \"...\",\n"
                    "       projectId: \"...\"\n"
                    "   };\n\n"
                    "2. CORREÇÃO CRÍTICA NAS REGRAS DO BANCO (FIRESTORE RULES):\n"
                    "   As chaves 'AIzaSy...' do Firebase são públicas por design do SDK Web do Google. A segurança REAL não vem de esconder a chave, mas de PROTEGER AS REGRAS DO BANCO!\n"
                    "   - Acesse o Firebase Console: https://console.firebase.google.com\n"
                    "   - Vá em 'Firestore Database' > aba 'Regras' (Rules).\n"
                    "   - NUNCA deixe: 'allow read, write: if true;' (qualquer pessoa com a chave pode apagar seu banco todo!).\n"
                    "   - Configure regras protegidas por autenticação. Exemplo:\n"
                    "     rules_version = '2';\n"
                    "     service cloud.firestore {\n"
                    "       match /databases/{database}/documents {\n"
                    "         match /usuarios/{userId} {\n"
                    "           allow read, write: if request.auth != null && request.auth.uid == userId;\n"
                    "         }\n"
                    "       }\n"
                    "     }\n\n"
                    "3. RESTRINGIR A CHAVE NO GOOGLE CLOUD CONSOLE:\n"
                    "   - Acesse https://console.cloud.google.com > APIs e Serviços > Credenciais.\n"
                    "   - Clique na chave 'AIzaSy...'.\n"
                    "   - Em 'Restrições de Aplicativo', selecione 'Referrers HTTP (sites da Web)'.\n"
                    "   - Adicione apenas os seus domínios autorizados (ex: 'https://seusite.com/*', 'http://localhost:*').\n"
                    "   - Em 'Restrições de API', selecione apenas as APIs que seu app usa (ex: Firebase Authentication, Cloud Firestore)."
                ),
                "vibe_tip": "O template gerado automaticamente por IAs inclui o bloco 'const firebaseConfig = { apiKey: ... }' no frontend. Se o desenvolvedor não pedir à IA para criar as Firestore Rules, o banco fica aberto na internet."
            }
        ]

        # Varre cada fonte individualmente para indicar o local exato
        found_signatures = set()

        for source_name, content in sources:
            for spec in secret_specs:
                regex = spec["regex"]
                for match in re.finditer(regex, content):
                    matched_text = match.group(0)
                    sig = (spec["id"], matched_text)
                    if sig in found_signatures:
                        continue
                    found_signatures.add(sig)

                    # Gera o bloco de evidência contextualizado com linha
                    evidence_box = extract_code_context(
                        source_name=source_name,
                        full_content=content,
                        match_start=match.start(),
                        match_end=match.end()
                    )

                    findings.append(AuditFinding(
                        id=spec["id"],
                        title=spec["title"],
                        category=self.owasp_category,
                        severity=spec["severity"],
                        url=context.url,
                        description=spec["desc"],
                        evidence=evidence_box,
                        remediation=spec["remediation"],
                        vibe_coding_context=spec["vibe_tip"]
                    ))

        # 2. Padrões de Mock e Bypass de Autenticação gerados por IA
        mock_patterns = [
            (
                r"(?:isAdmin|is_admin)\s*[:=]\s*true",
                "VIBE-MOCK-ADMIN-OVERRIDE",
                "Flag de Privilégio Administrativo Forçada no Cliente ('isAdmin: true')",
                Severity.HIGH,
                "Foi detectada uma instrução no cliente forçando privilégio de administrador (isAdmin = true). Se a autorização da aplicação depender do estado no frontend, qualquer usuário pode modificar esta variável e assumir o controle do sistema.",
                "Toda validação de privilégios de acesso DEVE ser executada exclusivamente no servidor (backend) a cada requisição.",
                "Para testar a tela de admin rapidamente, quem programa com IA costuma pedir 'deixe o admin liberado pra eu testar', e esse código segue para produção."
            ),
            (
                r"(?:bypassAuth|skipAuth|ignoreAuth)\s*[:=]\s*true",
                "VIBE-MOCK-BYPASS-AUTH",
                "Flag de Bypass de Autenticação ('bypassAuth = true')",
                Severity.HIGH,
                "Foi encontrada uma flag no código que desativa as checagens de autenticação.",
                "Remova qualquer bypass de desenvolvimento antes de subir o código para homologação ou produção.",
                "Clássica 'gambiarra' que o desenvolvedor pede para a IA acelerar o desenvolvimento de telas protegidas."
            ),
            (
                r"(?:password|passwd|senha)\s*[:=]\s*['\"](?:123456|admin|password|teste|test)['\"]",
                "VIBE-MOCK-WEAK-PASSWORD",
                "Credencial de Teste Fraca Hardcoded no Código",
                Severity.MEDIUM,
                "Valores de senhas padrão de teste ('admin', '123456', etc.) foram detectados em variáveis no frontend.",
                "Remova credenciais de teste fixas e use autenticação real.",
                "IAs costumam preencher formulários de login mockados com 'admin/admin' para agilizar os testes visuais."
            )
        ]

        for source_name, content in sources:
            for regex, finding_id, title, severity, desc, remed, vibe_tip in mock_patterns:
                for match in re.finditer(regex, content, re.IGNORECASE):
                    sig = (finding_id, match.group(0))
                    if sig in found_signatures:
                        continue
                    found_signatures.add(sig)

                    evidence_box = extract_code_context(
                        source_name=source_name,
                        full_content=content,
                        match_start=match.start(),
                        match_end=match.end()
                    )

                    findings.append(AuditFinding(
                        id=finding_id,
                        title=title,
                        category=self.owasp_category,
                        severity=severity,
                        url=context.url,
                        description=desc,
                        evidence=evidence_box,
                        remediation=remed,
                        vibe_coding_context=vibe_tip
                    ))

        # 3. Detecção de Source Maps expostos
        bundle_text = context.html + "\n" + "\n".join(context.scripts)
        if "//# sourceMappingURL=" in bundle_text or "//@ sourceMappingURL=" in bundle_text:
            findings.append(AuditFinding(
                id="VIBE-SOURCEMAP-EXPOSURE",
                title="Source Maps Detectados no Pacote do Frontend",
                category=self.owasp_category,
                severity=Severity.LOW,
                url=context.url,
                description="O aplicativo faz referência a arquivos .map (Source Maps). Isso permite que qualquer pessoa visualize o código original completo em TypeScript/React, incluindo comentários de desenvolvimento e rotas internas.",
                evidence="Referência a sourceMappingURL encontrada nos scripts.",
                remediation="Desative a geração de sourcemaps de produção no seu bundler (ex: vite.config.ts -> build: { sourcemap: false }).",
                vibe_coding_context="Projetos criados com templates rápidos (Vite, Next.js, CRA) frequentemente mantêm sourcemaps ativos se o comando de build padrão não for ajustado."
            ))

        return findings
