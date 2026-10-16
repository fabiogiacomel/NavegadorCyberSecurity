"""
Módulo Especializado: Segurança de Inteligência Artificial & OWASP LLM Top 10 (2025)
Audita aplicações integradas com LLMs e Agentes de IA em busca de:
- LLM01:2025 - Prompt Injection (Construção de prompts e controle da role 'system' no cliente)
- LLM05:2025 - Improper Output Handling (Renderização de respostas da IA sem sanitização -> XSS via Prompt Injection)
- LLM06:2025 - Excessive Agency & Chamadas Diretas a Provedores de IA pelo Navegador (OpenAI, Anthropic, Gemini, Groq, Ollama)
- LLM07:2025 - System Prompt Leakage (Exposição de System Prompts e instruções secretas no bundle frontend)
- LLM10:2025 - Unbounded Consumption / Denial of Wallet (Parâmetros 'model' e 'max_tokens' controlados pelo cliente)
"""

import re
from typing import List, Tuple
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity


class LlmAiSecurityAuditorModule(BaseAuditModule):
    IGNORED_SCHEMES = ("chrome://", "about:", "data:", "javascript:", "mailto:", "tel:")

    # 1. LLM06: Endpoints de provedores de LLM chamados diretamente a partir do navegador
    DIRECT_LLM_PROVIDER_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"https?://api\.openai\.com/v1/(?:chat/completions|responses|embeddings|assistants)", re.IGNORECASE), "OpenAI API Direta"),
        (re.compile(r"https?://api\.anthropic\.com/v1/messages", re.IGNORECASE), "Anthropic Claude API Direta"),
        (re.compile(r"https?://generativelanguage\.googleapis\.com/v1(?:beta)?/models/", re.IGNORECASE), "Google Gemini API Direta"),
        (re.compile(r"https?://api\.groq\.com/openai/v1/chat/completions", re.IGNORECASE), "Groq Cloud API Direta"),
        (re.compile(r"https?://openrouter\.ai/api/v1/chat/completions", re.IGNORECASE), "OpenRouter API Direta"),
        (re.compile(r"https?://api\.mistral\.ai/v1/chat/completions", re.IGNORECASE), "Mistral AI API Direta"),
        (re.compile(r"https?://(?:localhost|127\.0\.0\.1):11434/api/(?:generate|chat)", re.IGNORECASE), "Servidor Local Ollama Exposto"),
    ]

    # Ferramentas de alto risco (Excessive Agency - LLM06) declaradas no cliente
    EXCESSIVE_AGENCY_TOOL_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"['\"`](?:name|function)['\"`]\s*:\s*['\"`](?:execute_?sql|run_?sql|raw_?query|exec_?command|run_?bash|shell_?exec|delete_?user|drop_?table)['\"`]",
                re.IGNORECASE
            ),
            "Tool/Function Calling de execução irrestrita (SQL/Shell/Admin) exposta ao modelo"
        ),
    ]

    # 2. LLM01 & LLM07: Vazamento de System Prompt e construção insegura de Prompt no cliente
    SYSTEM_PROMPT_LEAK_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"\{\s*role\s*:\s*['\"`](?:system|developer)['\"`]\s*,\s*content\s*:\s*(['\"`][^'\"`]{15,}['\"`])",
                re.IGNORECASE | re.DOTALL
            ),
            "Mensagem com role 'system'/'developer' definida diretamente no cliente"
        ),
        (
            re.compile(
                r"\b(?:SYSTEM_PROMPT|systemPrompt|system_instruction|systemInstruction)\s*[:=]\s*(['\"`][^'\"`]{20,}['\"`])",
                re.IGNORECASE | re.DOTALL
            ),
            "Constante de System Prompt hardcoded no bundle frontend"
        ),
    ]

    CLIENT_PROMPT_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"`[^`]*(?:você é um|you are a|responda apenas|ignore previous|contexto:|instruções:)[^`]*\$\{[^}]+\}[^`]*`",
                re.IGNORECASE
            ),
            "Interpolação direta de entrada do usuário em template de prompt no cliente"
        ),
    ]

    # 3. LLM05: Improper Output Handling (Saída do modelo renderizada sem sanitização)
    UNSANITIZED_LLM_OUTPUT_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"(?:\.innerHTML|dangerouslySetInnerHTML)\s*[:=]\s*[^;\n]*(?:choices\[0\]\.message\.content|aiResponse|llmResponse|botReply|marked\.parse\s*\(| marked\s*\()",
                re.IGNORECASE
            ),
            "Resposta de LLM ou Markdown de IA injetado diretamente em innerHTML/dangerouslySetInnerHTML"
        ),
        (
            re.compile(
                r"\beval\s*\(\s*[^)]*(?:choices\[0\]|aiResponse|llmCode|generatedCode)",
                re.IGNORECASE
            ),
            "Execução direta de código gerado por LLM via eval() no navegador"
        ),
    ]

    # 4. LLM10: Unbounded Consumption (Denial of Wallet — modelo e max_tokens controlados pelo frontend)
    UNBOUNDED_CONSUMPTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\bmodel\s*:\s*['\"`](?:gpt-4[^'\"`]*|o1[^'\"`]*|o3[^'\"`]*|claude-3-[^'\"`]*|gemini-[^'\"`]*)['\"`]",
                re.IGNORECASE
            ),
            "Seleção do modelo de IA e custo da requisição controlada pelo payload do cliente"
        ),
        (
            re.compile(
                r"JSON\.stringify\s*\(\s*\{[^}]*\b(?:max_tokens|max_completion_tokens)\s*:\s*(\d{4,}|[a-zA-Z_$][\w.]*)",
                re.IGNORECASE
            ),
            "Limite de tokens (max_tokens) controlado diretamente pelo cliente"
        ),
    ]

    @property
    def module_id(self) -> str:
        return "mod_owasp_llm_ai"

    @property
    def name(self) -> str:
        return "Segurança de IA & OWASP LLM Top 10 (2025)"

    @property
    def description(self) -> str:
        return (
            "Audita vulnerabilidades do OWASP LLM Top 10: Prompt Injection no cliente, vazamento de System Prompt, "
            "renderização insegura de respostas da IA (XSS), Excessive Agency e Denial of Wallet."
        )

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.OWASP_LLM_TOP_10

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        if not context.url or context.url.startswith(self.IGNORED_SCHEMES):
            return findings

        html_content = context.html or ""
        scripts_content = "\n".join(context.scripts or [])
        all_text = f"{html_content}\n{scripts_content}"

        # 1. LLM06: Chamadas diretas do navegador a APIs de provedores de IA e Tools perigosas
        findings.extend(self._check_direct_llm_calls_and_agency(context.url, all_text, context.api_calls or []))

        # 2. LLM01 & LLM07: Vazamento de System Prompt e construção de prompt no cliente
        findings.extend(self._check_system_prompt_and_injection(context.url, all_text))

        # 3. LLM05: Improper Output Handling (XSS / Execução via resposta de IA)
        findings.extend(self._check_improper_llm_output_handling(context.url, all_text))

        # 4. LLM10: Unbounded Consumption / Denial of Wallet
        findings.extend(self._check_unbounded_llm_consumption(context.url, all_text))

        return findings

    @staticmethod
    def _clean_snippet(text: str, max_len: int = 80) -> str:
        cleaned = " ".join(text.strip().split())
        return cleaned[:max_len - 3] + "..." if len(cleaned) > max_len else cleaned

    def _check_direct_llm_calls_and_agency(
        self, current_url: str, all_text: str, api_calls: List[dict]
    ) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.DIRECT_LLM_PROVIDER_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {match.group(0)}")

        for call in api_calls:
            call_url = call.get("url", "")
            for pattern, label in self.DIRECT_LLM_PROVIDER_PATTERNS:
                if pattern.search(call_url):
                    evidences.append(f"Chamada interceptada ({label}): {call_url}")

        for pattern, label in self.EXCESSIVE_AGENCY_TOOL_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="LLM06-DIRECT-LLM-API-AND-TOOLS",
            title="Arquitetura de IA Insegura: Chamada Direta a Provedor LLM ou Excessive Agency (LLM06)",
            category=self.owasp_category,
            severity=Severity.CRITICAL,
            url=current_url,
            description=(
                "O navegador realiza conexões diretas com endpoints de provedores de IA (OpenAI, Anthropic, Gemini, "
                "Groq, OpenRouter ou Ollama) ou declara ferramentas (Function Calling) com permissões destrutivas "
                "(execução de SQL/comandos). Chamadas diretas do cliente exigem a exposição da API Key ou permitem "
                "que invasores usem sua cota livremente, enquanto ferramentas sem validação humana caracterizam "
                "Excessive Agency (OWASP LLM06)."
            ),
            evidence="Ocorrências detectadas: " + " | ".join(unique_evidences[:5]),
            remediation=(
                "1. Mova todas as chamadas a LLMs para rotas de backend autenticadas.\n"
                "2. Restrinja as ferramentas (Tools) disponíveis ao modelo seguindo o princípio do menor privilégio "
                "(conexões de banco somente-leitura e aprovação humana 'Human-in-the-Loop' para ações sensíveis)."
            ),
            vibe_coding_context=(
                "Erro número 1 em projetos de IA construídos rápido: instanciar o SDK da OpenAI/Anthropic com "
                "'dangerouslyAllowBrowser: true' diretamente em componentes React."
            )
        )]

    def _check_system_prompt_and_injection(self, current_url: str, all_text: str) -> List[AuditFinding]:
        findings: List[AuditFinding] = []
        prompt_leaks: List[str] = []
        injection_vectors: List[str] = []

        for pattern, label in self.SYSTEM_PROMPT_LEAK_PATTERNS:
            for match in pattern.finditer(all_text):
                prompt_leaks.append(f"{label}: {self._clean_snippet(match.group(0))}")

        for pattern, label in self.CLIENT_PROMPT_INJECTION_PATTERNS:
            for match in pattern.finditer(all_text):
                injection_vectors.append(f"{label}: {self._clean_snippet(match.group(0))}")

        if prompt_leaks:
            findings.append(AuditFinding(
                id="LLM07-SYSTEM-PROMPT-EXPOSED",
                title="Exposição e Controle de System Prompt no Lado do Cliente (OWASP LLM07 & LLM01)",
                category=self.owasp_category,
                severity=Severity.HIGH,
                url=current_url,
                description=(
                    "O System Prompt (instruções de sistema da IA) está visível no código JavaScript do cliente "
                    "e é enviado pelo navegador na requisição. Além de revelar propriedade intelectual e regras de "
                    "negócio internas (LLM07: System Prompt Leakage), qualquer usuário pode interceptar a chamada e "
                    "substituir a mensagem 'role: system' para realizar Jailbreak completo da IA (LLM01: Prompt Injection)."
                ),
                evidence="System Prompts encontrados: " + " | ".join(list(dict.fromkeys(prompt_leaks))[:4]),
                remediation=(
                    "Armazene e injete o 'system prompt' exclusivamente no servidor (backend). O frontend deve enviar "
                    "apenas a mensagem do usuário, e o backend deve prefixar as instruções de sistema de forma imutável."
                ),
                vibe_coding_context=(
                    "Ao criar wrappers de chat com IA, desenvolvedores frequentemente montam o array 'messages' "
                    "completo (incluindo o `{ role: 'system', content: '...' }`) no estado do React antes de enviar à API."
                )
            ))

        if injection_vectors:
            findings.append(AuditFinding(
                id="LLM01-CLIENT-PROMPT-CONSTRUCTION",
                title="Construção de Prompt com Interpolação Direta no Cliente (Risco de Prompt Injection - LLM01)",
                category=self.owasp_category,
                severity=Severity.MEDIUM,
                url=current_url,
                description=(
                    "A aplicação concatena a entrada do usuário diretamente dentro do template de instruções da IA "
                    "no código cliente. Isso permite que o usuário insira instruções adversariais ('Ignore todas as "
                    "instruções anteriores...') ou manipule o template diretamente pelo DevTools."
                ),
                evidence="Templates vulneráveis: " + " | ".join(list(dict.fromkeys(injection_vectors))[:4]),
                remediation=(
                    "Construa os templates de prompt no backend, separe claramente instruções de sistema e dados "
                    "não confiáveis usando delimitadores estruturados (XML tags / roles distintas) e valide a saída."
                ),
                vibe_coding_context=(
                    "Padrão típico de Vibe Coding: `const prompt = \\`Você é um assistente financeiro. Analise: \\${input}\\`` "
                    "montado diretamente no evento onClick do botão."
                )
            ))

        return findings

    def _check_improper_llm_output_handling(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.UNSANITIZED_LLM_OUTPUT_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="LLM05-UNSANITIZED-LLM-OUTPUT",
            title="Manipulação Insegura de Saída de LLM (Improper Output Handling -> XSS / RCE - LLM05)",
            category=self.owasp_category,
            severity=Severity.HIGH,
            url=current_url,
            description=(
                "A resposta gerada pelo modelo de linguagem (ou o HTML resultante de um parser Markdown como 'marked') "
                "é inserida diretamente no DOM sem sanitização ou executada via 'eval()'. Se um atacante realizar "
                "Prompt Injection (Direto ou Indireto via documentos/sites lidos pela IA) fazendo o modelo retornar "
                "`<img src=x onerror=...>`, o script malicioso será executado no navegador do usuário."
            ),
            evidence="Sinks de saída de IA: " + " | ".join(unique_evidences[:4]),
            remediation=(
                "Trate toda saída de LLM como dado não confiável: sanitize sempre o HTML gerado por Markdown usando "
                "`DOMPurify.sanitize(marked.parse(aiResponse))` e jamais utilize `eval()` sobre código gerado por IA "
                "fora de um sandbox isolado (Web Worker / iframe sandboxed / container)."
            ),
            vibe_coding_context=(
                "Interfaces de chat geradas por IA quase sempre usam `innerHTML = marked.parse(aiReply)` para "
                "exibir respostas formatadas, esquecendo que o `marked` moderno não sanitiza HTML por padrão."
            )
        )]

    def _check_unbounded_llm_consumption(self, current_url: str, all_text: str) -> List[AuditFinding]:
        evidences: List[str] = []

        for pattern, label in self.UNBOUNDED_CONSUMPTION_PATTERNS:
            for match in pattern.finditer(all_text):
                evidences.append(f"{label}: {self._clean_snippet(match.group(0))}")

        unique_evidences = list(dict.fromkeys(evidences))
        if not unique_evidences:
            return []

        return [AuditFinding(
            id="LLM10-UNBOUNDED-MODEL-OR-TOKENS",
            title="Consumo Irrestrito de IA / Denial of Wallet (Modelo ou max_tokens Controlado pelo Cliente - LLM10)",
            category=self.owasp_category,
            severity=Severity.MEDIUM,
            url=current_url,
            description=(
                "O payload enviado pelo frontend especifica diretamente qual modelo de IA utilizar (ex.: 'gpt-4', "
                "'claude-3-opus') ou o limite de tokens ('max_tokens'). Um atacante pode alterar a requisição "
                "para forçar o modelo mais caro disponível com 'max_tokens' máximo em loop, gerando custos "
                "financeiros severos (Denial of Wallet - OWASP LLM10)."
            ),
            evidence="Parâmetros de custo controlados no cliente: " + " | ".join(unique_evidences[:4]),
            remediation=(
                "Fixe o nome do modelo, a temperatura e o teto rígido de 'max_tokens' no backend, aplicando "
                "cotas de uso por usuário autenticado e limites de tamanho máximo no input recebido."
            ),
            vibe_coding_context=(
                "Backends de proxy para IA criados rapidamente costumam fazer `openai.chat.completions.create(req.body)`, "
                "repassando qualquer parâmetro `model` ou `max_tokens` escolhido pelo cliente."
            )
        )]
