# 🛡️ Navegador CyberSecurity — Vibe Coding & OWASP Top 10 Auditor

> **Navegador Web em Python com motor Chromium integrado, projetado para auditoria humana defensiva de aplicações desenvolvidas com IA ("vibe coding") e conformidade com o OWASP Top 10.**

---

## 🎯 Por que esta ferramenta existe?

O avanço do **vibe coding** (desenvolvimento acelerado utilizando assistentes de IA como Claude, GPT-4, Cursor, Copilot e v0) aumentou drasticamente a velocidade de entrega de software. No entanto, modelos de linguagem frequentemente cometem **erros repetitivos de segurança**:
- ❌ Sugerem chamadas diretas de frontend para APIs de IA, vazando chaves `OPENAI_API_KEY` ou `ANTHROPIC_API_KEY` no código cliente.
- ❌ Gravam tokens JWT de autenticação no `localStorage` por facilidade, expondo a sessão a qualquer injeção XSS.
- ❌ Omitem tokens anti-CSRF em formulários POST e deixam de configurar cabeçalhos defensivos (`Content-Security-Policy`, `X-Frame-Options`, `HSTS`).
- ❌ Usam `.innerHTML` ou `dangerouslySetInnerHTML` sem sanitização quando solicitados a renderizar textos formatados.
- ❌ Emitem cookies de sessão sem as flags essenciais `HttpOnly` e `Secure`.
- ❌ Deixam credenciais mockadas (`admin/admin123`) ou flags como `isAdmin: true` e `bypassAuth: true` para "testar rápido".

O **Navegador CyberSecurity** funciona como uma bancada de trabalho para o desenvolvedor e auditor: você navega normalmente pela sua aplicação (em `localhost` ou homologação) e o painel lateral aponta instantaneamente todas as falhas estruturais, sua gravidade, evidência e a respectiva correção de código.

---

## 🏛️ Arquitetura do Sistema

```
NavegadorCyberSecurity/
├── menu.ps1                    # Menu interativo em PowerShell (Central de Comando)
├── iniciar.bat                 # Atalho de inicialização rápida com duplo-clique
├── main.py                     # Ponto de entrada (GUI PyQt6 + Chromium)
├── config.py                   # Configurações globais e atalhos de portas dev
├── demo_vulnerable_app.py      # Servidor de teste com falhas típicas de IA
├── requirements.txt            # Dependências Python
│
├── core/                       # Núcleo da aplicação
│   ├── browser_window.py       # Janela principal com layout dividido (Split View)
│   ├── web_view.py             # Chromium WebView customizado com probe de DOM/JS
│   ├── audit_engine.py         # Motor de execução modular e cálculo de Security Score
│   └── report_generator.py     # Exportador de relatórios (Markdown, HTML, JSON)
│
├── modules/                    # Módulos de Auditoria (Plug & Play)
│   ├── base.py                 # Classes base: BaseAuditModule, AuditFinding, AuditContext
│   ├── a01_broken_access.py    # OWASP A01: Quebra de Controle de Acesso & Rotas Sensíveis
│   ├── a02_crypto_failures.py  # OWASP A02: Falhas Criptográficas & Mixed Content
│   ├── a03_injection.py        # OWASP A03: Injeção, DOM XSS Sinks & Formulários sem CSRF
│   ├── a05_misconfiguration.py # OWASP A05: Configuração Insegura (CSP, HSTS, CORS, Banners)
│   ├── a07_auth_failures.py    # OWASP A07: Cookies sem HttpOnly, Tokens em LocalStorage
│   ├── a08_integrity.py        # OWASP A08: Falhas de Integridade (CDNs sem SRI)
│   ├── vibe_coding_leaks.py    # Vibe Coding: Detecção de Chaves OpenAI, Supabase, Mock Auth
│   └── api_security_auditor.py # 🔌 OWASP API Security Top 10 (2023) & API Sentinel
│
├── ui/                         # Interface Gráfica
│   ├── styles.py               # Tema Cyber Dark moderno (QSS)
│   ├── audit_panel.py          # Painel lateral do auditor (Tabs, Score, Filtros)
│   └── finding_dialog.py       # Modal de detalhes e remediação passo a passo
│
└── tests/                      # Suite de Testes Automatizados
    ├── test_modules.py         # Testes unitários de cada módulo e pontuação
    └── test_e2e_audit.py       # Teste de integração ponta a ponta contra servidor real
```

---

## 🚀 Instalação e Execução

### 1. Pré-requisitos
- Python 3.10 ou superior instalado.

### 2. Instalar Dependências
```bash
pip install -r requirements.txt
```

### 3. Iniciar via Menu PowerShell (Recomendado)
Você pode abrir a central de comando interativa executando no PowerShell:
```powershell
.\menu.ps1
```
*(Ou dê um duplo-clique no arquivo `iniciar.bat` no Windows Explorer).*

O menu oferece atalhos para:
- Iniciar o navegador em modo padrão
- Abrir diretamente em uma porta de desenvolvimento (3000, 5173, etc.)
- Iniciar o servidor de teste vulnerável
- Modo demonstração completo (servidor de teste + navegador abrindo juntos)
- Rodar todos os testes automatizados
- Instalar dependências

### 4. Iniciar Diretamente via Python
```bash
python main.py
```

Você também pode abrir o navegador diretamente em uma URL ou porta específica:
```bash
# Abrir direto no localhost:3000
python main.py 3000

# Ou com URL completa
python main.py http://localhost:5173
```

---

## 🧪 Testando com a Aplicação Vulnerável de Demonstração

Para validar todos os recursos do navegador sem precisar configurar uma aplicação externa, utilize o servidor de testes incluso (`demo_vulnerable_app.py`):

1. Em um terminal, inicie o servidor vulnerável:
   ```bash
   python demo_vulnerable_app.py
   ```
   *(Ele iniciará em `http://localhost:5050`)*

2. No **Navegador CyberSecurity**, acerte a URL para `http://localhost:5050`.
3. O navegador executará a auditoria automaticamente e apresentará:
   - **Security Score: 0/100 (Nota F)**
   - 14 falhas detectadas categorizadas por severidade
   - Chave de IA da OpenAI interceptada no código
   - Token JWT detectado em `localStorage`
   - Cookie de sessão sem `HttpOnly`
   - Sinks de injeção `.innerHTML` e `eval()` apontados com linha e trecho
   - Formulário sem Anti-CSRF
   - Script jQuery de CDN externa sem hash SRI

---

## 📊 Sistema de Pontuação (Security Score)

O navegador calcula uma nota defensiva de 0 a 100 com pesos baseados no impacto real da falha:

| Severidade | Dedução | Impacto |
| :--- | :---: | :--- |
| 🔴 **CRÍTICA** | **-25 pts** | Vazamento de chaves privadas/IA, RCE via `eval()`, senhas sobre HTTP. |
| 🟠 **ALTA** | **-15 pts** | Ausência de CSP, Cookie sem `HttpOnly`, JWT em `localStorage`, falta de CSRF. |
| 🟡 **MÉDIA** | **-8 pts** | Ausência de HSTS, Clickjacking, scripts CDN sem SRI, `.innerHTML` sink. |
| 🔵 **BAIXA** | **-3 pts** | Vazamento de versão de servidor (`X-Powered-By`), política de Referrer fraca. |
| ⚪ **INFO** | **0 pts** | Informações contextuais de mapeamento de rotas. |

**Tabela de Classificação:**
- **95 a 100:** `A+` (Excelente)
- **85 a 94:** `A` (Bom)
- **70 a 84:** `B` (Requer Atenção)
- **50 a 69:** `C` (Vulnerável)
- **30 a 49:** `D` (Crítico)
- **0 a 29:** `F` (Gravemente Comprometido)

---

## 🔌 Como Criar Novos Módulos de Auditoria

O sistema é 100% plug & play. Para adicionar uma nova verificação, basta criar uma classe herdando de `BaseAuditModule` no diretório `modules/`:

```python
from typing import List
from modules.base import BaseAuditModule, AuditFinding, AuditContext, OwaspCategory, Severity

class MeuNovoModulo(BaseAuditModule):
    @property
    def module_id(self) -> str:
        return "mod_meu_novo_check"

    @property
    def name(self) -> str:
        return "Verificação Customizada"

    @property
    def description(self) -> str:
        return "Verifica uma regra específica da minha empresa."

    @property
    def owasp_category(self) -> OwaspCategory:
        return OwaspCategory.A05_SECURITY_MISCONFIG

    def run(self, context: AuditContext) -> List[AuditFinding]:
        findings = []
        # Inspecione context.headers, context.html, context.cookies, context.local_storage, etc.
        if "chave_proibida" in context.html:
            findings.append(AuditFinding(
                id="SEC-CUSTOM-01",
                title="Padrão Inseguro Encontrado",
                category=self.owasp_category,
                severity=Severity.HIGH,
                url=context.url,
                description="Explicação do risco.",
                evidence="Trecho detectado",
                remediation="Como corrigir no código",
                vibe_coding_context="Dica de prompt de IA para evitar esse problema."
            ))
        return findings
```
Em seguida, adicione o módulo em `modules/__init__.py`.

---

## 🧪 Executando os Testes Automatizados

Para rodar todos os testes de unidade e integração:
```bash
python -m unittest discover tests
```

---

## 📜 Licença
Projeto desenvolvido para auditoria defensiva de sistemas web e boas práticas de engenharia de software com IA.
