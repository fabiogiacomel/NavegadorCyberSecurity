"""
Janela Principal do Navegador CyberSecurity (MainWindow).
Layout dividido (Split View) com navegador Chromium à esquerda e Painel de Auditoria à direita.
"""

from typing import Optional
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QToolBar, QSplitter,
    QProgressBar, QLabel, QCheckBox
)
from PyQt6.QtCore import QUrl, Qt
from PyQt6.QtGui import QIcon, QAction

from core.web_view import CyberSecurityWebView
from core.audit_engine import AuditEngine
from ui.audit_panel import AuditPanel
from ui.styles import CYBER_DARK_QSS


class CyberSecurityBrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSecurity Browser — Vibe Coding & OWASP Top 10 Auditor")
        self.resize(1440, 900)
        self.setStyleSheet(CYBER_DARK_QSS)

        # Inicializa o motor de auditoria
        self.audit_engine = AuditEngine(self)

        self._init_ui()
        self._setup_connections()

        # Carrega a página inicial de boas-vindas do auditor
        self.load_welcome_page()

    def _init_ui(self):
        # 1. Barra de Ferramentas Superior (Navegação & Auditoria)
        self.toolbar = QToolBar("Navegação")
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)

        # Botões de Navegação
        self.btn_back = QPushButton("◀")
        self.btn_back.setObjectName("btn_nav")
        self.btn_back.setToolTip("Voltar")
        self.toolbar.addWidget(self.btn_back)

        self.btn_forward = QPushButton("▶")
        self.btn_forward.setObjectName("btn_nav")
        self.btn_forward.setToolTip("Avançar")
        self.toolbar.addWidget(self.btn_forward)

        self.btn_reload = QPushButton("🔄")
        self.btn_reload.setObjectName("btn_nav")
        self.btn_reload.setToolTip("Recarregar Página")
        self.toolbar.addWidget(self.btn_reload)

        self.btn_home = QPushButton("🏠")
        self.btn_home.setObjectName("btn_nav")
        self.btn_home.setToolTip("Página Inicial do Auditor")
        self.toolbar.addWidget(self.btn_home)

        # Campo de Endereço URL
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Digite a URL ou porta local (ex: http://localhost:3000 ou https://exemplo.com)...")
        self.toolbar.addWidget(self.url_bar)

        # Botão Ir / Navegar
        self.btn_go = QPushButton("Ir")
        self.toolbar.addWidget(self.btn_go)

        # Checkbox Auto-Auditoria
        self.chk_auto_audit = QCheckBox("Auditoria Automática")
        self.chk_auto_audit.setChecked(True)
        self.chk_auto_audit.setStyleSheet("color: #8b949e; margin-left: 8px; margin-right: 8px;")
        self.toolbar.addWidget(self.chk_auto_audit)

        # Botão Disparar Auditoria
        self.btn_audit_top = QPushButton("⚡ Auditar Agora")
        self.btn_audit_top.setObjectName("btn_audit")
        self.toolbar.addWidget(self.btn_audit_top)

        # Botão Alternar Painel Lateral
        self.btn_toggle_panel = QPushButton("📋 Painel")
        self.btn_toggle_panel.setToolTip("Ocultar / Exibir Painel de Auditoria")
        self.toolbar.addWidget(self.btn_toggle_panel)

        # 2. Área Central com Splitter (Browser à Esquerda, Painel à Direita)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # Navegador Web Chromium
        self.web_view = CyberSecurityWebView(self)
        self.splitter.addWidget(self.web_view)

        # Painel Lateral de Auditoria
        self.audit_panel = AuditPanel(self)
        self.splitter.addWidget(self.audit_panel)

        # Proporção inicial: 65% Browser, 35% Painel
        self.splitter.setSizes([920, 520])
        self.setCentralWidget(self.splitter)

        # 3. Barra de Status Inferior
        self.status_bar = self.statusBar()
        self.status_label = QLabel(f"Pronto | {len(self.audit_engine.modules)} módulos de segurança carregados")
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(150)
        self.progress_bar.setMaximumHeight(14)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _setup_connections(self):
        # Ações dos botões de navegação
        self.btn_back.clicked.connect(self.web_view.back)
        self.btn_forward.clicked.connect(self.web_view.forward)
        self.btn_reload.clicked.connect(self.web_view.reload)
        self.btn_home.clicked.connect(self.load_welcome_page)
        self.btn_go.clicked.connect(self._navigate_to_url)
        self.url_bar.returnPressed.connect(self._navigate_to_url)

        # Ações de auditoria
        self.btn_audit_top.clicked.connect(self.run_audit_current_page)
        self.audit_panel.request_audit.connect(self.run_audit_current_page)

        # Alternar visibilidade do painel
        self.btn_toggle_panel.clicked.connect(self._toggle_inspector_panel)

        # Eventos do WebView
        self.web_view.urlChanged.connect(self._on_url_changed)
        self.web_view.loadProgress.connect(self._on_load_progress)
        self.web_view.loadFinished.connect(self._on_load_finished)

        # Eventos do Audit Engine
        self.audit_engine.audit_completed.connect(self.audit_panel.update_results)

    def _navigate_to_url(self):
        text = self.url_bar.text().strip()
        if not text:
            return

        # Trata portas locais (ex: 3000, 5000, 8000)
        if text.isdigit():
            text = f"http://localhost:{text}"
        elif not text.startswith("http://") and not text.startswith("https://") and not text.startswith("file://") and not text.startswith("about:"):
            # Se for localhost ou IP sem protocolo, default para http
            if text.startswith("localhost") or text.startswith("127.0.0.1"):
                text = f"http://{text}"
            else:
                text = f"https://{text}"

        self.url_bar.setText(text)
        self.web_view.setUrl(QUrl(text))

    def _on_url_changed(self, qurl: QUrl):
        url_str = qurl.toString()
        if url_str != "about:blank":
            self.url_bar.setText(url_str)
            self.status_label.setText(f"Navegando: {url_str}")

    def _on_load_progress(self, progress: int):
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(progress)

    def _on_load_finished(self, success: bool):
        self.progress_bar.setVisible(False)
        url = self.web_view.url().toString()
        if success:
            self.status_label.setText(f"Página carregada: {url}")
            if self.chk_auto_audit.isChecked() and not url.startswith("about:"):
                self.run_audit_current_page()
        else:
            self.status_label.setText(f"Falha ao carregar: {url}")

    def run_audit_current_page(self):
        """Coleta o contexto da página no Chromium e dispara a auditoria."""
        current_url = self.web_view.url().toString()
        if not current_url or current_url.startswith("about:"):
            return

        self.status_label.setText(f"Auditando segurança em {current_url}...")
        self.btn_audit_top.setEnabled(False)
        self.btn_audit_top.setText("Auditando...")

        def on_context_extracted(context):
            summary = self.audit_engine.run_audit(context)
            self.btn_audit_top.setEnabled(True)
            self.btn_audit_top.setText("⚡ Auditar Agora")
            score = summary.get("score", 100)
            grade = summary.get("grade", "A+")
            total = summary.get("total_findings", 0)
            self.status_label.setText(f"Auditoria Concluída: Nota {grade} ({score}/100) — {total} falhas apontadas")

        self.web_view.extract_audit_context(on_context_extracted)

    def _toggle_inspector_panel(self):
        is_visible = self.audit_panel.isVisible()
        self.audit_panel.setVisible(not is_visible)
        self.btn_toggle_panel.setText("📋 Exibir" if is_visible else "📋 Ocultar")

    def load_welcome_page(self):
        """Carrega a página HTML interna de boas-vindas do navegador."""
        welcome_html = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    background: #0d1117;
                    color: #c9d1d9;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    padding: 40px;
                    line-height: 1.6;
                }}
                .hero {{
                    max-width: 850px;
                    margin: 0 auto;
                }}
                h1 {{
                    color: #58a6ff;
                    font-size: 32px;
                    margin-bottom: 8px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }}
                .tagline {{
                    font-size: 16px;
                    color: #8b949e;
                    margin-bottom: 28px;
                }}
                .cards {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 16px;
                    margin-top: 24px;
                }}
                .card {{
                    background: #161b22;
                    border: 1px solid #30363d;
                    border-radius: 8px;
                    padding: 18px;
                }}
                .card h3 {{
                    margin: 0 0 8px 0;
                    color: #e6edf3;
                    font-size: 15px;
                }}
                .card p {{
                    font-size: 13px;
                    color: #8b949e;
                    margin: 0;
                }}
                .port-btn {{
                    display: inline-block;
                    background: #21262d;
                    color: #58a6ff;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 6px 12px;
                    margin-right: 8px;
                    margin-top: 10px;
                    text-decoration: none;
                    font-family: monospace;
                    font-size: 13px;
                }}
                .port-btn:hover {{
                    background: #30363d;
                    border-color: #58a6ff;
                }}
                .alert {{
                    background: #1f2937;
                    border-left: 4px solid #388bfd;
                    padding: 14px;
                    border-radius: 6px;
                    margin-top: 24px;
                    font-size: 13px;
                }}
            </style>
        </head>
        <body>
            <div class="hero">
                <h1>🛡️ Navegador CyberSecurity</h1>
                <div class="tagline">
                    Plataforma de Auditoria Humana Defensiva para Aplicações Web e Vibe Coding (OWASP Top 10)
                </div>

                <div class="alert">
                    💡 <strong>Como Auditar:</strong> Digite a URL ou porta da aplicação na barra superior.
                    O motor inspecionará automaticamente o DOM, cabeçalhos HTTP, cookies, storage e vazamentos de segredos de IA.
                </div>

                <div style="margin-top: 24px;">
                    <strong>Atalhos Rápidos de Desenvolvimento Local:</strong><br>
                    <a class="port-btn" href="http://localhost:3000">localhost:3000 (React / Next.js)</a>
                    <a class="port-btn" href="http://localhost:5173">localhost:5173 (Vite / Svelte)</a>
                    <a class="port-btn" href="http://localhost:5000">localhost:5000 (Flask / Python)</a>
                    <a class="port-btn" href="http://localhost:8000">localhost:8000 (FastAPI / Django)</a>
                </div>

                <div class="cards">
                    <div class="card">
                        <h3>🤖 Auditoria de Vibe Coding</h3>
                        <p>Detecta chaves de API (OpenAI, Anthropic, Supabase), senhas mock, flags bypassAuth e tokens sensíveis salvos em localStorage.</p>
                    </div>
                    <div class="card">
                        <h3>🛡️ OWASP Top 10</h3>
                        <p>Audita CSP, HSTS, X-Frame-Options (Clickjacking), formulários sem proteção Anti-CSRF, DOM XSS sinks (innerHTML, eval) e CORS.</p>
                    </div>
                    <div class="card">
                        <h3>🍪 Sessões e Cookies</h3>
                        <p>Verifica se cookies de autenticação possuem as flags HttpOnly, Secure e SameSite corretas para impedir roubo de sessão.</p>
                    </div>
                    <div class="card">
                        <h3>📊 Relatórios Automáticos</h3>
                        <p>Exporte em 1 clique o relatório completo das falhas com evidências e recomendações em Markdown, HTML estilizado ou JSON.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        self.web_view.setHtml(welcome_html, QUrl("about:welcome"))
        self.url_bar.setText("about:welcome")
