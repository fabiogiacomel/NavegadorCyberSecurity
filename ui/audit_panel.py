"""
Painel Lateral de Auditoria de Segurança (Audit Inspector Panel).
Exibe em tempo real:
- Security Score e Nota (A+ a F)
- Lista filtrável de vulnerabilidades com cores e detalhes
- Inspecionador de Cabeçalhos HTTP e Cookies
- Scanner específico de Vibe Coding (vazamentos de IA)
- Exportador de relatórios (Markdown, HTML, JSON)
"""

import os
from typing import Dict, Any, List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QComboBox,
    QFrame, QTextEdit, QFileDialog, QMessageBox, QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont

from modules.base import AuditFinding, Severity, AuditContext
from ui.finding_dialog import FindingDetailDialog
from core.report_generator import ReportGenerator


class AuditPanel(QWidget):
    request_audit = pyqtSignal()  # Sinal disparado quando o usuário clica em "Auditar Agora"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_summary: Dict[str, Any] = {}
        self.all_findings: List[AuditFinding] = []
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Header do Painel: Score Card & Status Geral
        self.score_card = QFrame()
        self.score_card.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        score_layout = QHBoxLayout(self.score_card)
        score_layout.setContentsMargins(8, 8, 8, 8)

        # Badge Circular de Nota
        self.grade_label = QLabel("A+")
        self.grade_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.grade_label.setFixedSize(60, 60)
        self.grade_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.grade_label.setStyleSheet("""
            background-color: #0d1117;
            color: #3fb950;
            border: 2px solid #3fb950;
            border-radius: 30px;
        """)
        score_layout.addWidget(self.grade_label)

        # Texto de Score e Status
        score_text_layout = QVBoxLayout()
        self.score_title = QLabel("Security Score: 100/100")
        self.score_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.score_title.setStyleSheet("color: #ffffff;")
        score_text_layout.addWidget(self.score_title)

        self.score_subtitle = QLabel("Aguardando auditoria...")
        self.score_subtitle.setStyleSheet("color: #8b949e; font-size: 11px;")
        score_text_layout.addWidget(self.score_subtitle)

        # Contadores de Severidade
        self.counters_layout = QHBoxLayout()
        self.cnt_crit = self._create_mini_badge("0 Crit", "#f85149")
        self.cnt_high = self._create_mini_badge("0 Alt", "#f0883e")
        self.cnt_med = self._create_mini_badge("0 Méd", "#d29922")
        self.cnt_low = self._create_mini_badge("0 Bx", "#58a6ff")
        self.counters_layout.addWidget(self.cnt_crit)
        self.counters_layout.addWidget(self.cnt_high)
        self.counters_layout.addWidget(self.cnt_med)
        self.counters_layout.addWidget(self.cnt_low)
        self.counters_layout.addStretch()
        score_text_layout.addLayout(self.counters_layout)

        score_layout.addLayout(score_text_layout)

        # Botão de Ação "Auditar Agora"
        btn_audit = QPushButton("⚡ Auditar")
        btn_audit.setObjectName("btn_audit")
        btn_audit.setFixedWidth(90)
        btn_audit.setFixedHeight(36)
        btn_audit.clicked.connect(self.request_audit.emit)
        score_layout.addWidget(btn_audit)

        main_layout.addWidget(self.score_card)

        # 2. Barra de Filtro e Busca
        filter_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "Todas as Severidades",
            "🔴 Apenas Críticas",
            "🟠 Apenas Altas",
            "🟡 Apenas Médias",
            "🔵 Apenas Baixas"
        ])
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.filter_combo)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Filtrar falhas...")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.search_input)

        main_layout.addLayout(filter_layout)

        # 3. Tab Widget com as Abas do Auditor
        self.tabs = QTabWidget()

        # Aba 1: Vulnerabilidades
        self.tab_findings = QWidget()
        self._init_tab_findings()
        self.tabs.addTab(self.tab_findings, "🚨 Vulnerabilidades")

        # Aba 2: Headers & Cookies
        self.tab_headers = QWidget()
        self._init_tab_headers()
        self.tabs.addTab(self.tab_headers, "🌐 Headers & Cookies")

        # Aba 3: API Sentinel (OWASP API Top 10)
        self.tab_api = QWidget()
        self._init_tab_api()
        self.tabs.addTab(self.tab_api, "🔌 API Sentinel")

        # Aba 4: Vibe-Coding Scanner
        self.tab_vibe = QWidget()
        self._init_tab_vibe()
        self.tabs.addTab(self.tab_vibe, "🤖 Vibe-Coding")

        # Aba 5: Relatório
        self.tab_report = QWidget()
        self._init_tab_report()
        self.tabs.addTab(self.tab_report, "📄 Relatório")

        main_layout.addWidget(self.tabs)

    def _create_mini_badge(self, text: str, color: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"""
            background-color: {color}22;
            color: {color};
            border: 1px solid {color}66;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            padding: 2px 6px;
        """)
        return lbl

    # -------------------------------------------------------------
    # ABA 1: Vulnerabilidades
    # -------------------------------------------------------------
    def _init_tab_findings(self):
        layout = QVBoxLayout(self.tab_findings)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Árvore de achados
        self.tree_findings = QTreeWidget()
        self.tree_findings.setHeaderLabels(["Severidade", "Vulnerabilidade", "Categoria OWASP"])
        self.tree_findings.header().resizeSection(0, 110)
        self.tree_findings.header().resizeSection(1, 230)
        self.tree_findings.itemDoubleClicked.connect(self._on_finding_double_clicked)
        self.tree_findings.itemSelectionChanged.connect(self._on_finding_selected)
        splitter.addWidget(self.tree_findings)

        # Preview inferior do achado selecionado
        self.preview_frame = QFrame()
        self.preview_frame.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
            }
        """)
        preview_layout = QVBoxLayout(self.preview_frame)
        preview_layout.setContentsMargins(8, 8, 8, 8)
        preview_layout.setSpacing(4)

        self.preview_title = QLabel("Selecione um item acima para ver detalhes")
        self.preview_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.preview_title.setStyleSheet("color: #58a6ff;")
        self.preview_title.setWordWrap(True)
        preview_layout.addWidget(self.preview_title)

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setPlaceholderText("A remediação e evidência detalhadas aparecerão aqui...")
        preview_layout.addWidget(self.preview_text)

        splitter.addWidget(self.preview_frame)
        splitter.setSizes([320, 200])

        layout.addWidget(splitter)

    # -------------------------------------------------------------
    # ABA 2: Headers & Cookies
    # -------------------------------------------------------------
    def _init_tab_headers(self):
        layout = QVBoxLayout(self.tab_headers)
        layout.setContentsMargins(6, 6, 6, 6)

        lbl_hdr = QLabel("Cabeçalhos HTTP de Resposta:")
        lbl_hdr.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_hdr)

        self.table_headers = QTableWidget()
        self.table_headers.setColumnCount(3)
        self.table_headers.setHorizontalHeaderLabels(["Status", "Cabeçalho", "Valor"])
        self.table_headers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_headers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.table_headers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_headers)

        lbl_ck = QLabel("Cookies do Navegador:")
        lbl_ck.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_ck)

        self.table_cookies = QTableWidget()
        self.table_cookies.setColumnCount(5)
        self.table_cookies.setHorizontalHeaderLabels(["Nome", "HttpOnly", "Secure", "SameSite", "Domínio"])
        self.table_cookies.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_cookies)

    # -------------------------------------------------------------
    # ABA 3: API Security Sentinel
    # -------------------------------------------------------------
    def _init_tab_api(self):
        layout = QVBoxLayout(self.tab_api)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Header com estatísticas de API
        api_header = QHBoxLayout()
        self.lbl_api_total = self._create_mini_badge("0 Chamadas Interceptadas", "#58a6ff")
        self.lbl_api_openapi = self._create_mini_badge("OpenAPI: Não detectada", "#8b949e")
        self.lbl_api_graphql = self._create_mini_badge("GraphQL: Inativo", "#8b949e")
        api_header.addWidget(self.lbl_api_total)
        api_header.addWidget(self.lbl_api_openapi)
        api_header.addWidget(self.lbl_api_graphql)
        api_header.addStretch()
        layout.addLayout(api_header)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Tabela de Chamadas Interceptadas
        self.table_api_calls = QTableWidget()
        self.table_api_calls.setColumnCount(4)
        self.table_api_calls.setHorizontalHeaderLabels(["Método", "Status", "Endpoint API", "Risco de Segurança"])
        self.table_api_calls.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_api_calls.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_api_calls.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_api_calls.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table_api_calls.itemSelectionChanged.connect(self._on_api_call_selected)
        splitter.addWidget(self.table_api_calls)

        # Inspector de Payload JSON / Detalhes de Risco
        preview_box = QFrame()
        preview_box.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
            }
        """)
        pv_layout = QVBoxLayout(preview_box)
        pv_layout.setContentsMargins(6, 6, 6, 6)
        pv_layout.setSpacing(4)

        lbl_pv = QLabel("🔍 Resposta JSON / Análise de Modelo (Excessive Data Exposure):")
        lbl_pv.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl_pv.setStyleSheet("color: #79c0ff;")
        pv_layout.addWidget(lbl_pv)

        self.txt_api_preview = QTextEdit()
        self.txt_api_preview.setReadOnly(True)
        self.txt_api_preview.setPlaceholderText("Selecione uma chamada de API acima para inspecionar headers, payloads e vazamentos de DTOs...")
        pv_layout.addWidget(self.txt_api_preview)

        splitter.addWidget(preview_box)
        splitter.setSizes([260, 220])
        layout.addWidget(splitter)

    # -------------------------------------------------------------
    # ABA 4: Vibe-Coding Scanner
    # -------------------------------------------------------------
    def _init_tab_vibe(self):
        layout = QVBoxLayout(self.tab_vibe)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        lbl_info = QLabel("🤖 Detector Especializado de Anti-Padrões de IA (Vibe Coding)")
        lbl_info.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        lbl_info.setStyleSheet("color: #e3b341;")
        layout.addWidget(lbl_info)

        desc = QLabel(
            "Analisa o código cliente gerado por modelos de linguagem procurando chaves de API expostas "
            "(OpenAI, Anthropic, Supabase), credenciais mock, flags 'isAdmin: true', tokens em localStorage "
            "e métodos vulneráveis como dangerouslySetInnerHTML."
        )
        desc.setStyleSheet("color: #8b949e; font-size: 11px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        self.vibe_tree = QTreeWidget()
        self.vibe_tree.setHeaderLabels(["Gravidade", "Problema de IA Detectado", "Evidência"])
        self.vibe_tree.header().resizeSection(0, 100)
        self.vibe_tree.header().resizeSection(1, 240)
        self.vibe_tree.itemDoubleClicked.connect(self._on_finding_double_clicked)
        layout.addWidget(self.vibe_tree)

    # -------------------------------------------------------------
    # ABA 4: Relatório
    # -------------------------------------------------------------
    def _init_tab_report(self):
        layout = QVBoxLayout(self.tab_report)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        btn_row = QHBoxLayout()

        btn_html = QPushButton("🌐 Exportar HTML")
        btn_html.clicked.connect(self._export_html)
        btn_row.addWidget(btn_html)

        btn_md = QPushButton("📝 Exportar Markdown")
        btn_md.clicked.connect(self._export_markdown)
        btn_row.addWidget(btn_md)

        btn_json = QPushButton("⚙️ Exportar JSON")
        btn_json.clicked.connect(self._export_json)
        btn_row.addWidget(btn_json)

        layout.addLayout(btn_row)

        self.txt_report_preview = QTextEdit()
        self.txt_report_preview.setReadOnly(True)
        self.txt_report_preview.setPlaceholderText("O resumo do relatório para exportação aparecerá aqui...")
        layout.addWidget(self.txt_report_preview)

    # -------------------------------------------------------------
    # Atualização de Dados
    # -------------------------------------------------------------
    def update_results(self, summary: Dict[str, Any]):
        self.current_summary = summary
        self.all_findings = summary.get("findings", [])
        score = summary.get("score", 100)
        grade = summary.get("grade", "A+")
        counts = summary.get("counts", {})
        context: Optional[AuditContext] = summary.get("context")

        # Atualiza Card de Score
        self.grade_label.setText(grade)
        grade_color = "#3fb950" if score >= 85 else ("#d29922" if score >= 70 else "#f85149")
        self.grade_label.setStyleSheet(f"""
            background-color: #0d1117;
            color: {grade_color};
            border: 2px solid {grade_color};
            border-radius: 30px;
        """)

        self.score_title.setText(f"Security Score: {score}/100")
        self.score_subtitle.setText(f"{len(self.all_findings)} vulnerabilidade(s) encontrada(s)")

        self.cnt_crit.setText(f"{counts.get('CRITICAL', 0)} Crit")
        self.cnt_high.setText(f"{counts.get('HIGH', 0)} Alt")
        self.cnt_med.setText(f"{counts.get('MEDIUM', 0)} Méd")
        self.cnt_low.setText(f"{counts.get('LOW', 0)} Bx")

        # Atualiza listas
        self._apply_filters()
        self._update_headers_and_cookies(context)
        self._update_api_tab(context)
        self._update_vibe_findings()
        self._update_report_preview()

    def _apply_filters(self):
        """Filtra a lista de achados com base no combo e busca."""
        self.tree_findings.clear()
        filter_idx = self.filter_combo.currentIndex()
        query = self.search_input.text().strip().lower()

        sev_map = {
            1: Severity.CRITICAL,
            2: Severity.HIGH,
            3: Severity.MEDIUM,
            4: Severity.LOW,
        }
        target_sev = sev_map.get(filter_idx)

        for f in self.all_findings:
            if target_sev and f.severity != target_sev:
                continue
            if query and (query not in f.title.lower() and query not in f.description.lower() and query not in f.id.lower()):
                continue

            item = QTreeWidgetItem([
                f.severity.label_pt,
                f.title,
                f.category.value
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            item.setForeground(0, QBrush(QColor(f.severity.color)))
            self.tree_findings.addTopLevelItem(item)

    def _update_vibe_findings(self):
        self.vibe_tree.clear()
        vibe_findings = [f for f in self.all_findings if f.category.name == "VIBE_CODING_PATTERNS" or f.vibe_coding_context]
        for f in vibe_findings:
            item = QTreeWidgetItem([
                f.severity.label_pt,
                f.title,
                f.evidence[:70] + "..." if len(f.evidence) > 70 else f.evidence
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            item.setForeground(0, QBrush(QColor(f.severity.color)))
            self.vibe_tree.addTopLevelItem(item)

    def _update_headers_and_cookies(self, context: Optional[AuditContext]):
        if not context:
            return

        # Cabeçalhos
        self.table_headers.setRowCount(0)
        important_headers = [
            ("Content-Security-Policy", "CSP anti-XSS"),
            ("Strict-Transport-Security", "HSTS HTTPS forçado"),
            ("X-Frame-Options", "Proteção Anti-Clickjacking"),
            ("X-Content-Type-Options", "Proteção Anti-MIME Sniffing"),
            ("Referrer-Policy", "Privacidade de Referrer"),
            ("Access-Control-Allow-Origin", "CORS Políticas de Origem"),
            ("Server", "Vazamento de Banner"),
            ("X-Powered-By", "Vazamento de Framework"),
        ]

        headers_lower = {k.lower(): v for k, v in context.headers.items()}
        row = 0

        # Mostra primeiro os cabeçalhos de segurança checados
        for h_name, h_desc in important_headers:
            val = headers_lower.get(h_name.lower())
            self.table_headers.insertRow(row)
            if val:
                status_item = QTableWidgetItem("✅ PRESENTE")
                status_item.setForeground(QBrush(QColor("#3fb950")))
                val_item = QTableWidgetItem(val)
            else:
                if h_name in ["Server", "X-Powered-By"]:
                    status_item = QTableWidgetItem("✅ OCULTO")
                    status_item.setForeground(QBrush(QColor("#3fb950")))
                    val_item = QTableWidgetItem("Não emitido (Bom)")
                else:
                    status_item = QTableWidgetItem("❌ AUSENTE")
                    status_item.setForeground(QBrush(QColor("#f85149")))
                    val_item = QTableWidgetItem(f"Recomendado para segurança ({h_desc})")

            name_item = QTableWidgetItem(h_name)
            self.table_headers.setItem(row, 0, status_item)
            self.table_headers.setItem(row, 1, name_item)
            self.table_headers.setItem(row, 2, val_item)
            row += 1

        # Outros cabeçalhos recebidos
        for k, v in context.headers.items():
            if k.lower() in [ih[0].lower() for ih in important_headers]:
                continue
            self.table_headers.insertRow(row)
            self.table_headers.setItem(row, 0, QTableWidgetItem("ℹ️ INFO"))
            self.table_headers.setItem(row, 1, QTableWidgetItem(k))
            self.table_headers.setItem(row, 2, QTableWidgetItem(v))
            row += 1

        # Cookies
        self.table_cookies.setRowCount(0)
        for c_idx, cookie in enumerate(context.cookies):
            self.table_cookies.insertRow(c_idx)
            name = cookie.get("name", "")
            http_only = "✅ Sim" if cookie.get("httpOnly") else "❌ Não (Inseguro)"
            secure = "✅ Sim" if cookie.get("secure") else "❌ Não"
            same_site = str(cookie.get("sameSite", "Não especificado"))
            domain = str(cookie.get("domain", ""))

            self.table_cookies.setItem(c_idx, 0, QTableWidgetItem(name))
            
            ho_item = QTableWidgetItem(http_only)
            ho_item.setForeground(QBrush(QColor("#3fb950" if cookie.get("httpOnly") else "#f85149")))
            self.table_cookies.setItem(c_idx, 1, ho_item)

            sec_item = QTableWidgetItem(secure)
            sec_item.setForeground(QBrush(QColor("#3fb950" if cookie.get("secure") else "#f0883e")))
            self.table_cookies.setItem(c_idx, 2, sec_item)

            self.table_cookies.setItem(c_idx, 3, QTableWidgetItem(same_site))
            self.table_cookies.setItem(c_idx, 4, QTableWidgetItem(domain))

    def _update_report_preview(self):
        md = ReportGenerator.generate_markdown(self.current_summary)
        self.txt_report_preview.setPlainText(md)

    def _on_finding_selected(self):
        items = self.tree_findings.selectedItems()
        if not items:
            return
        finding: Optional[AuditFinding] = items[0].data(0, Qt.ItemDataRole.UserRole)
        if finding:
            self.preview_title.setText(f"[{finding.severity.label_pt}] {finding.title}")
            text = (
                f"ID: {finding.id}\n"
                f"Categoria: {finding.category.value}\n\n"
                f"Descrição:\n{finding.description}\n\n"
                f"Evidência:\n{finding.evidence}\n\n"
                f"Como Corrigir:\n{finding.remediation}\n\n"
            )
            if finding.vibe_coding_context:
                text += f"💡 Contexto Vibe Coding:\n{finding.vibe_coding_context}\n"
            self.preview_text.setPlainText(text)

    def _on_finding_double_clicked(self, item: QTreeWidgetItem, column: int):
        finding: Optional[AuditFinding] = item.data(0, Qt.ItemDataRole.UserRole)
        if finding:
            dlg = FindingDetailDialog(finding, self)
            dlg.exec()

    def _update_api_tab(self, context: Optional[AuditContext]):
        if not context:
            return

        api_calls = getattr(context, "api_calls", [])
        self.lbl_api_total.setText(f"{len(api_calls)} Chamadas Interceptadas")

        # Atualiza status do OpenAPI
        has_openapi = any("OPENAPI" in f.id or "SWAGGER" in f.id for f in self.all_findings)
        if has_openapi:
            self.lbl_api_openapi.setText("OpenAPI: Detectada ⚠️")
            self.lbl_api_openapi.setStyleSheet("background-color: #d2992222; color: #d29922; border: 1px solid #d29922; border-radius: 4px; font-size: 10px; font-weight: bold; padding: 2px 6px;")
        else:
            self.lbl_api_openapi.setText("OpenAPI: Oculta / Segura")
            self.lbl_api_openapi.setStyleSheet("background-color: #23863622; color: #3fb950; border: 1px solid #238636; border-radius: 4px; font-size: 10px; font-weight: bold; padding: 2px 6px;")

        # Atualiza status do GraphQL
        has_graphql_leak = any("GRAPHQL" in f.id for f in self.all_findings)
        if has_graphql_leak:
            self.lbl_api_graphql.setText("GraphQL Introspection: ATIVA 🔴")
            self.lbl_api_graphql.setStyleSheet("background-color: #f8514922; color: #f85149; border: 1px solid #f85149; border-radius: 4px; font-size: 10px; font-weight: bold; padding: 2px 6px;")
        else:
            self.lbl_api_graphql.setText("GraphQL: Seguro")
            self.lbl_api_graphql.setStyleSheet("background-color: #23863622; color: #3fb950; border: 1px solid #238636; border-radius: 4px; font-size: 10px; font-weight: bold; padding: 2px 6px;")

        # Preenche tabela de chamadas de API
        self.table_api_calls.setRowCount(0)
        sensitive_keywords = ["password", "hash", "salt", "secret", "cpf", "ssn", "credit_card", "token"]

        for idx, call in enumerate(api_calls):
            self.table_api_calls.insertRow(idx)
            method = call.get("method", "GET").upper()
            status = str(call.get("status", 200))
            url = call.get("url", "")
            response = str(call.get("response", ""))

            # Determina risco da chamada
            risk_label = "✅ Normal"
            risk_color = "#3fb950"

            leaked = [k for k in sensitive_keywords if f'"{k}"' in response.lower() or f"'{k}'" in response.lower()]
            if leaked:
                risk_label = f"🔴 Vazamento PII/Hash ({', '.join(leaked[:2])})"
                risk_color = "#f85149"
            elif int(status) >= 500:
                risk_label = "⚠️ Erro 500 (Potencial Stack Trace)"
                risk_color = "#f0883e"
            elif "api" in url.lower() and not any(h in str(call.get("headers", {})).lower() for h in ["ratelimit", "retry-after"]):
                risk_label = "🟡 Sem Rate Limit"
                risk_color = "#d29922"

            item_method = QTableWidgetItem(method)
            item_status = QTableWidgetItem(status)
            item_url = QTableWidgetItem(url)
            item_risk = QTableWidgetItem(risk_label)
            item_risk.setForeground(QBrush(QColor(risk_color)))

            # Guarda o objeto de chamada para o preview
            item_url.setData(Qt.ItemDataRole.UserRole, call)

            self.table_api_calls.setItem(idx, 0, item_method)
            self.table_api_calls.setItem(idx, 1, item_status)
            self.table_api_calls.setItem(idx, 2, item_url)
            self.table_api_calls.setItem(idx, 3, item_risk)

    def _on_api_call_selected(self):
        items = self.table_api_calls.selectedItems()
        if not items:
            return
        row = items[0].row()
        url_item = self.table_api_calls.item(row, 2)
        if not url_item:
            return

        call = url_item.data(Qt.ItemDataRole.UserRole)
        if not call:
            return

        url = call.get("url", "")
        method = call.get("method", "GET")
        status = call.get("status", 200)
        res_text = str(call.get("response", ""))

        formatted_json = res_text
        try:
            parsed = json.loads(res_text)
            formatted_json = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            pass

        info = [
            f"=== CHAMADA INTERCEPTADA: {method} {url} (HTTP {status}) ===",
            f"Timestamp: {call.get('timestamp', 'N/A')}",
            f"\n--- Resposta (Payload JSON / DTO): ---",
            formatted_json[:4000]
        ]
        self.txt_api_preview.setPlainText("\n".join(info))

    # -------------------------------------------------------------
    # Exportações
    # -------------------------------------------------------------
    def _export_markdown(self):
        if not self.current_summary:
            QMessageBox.warning(self, "Aviso", "Nenhuma auditoria realizada ainda.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Markdown", "relatorio_seguranca.md", "Markdown (*.md)")
        if path:
            content = ReportGenerator.generate_markdown(self.current_summary)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Sucesso", f"Relatório salvo com sucesso em:\n{path}")

    def _export_html(self):
        if not self.current_summary:
            QMessageBox.warning(self, "Aviso", "Nenhuma auditoria realizada ainda.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório HTML", "relatorio_seguranca.html", "HTML (*.html)")
        if path:
            content = ReportGenerator.generate_html(self.current_summary)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Sucesso", f"Relatório HTML salvo com sucesso em:\n{path}")

    def _export_json(self):
        if not self.current_summary:
            QMessageBox.warning(self, "Aviso", "Nenhuma auditoria realizada ainda.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório JSON", "relatorio_seguranca.json", "JSON (*.json)")
        if path:
            content = ReportGenerator.generate_json(self.current_summary)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Sucesso", f"Relatório JSON salvo com sucesso em:\n{path}")
