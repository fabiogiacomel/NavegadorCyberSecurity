"""
Modal de Detalhes da Vulnerabilidade.
Exibe informações aprofundadas, evidência em bloco de código, remediação e dicas de vibe coding.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QFrame, QApplication
)
from PyQt6.QtCore import Qt
from modules.base import AuditFinding


class FindingDetailDialog(QDialog):
    def __init__(self, finding: AuditFinding, parent=None):
        super().__init__(parent)
        self.finding = finding
        self.setWindowTitle(f"Auditoria: {finding.title}")
        self.resize(750, 600)
        self.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
                color: #c9d1d9;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header com badges
        header_layout = QHBoxLayout()
        
        badge_sev = QLabel(f" {finding.severity.label_pt} ")
        badge_sev.setStyleSheet(f"""
            background-color: {finding.severity.color}22;
            color: {finding.severity.color};
            border: 1px solid {finding.severity.color};
            border-radius: 4px;
            font-weight: bold;
            padding: 4px 8px;
        """)
        header_layout.addWidget(badge_sev)

        lbl_id = QLabel(f"ID: {finding.id}")
        lbl_id.setStyleSheet("color: #8b949e; font-family: monospace;")
        header_layout.addWidget(lbl_id)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Título
        lbl_title = QLabel(finding.title)
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        lbl_title.setWordWrap(True)
        layout.addWidget(lbl_title)

        # Categoria OWASP
        lbl_cat = QLabel(f"🛡️ Categoria: {finding.category.value}")
        lbl_cat.setStyleSheet("color: #58a6ff; font-weight: 500;")
        layout.addWidget(lbl_cat)

        # Separador
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #30363d;")
        layout.addWidget(line)

        # Descrição
        lbl_desc_title = QLabel("Descrição do Risco:")
        lbl_desc_title.setStyleSheet("font-weight: bold; color: #e6edf3;")
        layout.addWidget(lbl_desc_title)

        lbl_desc = QLabel(finding.description)
        lbl_desc.setStyleSheet("color: #adbac7; line-height: 1.4;")
        lbl_desc.setWordWrap(True)
        layout.addWidget(lbl_desc)

        # Evidência
        lbl_ev_title = QLabel("Evidência / Código Identificado:")
        lbl_ev_title.setStyleSheet("font-weight: bold; color: #e6edf3;")
        layout.addWidget(lbl_ev_title)

        txt_evidence = QTextEdit()
        txt_evidence.setReadOnly(True)
        txt_evidence.setPlainText(finding.evidence)
        txt_evidence.setMaximumHeight(110)
        layout.addWidget(txt_evidence)

        # Remediação / Como Corrigir
        lbl_rem_title = QLabel("✅ Como Corrigir (Remediação de Segurança):")
        lbl_rem_title.setStyleSheet("font-weight: bold; color: #3fb950;")
        layout.addWidget(lbl_rem_title)

        txt_remediation = QTextEdit()
        txt_remediation.setReadOnly(True)
        txt_remediation.setPlainText(finding.remediation)
        txt_remediation.setStyleSheet("""
            background-color: #041a0d;
            border: 1px solid #238636;
            color: #7ee787;
        """)
        txt_remediation.setMaximumHeight(90)
        layout.addWidget(txt_remediation)

        # Dica Vibe Coding
        if finding.vibe_coding_context:
            lbl_vibe_title = QLabel("💡 Dica para Auditoria de Vibe Coding (Código gerado por IA):")
            lbl_vibe_title.setStyleSheet("font-weight: bold; color: #d29922;")
            layout.addWidget(lbl_vibe_title)

            lbl_vibe = QLabel(finding.vibe_coding_context)
            lbl_vibe.setStyleSheet("""
                background-color: #271f0c;
                border: 1px solid #9e6a03;
                border-radius: 6px;
                padding: 10px;
                color: #e3b341;
            """)
            lbl_vibe.setWordWrap(True)
            layout.addWidget(lbl_vibe)

        # Botões inferiores
        btn_layout = QHBoxLayout()
        btn_copy = QPushButton("📋 Copiar Detalhes")
        btn_copy.clicked.connect(self._copy_details)
        btn_layout.addWidget(btn_copy)

        btn_layout.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def _copy_details(self):
        text = (
            f"Vulnerabilidade: {self.finding.title}\n"
            f"Severidade: {self.finding.severity.label_pt}\n"
            f"Categoria: {self.finding.category.value}\n"
            f"Evidência: {self.finding.evidence}\n"
            f"Remediação: {self.finding.remediation}\n"
        )
        QApplication.clipboard().setText(text)
