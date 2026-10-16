"""
Estilos visuais Cyber Dark (QSS) para o Navegador CyberSecurity.
Tema moderno, escuro, inspirado em ferramentas profissionais como Burp Suite, DevTools e GitHub Dark.
"""

CYBER_DARK_QSS = """
/* Reset Global */
QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}

/* Janela Principal e Splitter */
QMainWindow {
    background-color: #0d1117;
}

QSplitter::handle {
    background-color: #21262d;
    width: 3px;
}

QSplitter::handle:hover {
    background-color: #58a6ff;
}

/* Barra de Ferramentas e Navegação */
QToolBar {
    background-color: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 6px 12px;
    spacing: 8px;
}

/* Barra de Endereço (URL) */
QLineEdit {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 13px;
    selection-background-color: #1f6feb;
}

QLineEdit:focus {
    border: 1px solid #58a6ff;
    background-color: #161b22;
}

/* Botões */
QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #363b42;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #161b22;
}

QPushButton#btn_audit {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    font-weight: 600;
}

QPushButton#btn_audit:hover {
    background-color: #2ea043;
    border-color: #3fb950;
}

QPushButton#btn_nav {
    background-color: transparent;
    border: none;
    font-size: 15px;
    padding: 6px 10px;
    border-radius: 6px;
}

QPushButton#btn_nav:hover {
    background-color: #21262d;
    color: #58a6ff;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #161b22;
    border-radius: 6px;
    top: -1px;
}

QTabBar::tab {
    background-color: #0d1117;
    color: #8b949e;
    border: 1px solid #30363d;
    border-bottom: none;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
}

QTabBar::tab:selected {
    background-color: #161b22;
    color: #58a6ff;
    border-top: 2px solid #58a6ff;
    border-bottom: 1px solid #161b22;
}

QTabBar::tab:hover:!selected {
    background-color: #161b22;
    color: #c9d1d9;
}

/* Tabelas e Árvores */
QTableWidget, QTreeWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    gridline-color: #21262d;
    outline: none;
}

QTableWidget::item, QTreeWidget::item {
    padding: 8px 6px;
    border-bottom: 1px solid #161b22;
}

QTableWidget::item:selected, QTreeWidget::item:selected {
    background-color: #1f6feb22;
    color: #58a6ff;
    border-left: 3px solid #58a6ff;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    border-bottom: 1px solid #30363d;
    border-right: 1px solid #21262d;
    padding: 6px 10px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
}

/* Caixas de Texto Monospace / Detalhes */
QTextEdit, QPlainTextEdit {
    background-color: #090d12;
    color: #79c0ff;
    border: 1px solid #30363d;
    border-radius: 6px;
    font-family: Consolas, "Courier New", monospace;
    font-size: 12px;
    padding: 8px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0d1117;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #30363d;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #8b949e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #0d1117;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background: #30363d;
    min-width: 20px;
    border-radius: 4px;
}

/* Status Bar */
QStatusBar {
    background-color: #161b22;
    border-top: 1px solid #30363d;
    color: #8b949e;
    padding: 4px 10px;
    font-size: 11px;
}

/* ComboBox */
QComboBox {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 5px 12px;
    color: #c9d1d9;
}

QComboBox:hover {
    border-color: #8b949e;
}

QComboBox::drop-down {
    border: none;
}

QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
    outline: none;
}
"""
