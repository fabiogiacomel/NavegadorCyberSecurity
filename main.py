"""
Ponto de entrada do Navegador CyberSecurity.
Executa a aplicação PyQt6 e inicia o motor Chromium e de auditoria.
"""

import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QUrl

# Garante que o diretório raiz esteja no path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.browser_window import CyberSecurityBrowserWindow
from config import APP_NAME, APP_VERSION


def main():
    # Habilita atributos de renderização de alto DPI
    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    window = CyberSecurityBrowserWindow()

    # Se uma URL foi passada por linha de comando, navega até ela
    if len(sys.argv) > 1:
        initial_url = sys.argv[1]
        if not initial_url.startswith("http://") and not initial_url.startswith("https://"):
            if initial_url.isdigit():
                initial_url = f"http://localhost:{initial_url}"
            else:
                initial_url = f"https://{initial_url}"
        window.url_bar.setText(initial_url)
        window.web_view.setUrl(QUrl(initial_url))

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
