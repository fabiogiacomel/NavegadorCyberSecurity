"""
Configurações e constantes do Navegador CyberSecurity.
"""

APP_NAME = "CyberSecurity Browser"
APP_SUBTITLE = "Vibe Coding & OWASP Top 10 Auditor"
APP_VERSION = "1.0.0"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberAuditBrowser/1.0"

# Portas de desenvolvimento comuns para atalhos
DEV_PORTS = [
    {"name": "React / Next.js", "port": 3000},
    {"name": "Vite / Vue / Svelte", "port": 5173},
    {"name": "Flask / Python", "port": 5000},
    {"name": "FastAPI / Django", "port": 8000},
    {"name": "Angular", "port": 4200},
]

# Configurações de Auditoria
AUDIT_TIMEOUT_SECONDS = 5
MAX_LOG_ENTRIES = 100
