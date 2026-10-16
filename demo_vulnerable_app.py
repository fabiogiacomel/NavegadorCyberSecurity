"""
Servidor Web de Testes com Falhas Típicas de Vibe Coding & OWASP Top 10 + OWASP API Security.
Utiliza apenas a biblioteca padrão do Python (sem dependências externas).
Porta padrão: 5050 (http://localhost:5050).

Permite testar e validar o Navegador CyberSecurity e o módulo API Sentinel.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys


class VulnerableTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 1. ROTA DE API: Especificação OpenAPI Exposta (/openapi.json)
        if self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            spec = {
                "openapi": "3.0.2",
                "info": {"title": "Vibe Coding Internal API", "version": "1.0.0"},
                "paths": {
                    "/api/users": {
                        "get": {"summary": "List all users"}
                    },
                    "/api/admin/reset-db": {
                        "post": {"summary": "Reset database without auth"}
                    },
                    "/api/users/{id}": {
                        "delete": {"summary": "Delete user by ID"}
                    }
                }
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))
            return

        # 2. ROTA DE API: Excessive Data Exposure (/api/users)
        if self.path == "/api/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            # Propositalmente SEM cabeçalhos de Rate Limiting
            self.end_headers()
            users_payload = [
                {
                    "id": 1,
                    "name": "Administrador do Sistema",
                    "email": "admin@empresa.com.br",
                    "password_hash": "$2b$12$e8Y5fakepasswordhashvibeai1234567890abcdef",
                    "salt": "3f8a92bc10de",
                    "role": "superadmin",
                    "is_admin": True,
                    "cpf": "123.456.789-00",
                    "credit_card": "4111-XXXX-XXXX-1111"
                },
                {
                    "id": 2,
                    "name": "Usuario Comum",
                    "email": "usuario@empresa.com.br",
                    "password_hash": "$2b$12$k9L2fakeuserpasswordhash9988776655443322",
                    "salt": "a1b2c3d4e5f6",
                    "role": "user",
                    "is_admin": False
                }
            ]
            self.wfile.write(json.dumps(users_payload).encode("utf-8"))
            return

        # 3. ROTA DE API: Vazamento de Stack Trace (/api/debug)
        if self.path == "/api/debug":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            error_payload = {
                "error": "InternalServerError",
                "message": "SequelizeDatabaseError: syntax error at or near 'SELECT'",
                "stack": "Traceback (most recent call last):\n  File 'server.py', line 88, in query\n  File 'db.py', line 12, in execute\nSequelizeDatabaseError: connection pool exhausted"
            }
            self.wfile.write(json.dumps(error_payload).encode("utf-8"))
            return

        # 4. PÁGINA PRINCIPAL HTML
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "VibeServer/2.4.1 (Ubuntu)")
        self.send_header("X-Powered-By", "Express/4.18.2")
        self.send_header("Access-Control-Allow-Origin", "*")  # CORS Wildcard
        self.send_header("Set-Cookie", "session_id=vibe_session_998877; Path=/")
        self.end_headers()

        html_content = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>AI Vibe App — Demonstração de Auditoria Completa</title>
    <!-- Script de CDN externa sem integridade (SRI) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }
        .card { background: #1e293b; padding: 24px; border-radius: 12px; max-width: 800px; margin: 0 auto; box-shadow: 0 4px 14px rgba(0,0,0,0.4); border: 1px solid #334155; }
        h1 { color: #38bdf8; margin-top: 0; }
        .alert { background: #7f1d1d; border-left: 4px solid #ef4444; padding: 14px; margin: 16px 0; border-radius: 6px; }
        .api-box { background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-top: 14px; }
        input, button { padding: 10px; margin: 6px 0; width: 100%; box-sizing: border-box; border-radius: 6px; }
        button { background: #2563eb; color: white; border: none; font-weight: bold; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .btn-api { background: #059669; }
        .btn-api:hover { background: #047857; }
        pre { background: #020617; padding: 10px; border-radius: 6px; color: #7dd3fc; font-size: 12px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🚀 Aplicação de Teste (Vibe Coding & API Sentinel)</h1>
        <p>Esta aplicação demonstra em tempo real as principais falhas do <strong>OWASP Top 10 Web</strong> e <strong>OWASP API Security Top 10:2023</strong>.</p>
        
        <div class="alert">
            ⚠️ <strong>Falhas Ativas:</strong> OpenAPI público (/openapi.json), GraphQL Introspection (/graphql), Excessive Data Exposure (/api/users), ausência de Rate Limiting, Vazamento de Stack Trace (/api/debug), Chave OpenAI no cliente, JWT em LocalStorage e falta de CSP.
        </div>

        <div class="api-box">
            <h3>🔌 Teste das APIs Vulneráveis (Interceptadas pelo Navegador):</h3>
            <button class="btn-api" onclick="chamarApiUsuarios()">Chamar GET /api/users (Vazamento de Hashes/PII)</button>
            <button class="btn-api" style="background: #dc2626;" onclick="chamarApiDebug()">Chamar GET /api/debug (Vazamento de Stack Trace)</button>
            <div id="api-output" style="margin-top: 10px;"></div>
        </div>

        <h3>Formulário de Transferência / Ação (Sem CSRF):</h3>
        <form action="/api/transfer" method="POST">
            <input type="text" name="recipient" placeholder="Destinatário" value="usuario_destino">
            <input type="text" name="amount" placeholder="Valor (R$)" value="1500.00">
            <button type="submit">Transferir Fundos</button>
        </form>

        <h3>Área de Mensagens Dinâmicas (DOM XSS Sink):</h3>
        <div id="user-display">Aguardando dados...</div>

        <p><a href="/admin/dashboard" style="color: #38bdf8;">Ir para Painel Administrativo (/admin/dashboard)</a></p>
    </div>

    <!-- Scripts simulando código gerado por IA -->
    <script>
        // 1. VAZAMENTO VIBE CODING: Chave de API de IA colocada no cliente
        const OPENAI_API_KEY = "sk-proj-DEMO1234567890abcdef1234567890abcdef1234567890abcdef";
        const ADMIN_SECRET = "password: 'admin123'";
        const is_admin = true;

        // 2. FALHA A07: JWT armazenado em localStorage em vez de HttpOnly cookie
        localStorage.setItem("auth_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMzg0IiwibmFtZSI6IkFkbWluIn0.fake_signature_vibe_coding_demo");
        localStorage.setItem("user_role", "superuser");

        // 3. FALHA A03: Manipulação insegura do DOM com innerHTML
        const params = new URLSearchParams(window.location.search);
        const userName = params.get("name") || "<b>Usuário Convidado</b>";
        document.getElementById("user-display").innerHTML = "Olá, " + userName;

        // 4. FALHA A03: Uso de eval()
        try {
            eval("console.log('Ambiente de debug carregado')");
        } catch(e) {}

        // 5. Chamadas de API automáticas para o Sentinel interceptar
        async function chamarApiUsuarios() {
            const res = await fetch("/api/users");
            const data = await res.json();
            document.getElementById("api-output").innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
        }

        async function chamarApiDebug() {
            try {
                const res = await fetch("/api/debug");
                const data = await res.json();
                document.getElementById("api-output").innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
            } catch(e) {}
        }

        // Dispara requisições iniciais para popular o Sentinel automaticamente
        chamarApiUsuarios();
    </script>
</body>
</html>
        """
        self.wfile.write(html_content.encode("utf-8"))

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "VibeServer/2.4.1 (Ubuntu)")
        self.end_headers()

    def do_POST(self):
        # Suporte a GraphQL Introspection (/graphql)
        if self.path in ["/graphql", "/api/graphql"]:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Se for uma consulta de introspecção GraphQL
            if "__schema" in post_data:
                graphql_res = {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {"name": "Query"},
                                {"name": "User"},
                                {"name": "AdminSecret"},
                                {"name": "Mutation"}
                            ]
                        }
                    }
                }
                self.wfile.write(json.dumps(graphql_res).encode("utf-8"))
            else:
                self.wfile.write(json.dumps({"data": {"status": "ok"}}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Acao executada com sucesso")

    def log_message(self, format, *args):
        # Log simplificado
        sys.stderr.write(f"[DemoServer] {self.address_string()} - {format % args}\n")


def run_demo_server(port=5050):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, VulnerableTestHandler)
    print(f"\n" + "="*65)
    print(f"🔥 Servidor de Demonstração Vibe Coding & API Sentinel ATIVO!")
    print(f"👉 URL: http://localhost:{port}")
    print(f"Rotas de API Ativas:")
    print(f"  - GET  http://localhost:{port}/openapi.json   (OpenAPI Spec)")
    print(f"  - GET  http://localhost:{port}/api/users      (Excessive Data Exposure)")
    print(f"  - GET  http://localhost:{port}/api/debug      (Stack Trace Leak)")
    print(f"  - POST http://localhost:{port}/graphql        (GraphQL Introspection)")
    print(f"Abra esta URL no Navegador CyberSecurity para auditar.")
    print(f"Pressione Ctrl+C para encerrar o servidor.")
    print("="*65 + "\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5050
    run_demo_server(port)
