"""
Testes unitários dos módulos de auditoria de segurança e do motor de cálculo.
"""

import json
import unittest
from modules.base import AuditContext, Severity, OwaspCategory
from modules.a05_misconfiguration import SecurityMisconfigurationModule
from modules.a07_auth_failures import AuthAndSessionFailuresModule
from modules.a03_injection import InjectionAndDomXssModule
from modules.vibe_coding_leaks import VibeCodingLeaksModule
from modules.a02_crypto_failures import CryptographicFailuresModule
from modules.a08_integrity import SoftwareIntegrityModule
from modules.a01_broken_access import BrokenAccessControlModule
from core.audit_engine import AuditEngine
from core.report_generator import ReportGenerator


class TestSecurityModules(unittest.TestCase):
    def test_a05_missing_csp_and_clickjacking(self):
        mod = SecurityMisconfigurationModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            headers={"Server": "nginx/1.18.0"}  # Sem CSP, sem X-Frame-Options
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A05-CSP-MISSING", ids)
        self.assertIn("SEC-A05-CLICKJACKING-MISSING", ids)
        self.assertIn("SEC-A05-TECH-DISCLOSURE-HEADERS", ids)

    def test_a05_hsts_validation(self):
        mod = SecurityMisconfigurationModule()
        # HSTS fraco (max-age menor que 1 ano)
        ctx_weak = AuditContext(
            url="https://app-teste.com",
            headers={"Strict-Transport-Security": "max-age=300"}
        )
        findings = mod.run(ctx_weak)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A05-HSTS-WEAK", ids)

        # HSTS robusto
        ctx_strong = AuditContext(
            url="https://app-teste.com",
            headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
        )
        findings_strong = mod.run(ctx_strong)
        ids_strong = [f.id for f in findings_strong]
        self.assertNotIn("SEC-A05-HSTS-MISSING", ids_strong)
        self.assertNotIn("SEC-A05-HSTS-WEAK", ids_strong)

    def test_a05_csp_permissive_and_fallback(self):
        mod = SecurityMisconfigurationModule()
        # CSP permissivo
        ctx_permissive = AuditContext(
            url="https://app-teste.com",
            headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' *"}
        )
        findings = mod.run(ctx_permissive)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A05-CSP-PERMISSIVE", ids)

        # CSP declarado via meta tag HTML
        ctx_meta = AuditContext(
            url="https://app-teste.com",
            headers={},
            html="<meta http-equiv='Content-Security-Policy' content=\"default-src 'self'\">"
        )
        findings_meta = mod.run(ctx_meta)
        ids_meta = [f.id for f in findings_meta]
        self.assertNotIn("SEC-A05-CSP-MISSING", ids_meta)

    def test_a05_cors_critical_and_wildcard(self):
        mod = SecurityMisconfigurationModule()
        # CORS crítico: wildcard + credentials: true
        ctx_crit = AuditContext(
            url="https://app-teste.com",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"
            }
        )
        findings_crit = mod.run(ctx_crit)
        ids_crit = [f.id for f in findings_crit]
        self.assertIn("SEC-A05-CORS-CRITICAL-MISCONFIG", ids_crit)

        # CORS wildcard comum (sem credentials)
        ctx_wildcard = AuditContext(
            url="https://app-teste.com",
            headers={"Access-Control-Allow-Origin": "*"}
        )
        findings_wc = mod.run(ctx_wildcard)
        ids_wc = [f.id for f in findings_wc]
        self.assertIn("SEC-A05-CORS-WILDCARD", ids_wc)

    def test_a05_debug_traces_exposed(self):
        mod = SecurityMisconfigurationModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            html="""
            <div>
                <h1>Error 500</h1>
                <pre>Traceback (most recent call last):
                  File 'app.py', line 42, in get
                ZeroDivisionError: division by zero</pre>
            </div>
            """
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A05-DEBUG-STACK-TRACE-EXPOSED", ids)

    def test_a07_auth_storage_and_cookies(self):
        mod = AuthAndSessionFailuresModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            cookies=[
                {"name": "sessionid", "value": "12345", "httpOnly": False, "secure": True}
            ],
            local_storage={
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_store_me_in_localstorage"
            }
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        # Cookie sem httpOnly
        self.assertTrue(any("SEC-A07-COOKIE-NO-HTTPONLY" in i for i in ids))
        # JWT em localStorage
        self.assertTrue(any("SEC-A07-STORAGE-TOKEN-EXPOSURE" in i for i in ids))

    def test_a03_dom_sinks_and_csrf(self):
        mod = InjectionAndDomXssModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            html="""
            <html>
                <body>
                    <form action="/login" method="POST">
                        <input type="text" name="user">
                        <input type="password" name="pass">
                    </form>
                </body>
            </html>
            """,
            scripts=[
                "function render(data) { document.getElementById('target').innerHTML = data; eval(data); }"
            ]
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A03-DOM-XSS-SINKS", ids)
        self.assertIn("SEC-A03-DYNAMIC-CODE-EVAL", ids)
        self.assertTrue(any("SEC-A03-FORM-MISSING-CSRF" in i for i in ids))

    def test_a03_static_innerhtml_no_false_positive(self):
        mod = InjectionAndDomXssModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            scripts=[
                'element.innerHTML = "";',
                'element.innerHTML = "<b>Carregando dados estáticos...</b>";'
            ]
        )
        findings = mod.run(ctx)
        dom_findings = [f for f in findings if f.id == "SEC-A03-DOM-XSS-SINKS"]
        self.assertEqual(len(dom_findings), 0)

    def test_a03_framework_xss_and_javascript_uri(self):
        mod = InjectionAndDomXssModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            html="""
            <html>
                <body>
                    <a href="javascript:executePayload(1)">Exploit Link</a>
                    <a href="javascript:void(0)">Ignored Safe Link</a>
                </body>
            </html>
            """,
            scripts=[
                'const comp = <div dangerouslySetInnerHTML={{ __html: userBio }} />;'
            ]
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A03-DOM-XSS-SINKS", ids)

    def test_a03_insecure_postmessage(self):
        mod = InjectionAndDomXssModule()
        # Sem checar event.origin
        ctx_vuln = AuditContext(
            url="https://app-teste.com",
            scripts=[
                "window.addEventListener('message', (event) => { updateDom(event.data); });"
            ]
        )
        findings_vuln = mod.run(ctx_vuln)
        ids_vuln = [f.id for f in findings_vuln]
        self.assertIn("SEC-A03-INSECURE-POSTMESSAGE", ids_vuln)

        # Com checagem segura de origin
        ctx_safe = AuditContext(
            url="https://app-teste.com",
            scripts=[
                "window.addEventListener('message', (event) => { if (event.origin !== 'https://api.com') return; updateDom(event.data); });"
            ]
        )
        findings_safe = mod.run(ctx_safe)
        ids_safe = [f.id for f in findings_safe]
        self.assertNotIn("SEC-A03-INSECURE-POSTMESSAGE", ids_safe)

    def test_a03_query_interpolation(self):
        mod = InjectionAndDomXssModule()
        ctx = AuditContext(
            url="https://app-teste.com",
            scripts=[
                'const q = `query { user(id: ${userId}) { name } }`;',
                'const s = `SELECT * FROM users WHERE id = ${id}`;'
            ]
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A03-CLIENT-QUERY-INTERPOLATION", ids)

    def test_a03_reflected_params_in_script(self):
        mod = InjectionAndDomXssModule()
        ctx = AuditContext(
            url="https://app-teste.com?search=payload123&page=1",
            html="<script>const currentFilter = 'payload123'; const page = 1;</script>"
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A03-REFLECTED-PARAM-IN-SCRIPT", ids)

    def test_vibe_coding_openai_key_leak(self):
        mod = VibeCodingLeaksModule()
        mock_openai_key = "sk-proj-abc123xyz45678901234567890abcdef1234567890abcdef"
        ctx = AuditContext(
            url="https://app-teste.com",
            html=f"<script>const OPENAI_KEY = '{mock_openai_key}';</script>"
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertTrue(any("VIBE-SECRET-OPENAI-KEY" in i for i in ids))
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertGreaterEqual(len(critical_findings), 1)

    def test_api_security_sentinel_module(self):
        from modules.api_security_auditor import ApiSecurityAuditorModule
        mod = ApiSecurityAuditorModule()
        ctx = AuditContext(
            url="https://api-app.com",
            html="<script>const SEED_URL = '/api/seed';</script>",
            api_calls=[
                {
                    "url": "https://api-app.com/api/users",
                    "method": "GET",
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "response": json.dumps([
                        {"id": 1, "name": "Admin", "password_hash": "$2b$fakehash", "salt": "123", "cpf": "000.111.222-33"}
                    ])
                },
                {
                    "url": "https://api-app.com/api/debug",
                    "method": "GET",
                    "status": 500,
                    "headers": {"Content-Type": "application/json"},
                    "response": "Traceback (most recent call last):\n  File 'server.py', in query\nSequelizeDatabaseError"
                }
            ]
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("API-A03-EXCESSIVE-DATA-EXPOSURE", ids)
        self.assertIn("API-A04-NO-RATE-LIMITING", ids)
        self.assertIn("API-A08-DEBUG-STACK-TRACE-LEAK", ids)
        self.assertIn("API-VIBE-DEV-ENDPOINT", ids)

    def test_audit_engine_scoring_and_report(self):
        engine = AuditEngine()
        ctx = AuditContext(
            url="https://vulnerable-ai-app.com",
            headers={"Server": "Express"},
            html="<script>const apiKey = 'sk-proj-01234567890123456789012345678901234567890123456789';</script>",
            local_storage={"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxfQ.sig"}
        )
        summary = engine.run_audit(ctx)
        self.assertIn("score", summary)
        self.assertIn("grade", summary)
        self.assertLess(summary["score"], 80)  # Deve reduzir nota devido às falhas graves

        # Teste de geradores de relatório
        md = ReportGenerator.generate_markdown(summary)
        self.assertIn("Relatório de Auditoria de Segurança", md)
        html = ReportGenerator.generate_html(summary)
        self.assertIn("Auditoria de Segurança", html)
        json_str = ReportGenerator.generate_json(summary)
        self.assertIn("vulnerable-ai-app.com", json_str)

    def test_a01_broken_access_same_domain_no_false_positive(self):
        mod = BrokenAccessControlModule()
        ctx = AuditContext(
            url="https://meusite.com/login?next=https://meusite.com/painel",
            html="""
            <html>
                <body>
                    <a href="/login?redirect=https://meusite.com/dashboard">Dashboard</a>
                </body>
            </html>
            """
        )
        findings = mod.run(ctx)
        redirect_findings = [f for f in findings if "OPEN-REDIRECT" in f.id]
        self.assertEqual(len(redirect_findings), 0)

    def test_a01_broken_access_external_and_dangerous_redirects(self):
        mod = BrokenAccessControlModule()
        ctx = AuditContext(
            url="https://meusite.com/login?Next=https://evil.com/phish",
            html="""
            <html>
                <body>
                    <a href="/out?url=javascript:alert(1)">Inseguro JS</a>
                    <a href="/goto?destination=\\\\evil.com">Inseguro Backslash</a>
                </body>
            </html>
            """
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A01-OPEN-REDIRECT-NEXT", ids)
        self.assertIn("SEC-A01-OPEN-REDIRECT-URL", ids)
        self.assertIn("SEC-A01-OPEN-REDIRECT-DESTINATION", ids)

    def test_a01_broken_access_sensitive_routes_and_labels(self):
        mod = BrokenAccessControlModule()
        ctx = AuditContext(
            url="https://meusite.com",
            html="<script>const adminApi = `/api/v2/admin/users?limit=10`; const doc = '/swagger';</script>",
            scripts=["const debugEndpoint = '/api/debug';"]
        )
        findings = mod.run(ctx)
        sensitive = [f for f in findings if f.id == "SEC-A01-SENSITIVE-ENDPOINTS-EXPOSED"]
        self.assertEqual(len(sensitive), 1)
        evidence = sensitive[0].evidence
        self.assertIn("Endpoint de API Sensível / Debug", evidence)
        self.assertIn("Documentação ou Arquivo de Configuração", evidence)

    def test_a01_broken_access_client_side_auth(self):
        mod = BrokenAccessControlModule()
        ctx = AuditContext(
            url="https://meusite.com",
            scripts=[
                "if (localStorage.getItem('isAdmin')) { renderAdmin(); }",
                "if (user.role === 'admin') { showSuperSecretButtons(); }"
            ]
        )
        findings = mod.run(ctx)
        client_auth = [f for f in findings if f.id == "SEC-A01-CLIENT-SIDE-AUTH-CHECK"]
        self.assertEqual(len(client_auth), 1)
        self.assertIn("Leitura de privilégio via Storage do navegador", client_auth[0].evidence)
        self.assertIn("Verificação condicional de perfil administrativo no cliente", client_auth[0].evidence)

    def test_a01_broken_access_tokens_in_url(self):
        mod = BrokenAccessControlModule()
        jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789jkl012"
        ctx = AuditContext(
            url=f"https://meusite.com/callback?token=supersecret123&t={jwt_sample}",
            html="""
            <html>
                <body>
                    <a href="/oauth#access_token=oauthsecrettoken999">Link OAuth</a>
                </body>
            </html>
            """
        )
        findings = mod.run(ctx)
        token_findings = [f for f in findings if f.id == "SEC-A01-TOKEN-IN-URL"]
        self.assertEqual(len(token_findings), 1)
        evidence = token_findings[0].evidence
        self.assertIn("token=supe...t123", evidence)
        self.assertIn("access_token=oaut...n999", evidence)
        self.assertIn("Formato JWT", evidence)

    def test_a01_broken_access_idor_vectors(self):
        mod = BrokenAccessControlModule()
        ctx = AuditContext(
            url="https://meusite.com/dashboard?invoice_id=45",
            html="""
            <html>
                <body>
                    <a href="/api/users/1042">Perfil 1042</a>
                </body>
            </html>
            """,
            scripts=[
                "const getOrders = () => fetch(`/api/orders?user_id=${user.id}`);",
                "const getProfile = () => fetch(`/api/users/${user.id}`);"
            ]
        )
        findings = mod.run(ctx)
        idor_findings = [f for f in findings if f.id == "SEC-A01-POTENTIAL-IDOR-VECTOR"]
        self.assertEqual(len(idor_findings), 1)
        evidence = idor_findings[0].evidence
        self.assertIn("invoice_id=45", evidence)
        self.assertIn("/api/users/1042", evidence)
        self.assertIn("Envio de ID de usuário via Query String dinâmica na API", evidence)
        self.assertIn("Interpolação direta do ID do usuário logado na rota da API", evidence)

    def test_a02_unencrypted_http_and_localhost_verification(self):
        mod = CryptographicFailuresModule()
        # Não deve ser ignorado só porque tem 'localhost' como query param
        ctx_external = AuditContext(url="http://meusite.com/?origin=localhost")
        findings = mod.run(ctx_external)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A02-UNENCRYPTED-HTTP", ids)

        # Em localhost legítimo não deve alertar
        ctx_local1 = AuditContext(url="http://localhost:3000")
        self.assertEqual(len(mod.run(ctx_local1)), 0)

        ctx_local2 = AuditContext(url="http://127.0.0.1:8080/test")
        self.assertEqual(len(mod.run(ctx_local2)), 0)

    def test_a02_insecure_form_action_and_passwords(self):
        mod = CryptographicFailuresModule()
        ctx = AuditContext(
            url="https://meusite.com/login",
            html="""
            <html>
                <body>
                    <form action="http://auth.externo.com/login" method="POST">
                        <input type="PASSWORD" name="secret">
                        <button type="submit">Entrar</button>
                    </form>
                </body>
            </html>
            """
        )
        findings = mod.run(ctx)
        form_findings = [f for f in findings if f.id == "SEC-A02-INSECURE-FORM-ACTION"]
        self.assertEqual(len(form_findings), 1)
        self.assertEqual(form_findings[0].severity, Severity.CRITICAL)

    def test_a02_mixed_content_active_and_passive(self):
        mod = CryptographicFailuresModule()
        ctx = AuditContext(
            url="https://meusite.com",
            html="""
            <html>
                <head>
                    <script src="http://cdn.externo.com/app.js"></script>
                </head>
                <body>
                    <img src="http://cdn.externo.com/logo.png">
                </body>
            </html>
            """,
            scripts=["const ws = new WebSocket('ws://chat.externo.com');"]
        )
        findings = mod.run(ctx)
        ids = [f.id for f in findings]
        self.assertIn("SEC-A02-MIXED-CONTENT-ACTIVE", ids)
        self.assertIn("SEC-A02-MIXED-CONTENT-PASSIVE", ids)

    def test_a02_weak_client_crypto(self):
        mod = CryptographicFailuresModule()
        ctx = AuditContext(
            url="https://meusite.com",
            scripts=[
                "const hash = CryptoJS.MD5(pass);",
                "const enc = btoa(user.password);",
                "const token = Math.random();"
            ]
        )
        findings = mod.run(ctx)
        weak_findings = [f for f in findings if f.id == "SEC-A02-WEAK-CLIENT-CRYPTO"]
        self.assertEqual(len(weak_findings), 1)
        evidence = weak_findings[0].evidence
        self.assertIn("MD5", evidence)
        self.assertIn("btoa", evidence)
        self.assertIn("Math.random", evidence)


if __name__ == "__main__":
    unittest.main()
