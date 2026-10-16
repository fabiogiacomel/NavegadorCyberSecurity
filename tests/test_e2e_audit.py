"""
Teste de Integração End-to-End:
Inicia o demo_vulnerable_app em background, audita os dados e valida todas as regras.
"""

import threading
import time
import requests
import unittest
from http.server import HTTPServer
from demo_vulnerable_app import VulnerableTestHandler
from core.audit_engine import AuditEngine
from modules.base import AuditContext, Severity


class TestEndToEndAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 5055
        cls.server = HTTPServer(("127.0.0.1", cls.port), VulnerableTestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_audit_against_vulnerable_demo(self):
        url = f"http://localhost:{self.port}"
        resp = requests.get(url, timeout=3)
        self.assertEqual(resp.status_code, 200)

        # Monta o contexto exatamente como o CyberSecurityWebView faz
        cookies = []
        if "Set-Cookie" in resp.headers:
            cookies.append({
                "name": "session_id",
                "value": "vibe_session_998877",
                "httpOnly": False,
                "secure": False,
                "sameSite": "lax",
                "domain": "localhost"
            })

        local_storage = {
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMzg0IiwibmFtZSI6IkFkbWluIn0.fake_signature_vibe_coding_demo",
            "user_role": "superuser"
        }

        # Simula a interceptação de chamadas de API executadas pela página
        api_resp = requests.get(f"{url}/api/users", timeout=2)
        api_calls = [
            {
                "url": f"{url}/api/users",
                "method": "GET",
                "status": api_resp.status_code,
                "headers": dict(api_resp.headers),
                "response": api_resp.text,
                "timestamp": "2026-10-07T22:30:00Z"
            }
        ]

        ctx = AuditContext(
            url=url,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            html=resp.text,
            cookies=cookies,
            local_storage=local_storage,
            session_storage={},
            scripts=[resp.text],
            script_srcs=["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"],
            forms=[],
            api_calls=api_calls
        )

        engine = AuditEngine()
        summary = engine.run_audit(ctx)

        findings = summary["findings"]
        finding_ids = [f.id for f in findings]

        print(f"\n[Test E2E] Total de falhas detectadas: {len(findings)}")
        print(f"[Test E2E] Security Score: {summary['score']}/100 ({summary['grade']})")

        # Verifica falhas OWASP Web detectadas
        self.assertIn("SEC-A05-CSP-MISSING", finding_ids)
        self.assertIn("SEC-A05-CLICKJACKING-MISSING", finding_ids)
        self.assertIn("SEC-A05-TECH-DISCLOSURE-HEADERS", finding_ids)
        self.assertTrue(any("SEC-A07-COOKIE-NO-HTTPONLY" in i for i in finding_ids))
        self.assertTrue(any("SEC-A07-STORAGE-TOKEN-EXPOSURE" in i for i in finding_ids))
        self.assertIn("SEC-A03-DOM-XSS-SINKS", finding_ids)
        self.assertIn("SEC-A03-DYNAMIC-CODE-EVAL", finding_ids)
        self.assertTrue(any("SEC-A03-FORM-MISSING-CSRF" in i for i in finding_ids))
        self.assertTrue(any("VIBE-SECRET-OPENAI-KEY" in i for i in finding_ids))
        self.assertTrue(any("SEC-A08-MISSING-SRI-SCRIPTS" in i for i in finding_ids))

        # Verifica os novos módulos OWASP Top 10 (A04, A06, A09, A10)
        self.assertIn("SEC-A04-CLIENT-SIDE-TRUST-PRICING", finding_ids)
        self.assertIn("SEC-A04-MISSING-BOT-PROTECTION", finding_ids)
        self.assertIn("SEC-A06-VULNERABLE-JS-LIBRARY", finding_ids)
        self.assertIn("SEC-A09-SENSITIVE-CONSOLE-LOGGING", finding_ids)
        self.assertIn("SEC-A09-SILENT-ERROR-SWALLOWING", finding_ids)
        self.assertIn("SEC-A10-CLIENT-REMOTE-FETCH-PROXY", finding_ids)
        self.assertIn("SEC-A10-INTERNAL-INFRA-REFERENCE", finding_ids)

        # Verifica falhas do Módulo API Sentinel (OWASP API Top 10)
        self.assertIn("API-A08-OPENAPI-EXPOSED", finding_ids)
        self.assertIn("API-A08-GRAPHQL-INTROSPECTION-ENABLED", finding_ids)
        self.assertIn("API-A03-EXCESSIVE-DATA-EXPOSURE", finding_ids)

        # Verifica falhas dos Módulos Especializados (Multi-Tenant RLS & OWASP LLM Top 10)
        self.assertIn("RLS-03-DIRECT-DB-QUERY-EXPOSURE", finding_ids)
        self.assertIn("RLS-04-CROSS-TENANT-DATA-LEAK", finding_ids)
        self.assertIn("LLM06-DIRECT-LLM-API-AND-TOOLS", finding_ids)
        self.assertIn("LLM07-SYSTEM-PROMPT-EXPOSED", finding_ids)

        # O score deve ter caído para nível F dada a severidade das falhas
        self.assertEqual(summary["score"], 0)
        self.assertEqual(summary["grade"], "F")


if __name__ == "__main__":
    unittest.main()
