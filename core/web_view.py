"""
Visualizador Web Chromium (Custom QWebEngineView).
Integra o motor Chromium com inspeção passiva de DOM, scripts, storage e cabeçalhos HTTP.
"""

import json
import requests
from typing import Dict, Any, List, Optional
from PyQt6.QtCore import QUrl, pyqtSignal, QObject
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineScript
)
from modules.base import AuditContext


class CustomWebPage(QWebEnginePage):
    """Página customizada para capturar mensagens de console."""
    console_message_received = pyqtSignal(str)

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        self.console_message_received.emit(f"[{level}] {message} ({source_id}:{line_number})")
        super().javaScriptConsoleMessage(level, message, line_number, source_id)


class CyberSecurityWebView(QWebEngineView):
    """
    Componente central do navegador que carrega aplicações e extrai
    o contexto completo de segurança para os módulos de auditoria.
    """
    page_data_ready = pyqtSignal(object)  # Emite AuditContext

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.custom_page = CustomWebPage(self)
        self.setPage(self.custom_page)
        self.console_logs: List[str] = []
        self.custom_page.console_message_received.connect(self._on_console_message)

        # Injeta script de interceptação de APIs no ciclo de criação do documento
        self._inject_api_interceptor()

    def _inject_api_interceptor(self):
        hook_js = """
        (function() {
            window.__CYBER_API_CALLS__ = window.__CYBER_API_CALLS__ || [];

            // Intercepta Fetch API
            if (window.fetch && !window.__CYBER_FETCH_HOOKED__) {
                window.__CYBER_FETCH_HOOKED__ = true;
                var origFetch = window.fetch;
                window.fetch = async function() {
                    var args = arguments;
                    var url = typeof args[0] === 'string' ? args[0] : (args[0] ? args[0].url : '');
                    var method = (args[1] && args[1].method) ? args[1].method.toUpperCase() : 'GET';
                    var reqHeaders = (args[1] && args[1].headers) ? args[1].headers : {};

                    try {
                        var res = await origFetch.apply(this, args);
                        var clone = res.clone();
                        clone.text().then(function(text) {
                            var resHeaders = {};
                            try {
                                if (clone.headers && clone.headers.forEach) {
                                    clone.headers.forEach(function(v, k) { resHeaders[k] = v; });
                                }
                            } catch(e) {}

                            window.__CYBER_API_CALLS__.push({
                                url: url,
                                method: method,
                                status: res.status,
                                headers: resHeaders,
                                response: text.length > 30000 ? text.slice(0, 30000) : text,
                                timestamp: new Date().toISOString()
                            });
                        }).catch(function() {});
                        return res;
                    } catch(err) {
                        throw err;
                    }
                };
            }

            // Intercepta XMLHttpRequest
            if (window.XMLHttpRequest && !window.__CYBER_XHR_HOOKED__) {
                window.__CYBER_XHR_HOOKED__ = true;
                var origOpen = XMLHttpRequest.prototype.open;
                var origSend = XMLHttpRequest.prototype.send;

                XMLHttpRequest.prototype.open = function(method, url) {
                    this._cyber_method = method;
                    this._cyber_url = url;
                    return origOpen.apply(this, arguments);
                };

                XMLHttpRequest.prototype.send = function() {
                    this.addEventListener('load', function() {
                        try {
                            window.__CYBER_API_CALLS__.push({
                                url: this._cyber_url,
                                method: (this._cyber_method || 'GET').toUpperCase(),
                                status: this.status,
                                headers: {},
                                response: (this.responseText || '').slice(0, 30000),
                                timestamp: new Date().toISOString()
                            });
                        } catch(e) {}
                    });
                    return origSend.apply(this, arguments);
                };
            }
        })();
        """

        script = QWebEngineScript()
        script.setName("CyberApiInterceptor")
        script.setSourceCode(hook_js)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(True)
        self.custom_page.scripts().insert(script)

    def _on_console_message(self, msg: str):
        self.console_logs.append(msg)
        if len(self.console_logs) > 50:
            self.console_logs.pop(0)

    def extract_audit_context(self, callback):
        """
        Coleta de forma assíncrona o estado do DOM, localStorage,
        sessionStorage, scripts e cabeçalhos HTTP da URL atual.
        """
        current_url = self.url().toString()
        if not current_url or current_url == "about:blank":
            return

        # 1. Requisição de cabeçalhos HTTP no backend
        headers: Dict[str, str] = {}
        status_code = 200

        try:
            if current_url.startswith("http://") or current_url.startswith("https://"):
                resp = requests.head(current_url, timeout=4, allow_redirects=True, headers={
                    "User-Agent": "CyberSecurityAuditBrowser/1.0 (OWASP Auditor)"
                })
                # Converte cabeçalhos para dict
                headers = dict(resp.headers)
                status_code = resp.status_code
        except Exception:
            # Fallback caso HEAD falhe (alguns servidores não aceitam HEAD)
            try:
                resp = requests.get(current_url, timeout=4, stream=True, headers={
                    "User-Agent": "CyberSecurityAuditBrowser/1.0 (OWASP Auditor)"
                })
                headers = dict(resp.headers)
                status_code = resp.status_code
                resp.close()
            except Exception as e:
                print(f"[WebView] Falha ao coletar cabeçalhos de rede: {e}")

        # 2. Execução de script JavaScript passivo dentro do Chromium
        # Coleta localStorage, sessionStorage, cookies do documento e scripts
        js_probe = """
        (function() {
            var data = {
                localStorage: {},
                sessionStorage: {},
                cookies: [],
                scripts: [],
                script_srcs: [],
                forms: []
            };

            // Coleta localStorage
            try {
                for (var i = 0; i < localStorage.length; i++) {
                    var k = localStorage.key(i);
                    data.localStorage[k] = localStorage.getItem(k);
                }
            } catch(e) {}

            // Coleta sessionStorage
            try {
                for (var j = 0; j < sessionStorage.length; j++) {
                    var sk = sessionStorage.key(j);
                    data.sessionStorage[sk] = sessionStorage.getItem(sk);
                }
            } catch(e) {}

            // Coleta cookies visíveis no cliente
            try {
                if (document.cookie) {
                    var cParts = document.cookie.split(';');
                    for (var c = 0; c < cParts.length; c++) {
                        var pair = cParts[c].trim().split('=');
                        if (pair.length >= 2) {
                            data.cookies.push({
                                name: pair[0],
                                value: pair.slice(1).join('='),
                                httpOnly: false, // Se está visível no document.cookie, NÃO é httpOnly
                                secure: location.protocol === 'https:',
                                domain: location.hostname
                            });
                        }
                    }
                }
            } catch(e) {}

            // Coleta scripts inline e fontes externas
            try {
                var scriptTags = document.getElementsByTagName('script');
                for (var s = 0; s < scriptTags.length; s++) {
                    if (scriptTags[s].src) {
                        data.script_srcs.push(scriptTags[s].src);
                    } else if (scriptTags[s].innerText) {
                        data.scripts.push(scriptTags[s].innerText);
                    }
                }
            } catch(e) {}

            // Coleta chamadas de API interceptadas
            try {
                data.api_calls = window.__CYBER_API_CALLS__ || [];
            } catch(e) {}

            return JSON.stringify(data);
        })();
        """

        def on_js_result(result_json_str):
            # 3. Coleta o HTML bruto da página
            self.page().toHtml(lambda html_content: self._finish_context_extraction(
                current_url, status_code, headers, html_content, result_json_str, callback
            ))

        self.page().runJavaScript(js_probe, on_js_result)

    def _finish_context_extraction(self, url, status_code, headers, html_content, js_data_str, callback):
        local_storage = {}
        session_storage = {}
        cookies = []
        scripts = []
        script_srcs = []
        api_calls = []

        if js_data_str:
            try:
                js_data = json.loads(js_data_str)
                local_storage = js_data.get("localStorage", {})
                session_storage = js_data.get("sessionStorage", {})
                cookies = js_data.get("cookies", [])
                scripts = js_data.get("scripts", [])
                script_srcs = js_data.get("script_srcs", [])
                api_calls = js_data.get("api_calls", [])
            except Exception as e:
                print(f"[WebView] Erro ao parsear dados do JS probe: {e}")

        # Se houver cookies nos cabeçalhos Set-Cookie do servidor, audita também
        if "set-cookie" in [k.lower() for k in headers.keys()]:
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    c_parts = v.split(";")
                    first_part = c_parts[0].split("=")
                    c_name = first_part[0].strip() if len(first_part) > 0 else "unknown"
                    c_val = first_part[1].strip() if len(first_part) > 1 else ""
                    is_http_only = "httponly" in v.lower()
                    is_secure = "secure" in v.lower()
                    same_site = "lax"
                    if "samesite=strict" in v.lower():
                        same_site = "strict"
                    elif "samesite=none" in v.lower():
                        same_site = "none"

                    # Adiciona ou atualiza com os dados reais dos cabeçalhos do servidor
                    existing = [c for c in cookies if c.get("name") == c_name]
                    if existing:
                        existing[0]["httpOnly"] = is_http_only
                        existing[0]["secure"] = is_secure
                        existing[0]["sameSite"] = same_site
                    else:
                        cookies.append({
                            "name": c_name,
                            "value": c_val,
                            "httpOnly": is_http_only,
                            "secure": is_secure,
                            "sameSite": same_site,
                            "domain": ""
                        })

        ctx = AuditContext(
            url=url,
            status_code=status_code,
            headers=headers,
            html=html_content or "",
            cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            scripts=scripts,
            script_srcs=script_srcs,
            console_logs=list(self.console_logs),
            api_calls=api_calls
        )

        callback(ctx)
