"""
Gerador de Relatórios de Auditoria de Segurança.
Exporta os achados em formatos Markdown (.md), HTML (.html) estilizado e JSON (.json).
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from modules.base import AuditFinding, Severity


class ReportGenerator:
    @staticmethod
    def generate_markdown(summary: Dict[str, Any]) -> str:
        """Gera um relatório profissional em Markdown."""
        url = summary.get("url", "N/A")
        score = summary.get("score", 100)
        grade = summary.get("grade", "A+")
        counts = summary.get("counts", {})
        findings: List[AuditFinding] = summary.get("findings", [])
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        md = []
        md.append(f"# 🛡️ Relatório de Auditoria de Segurança Web")
        md.append(f"> **Gerado pelo Navegador CyberSecurity — Vibe Coding & OWASP Auditor**")
        md.append(f"")
        md.append(f"- **URL Auditada:** `{url}`")
        md.append(f"- **Data:** {date_str}")
        md.append(f"- **Security Score:** **{score}/100** (Classificação: **{grade}**)")
        md.append(f"")
        md.append(f"---")
        md.append(f"## 📊 Resumo Executivo das Vulnerabilidades")
        md.append(f"")
        md.append(f"| Severidade | Quantidade | Peso por Falha |")
        md.append(f"| :--- | :---: | :---: |")
        md.append(f"| 🔴 **Crítica** | `{counts.get('CRITICAL', 0)}` | -25 pts |")
        md.append(f"| 🟠 **Alta** | `{counts.get('HIGH', 0)}` | -15 pts |")
        md.append(f"| 🟡 **Média** | `{counts.get('MEDIUM', 0)}` | -8 pts |")
        md.append(f"| 🔵 **Baixa** | `{counts.get('LOW', 0)}` | -3 pts |")
        md.append(f"| ⚪ **Informativa** | `{counts.get('INFO', 0)}` | 0 pts |")
        md.append(f"| **Total** | **{len(findings)}** | |")
        md.append(f"")
        md.append(f"---")
        md.append(f"## 🔍 Detalhamento dos Achados de Segurança")
        md.append(f"")

        if not findings:
            md.append("🎉 **Nenhuma vulnerabilidade detectada nas regras ativas!**")
        else:
            for i, f in enumerate(findings, 1):
                md.append(f"### {i}. [{f.severity.label_pt}] {f.title}")
                md.append(f"- **ID:** `{f.id}`")
                md.append(f"- **Categoria:** `{f.category.value}`")
                md.append(f"- **Descrição:** {f.description}")
                md.append(f"")
                md.append(f"**Evidência:**")
                md.append(f"```text\n{f.evidence}\n```")
                md.append(f"")
                md.append(f"**Como Corrigir (Remediação):**")
                md.append(f"> {f.remediation}")
                md.append(f"")
                if f.vibe_coding_context:
                    md.append(f"💡 **Contexto Vibe Coding / IA:**")
                    md.append(f"> {f.vibe_coding_context}")
                    md.append(f"")
                md.append(f"---")

        md.append(f"")
        md.append(f"*Relatório gerado para auditoria humana defensiva de código.*")
        return "\n".join(md)

    @staticmethod
    def generate_html(summary: Dict[str, Any]) -> str:
        """Gera um relatório completo em HTML com visual moderno Cyber Dark."""
        url = summary.get("url", "N/A")
        score = summary.get("score", 100)
        grade = summary.get("grade", "A+")
        counts = summary.get("counts", {})
        findings: List[AuditFinding] = summary.get("findings", [])
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        grade_color = "#3fb950" if score >= 85 else ("#d29922" if score >= 70 else "#f85149")

        findings_html = []
        for i, f in enumerate(findings, 1):
            findings_html.append(f"""
            <div class="finding-card" style="border-left: 4px solid {f.severity.color};">
                <div class="finding-header">
                    <span class="badge" style="background: {f.severity.color}22; color: {f.severity.color}; border: 1px solid {f.severity.color}88;">
                        {f.severity.label_pt}
                    </span>
                    <span class="finding-cat">{f.category.value}</span>
                    <span class="finding-id">{f.id}</span>
                </div>
                <h3>{i}. {f.title}</h3>
                <p class="desc">{f.description}</p>
                
                <div class="evidence-box">
                    <strong>Evidência:</strong>
                    <pre><code>{f.evidence}</code></pre>
                </div>
                
                <div class="remediation-box">
                    <strong>✅ Como Corrigir:</strong>
                    <p>{f.remediation}</p>
                </div>
                
                {f'''<div class="vibe-box">
                    <strong>💡 Dica Vibe Coding (Auditoria IA):</strong>
                    <p>{f.vibe_coding_context}</p>
                </div>''' if f.vibe_coding_context else ''}
            </div>
            """)

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Auditoria de Segurança - {url}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .grade-box {{
            text-align: center;
            background: #0d1117;
            border: 2px solid {grade_color};
            border-radius: 50%;
            width: 85px;
            height: 85px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        .grade-letter {{
            font-size: 32px;
            font-weight: 800;
            color: {grade_color};
            line-height: 1;
        }}
        .score-val {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 24px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 12px;
            color: var(--text-muted);
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            font-size: 12px;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .finding-cat {{
            color: var(--accent);
        }}
        .finding-id {{
            color: var(--text-muted);
            font-family: monospace;
        }}
        h3 {{ margin: 6px 0 12px 0; color: #fff; }}
        .desc {{ line-height: 1.5; color: #adbac7; }}
        .evidence-box, .remediation-box, .vibe-box {{
            background: #0d1117;
            border-radius: 6px;
            padding: 12px;
            margin-top: 10px;
            border: 1px solid var(--border);
        }}
        .remediation-box {{ border-left: 3px solid #3fb950; }}
        .vibe-box {{ border-left: 3px solid #d29922; }}
        pre {{
            margin: 8px 0 0 0;
            white-space: pre-wrap;
            word-break: break-all;
            color: #79c0ff;
            font-family: Consolas, monospace;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0 0 8px 0;">🛡️ Auditoria de Segurança Web</h1>
                <p style="margin: 0; color: var(--text-muted);">
                    URL: <strong style="color: #58a6ff;">{url}</strong> | {date_str}
                </p>
            </div>
            <div class="grade-box">
                <span class="grade-letter">{grade}</span>
                <span class="score-val">{score}/100</span>
            </div>
        </div>

        <div class="stats-bar">
            <div class="stat-card" style="border-top: 3px solid #f85149;">
                <div class="stat-num" style="color: #f85149;">{counts.get('CRITICAL', 0)}</div>
                <div class="stat-label">Críticas</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #f0883e;">
                <div class="stat-num" style="color: #f0883e;">{counts.get('HIGH', 0)}</div>
                <div class="stat-label">Altas</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #d29922;">
                <div class="stat-num" style="color: #d29922;">{counts.get('MEDIUM', 0)}</div>
                <div class="stat-label">Médias</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #58a6ff;">
                <div class="stat-num" style="color: #58a6ff;">{counts.get('LOW', 0)}</div>
                <div class="stat-label">Baixas</div>
            </div>
            <div class="stat-card" style="border-top: 3px solid #8b949e;">
                <div class="stat-num" style="color: #8b949e;">{counts.get('INFO', 0)}</div>
                <div class="stat-label">Informativas</div>
            </div>
        </div>

        <div class="findings-list">
            {''.join(findings_html) if findings_html else '<p style="text-align:center; padding: 40px; color: #3fb950;">Nenhum problema detectado!</p>'}
        </div>
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def generate_json(summary: Dict[str, Any]) -> str:
        """Gera JSON estruturado com os resultados."""
        findings = summary.get("findings", [])
        data = {
            "url": summary.get("url"),
            "timestamp": datetime.now().isoformat(),
            "score": summary.get("score"),
            "grade": summary.get("grade"),
            "counts": summary.get("counts"),
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
