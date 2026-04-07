"""
Detailed Report Generator

Uses OpenAI GPT-4o to produce a comprehensive, structured HTML report from
orchestrated agent findings. Includes:
  - Executive Summary
  - Security findings (from SecurityAgent)
  - Quality findings (from QualityAgent)
  - Dependency risks (from DependencyAgent)
  - Remediation Roadmap (from OrchestratorAgent)
  - Enhancement Recommendations
  - Architecture description
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import config

logger = logging.getLogger(__name__)

REPORT_SYSTEM = """You are a senior engineering report writer who creates detailed, actionable
security and code quality reports for engineering teams.

Write clear, professional technical content that is:
- Evidence-based (cite specific files and line numbers)
- Actionable (every finding has a clear fix)
- Risk-prioritized (critical issues first)
- Architecture-aware (explain root causes, not just symptoms)

When asked for architecture description, explain the high-level design based on the code structure.
When asked for enhancements, suggest modern best practices and tooling.
"""


class DetailedReportGenerator:
    """
    Generates a detailed HTML/JSON report from multi-agent analysis results.
    Uses OpenAI GPT-4o for narrative sections and enhancement proposals.
    """

    def __init__(self):
        self._openai_client = None
        self._use_openai = False
        try:
            from openai import OpenAI
            self._openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
            self._use_openai = True
            logger.info("[DetailedReport] OpenAI client initialized")
        except Exception as e:
            logger.warning(f"[DetailedReport] OpenAI not available: {e}")

    def generate(self, uid: str, analysis_data: Dict[str, Any],
                 agent_bus_snapshot: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate a full detailed report.

        Args:
            uid: Analysis UID
            analysis_data: Merged security_report.json / dashboard_data.json
            agent_bus_snapshot: Snapshot from AgentBus (if available)

        Returns:
            Dict with 'html_report', 'json_report', 'summary'
        """
        # Collect findings from all sources
        security_findings = analysis_data.get('vulnerabilities', []) or \
                            analysis_data.get('issues', []) or []
        quality_findings = analysis_data.get('quality_issues', []) or []
        dep_findings = analysis_data.get('dependency_findings', []) or []
        orchestrator_data = analysis_data.get('orchestrator', {}) or {}
        merged_findings = orchestrator_data.get('merged_findings', [])
        roadmap = orchestrator_data.get('remediation_roadmap', [])
        enhancements = orchestrator_data.get('enhancements', [])
        patterns = orchestrator_data.get('systemic_patterns', [])
        exec_summary = orchestrator_data.get('executive_summary', '')
        overall_score = orchestrator_data.get('overall_risk_score',
                         analysis_data.get('security_score', 5.0))

        # Compute statistics
        all_findings = merged_findings or (security_findings + quality_findings + dep_findings)
        stats = self._compute_stats(all_findings, analysis_data)

        # Generate AI narrative sections
        narrative = self._generate_narrative(
            exec_summary, all_findings, roadmap, enhancements, patterns,
            analysis_data.get('files_analyzed', [])
        )

        report_data = {
            'uid': uid,
            'generated_at': datetime.utcnow().isoformat(),
            'overall_risk_score': overall_score,
            'stats': stats,
            'executive_summary': narrative.get('executive_summary', exec_summary),
            'architecture_overview': narrative.get('architecture_overview', ''),
            'security_findings': security_findings,
            'quality_findings': quality_findings,
            'dependency_findings': dep_findings,
            'merged_findings': all_findings,
            'remediation_roadmap': roadmap,
            'enhancements': narrative.get('enhancements', enhancements),
            'systemic_patterns': patterns,
            'agent_log': (agent_bus_snapshot or {}).get('log', [])[-30:],
        }

        html = self._render_html(report_data)
        report_data['html_report'] = html

        return report_data

    # ── AI narrative generation ───────────────────────────────────────────────

    def _generate_narrative(self, exec_summary: str, findings: List[Dict],
                             roadmap: List[Dict], enhancements: List[Dict],
                             patterns: List[str], files: List[str]) -> Dict[str, str]:
        if not self._use_openai:
            return {
                'executive_summary': exec_summary or 'Analysis complete. Review findings below.',
                'architecture_overview': 'Architecture overview not available (OpenAI key required).',
                'enhancements': enhancements,
            }

        prompt = self._build_narrative_prompt(
            exec_summary, findings, roadmap, enhancements, patterns, files
        )
        try:
            resp = self._openai_client.chat.completions.create(
                model='gpt-4o',
                messages=[
                    {"role": "system", "content": REPORT_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=3000,
            )
            raw = resp.choices[0].message.content
            return self._parse_narrative_json(raw)
        except Exception as e:
            logger.error(f"[DetailedReport] OpenAI narrative failed: {e}", exc_info=True)
            return {
                'executive_summary': exec_summary or 'See findings below.',
                'architecture_overview': 'Architecture analysis unavailable.',
                'enhancements': enhancements,
            }

    def _build_narrative_prompt(self, exec_summary: str, findings: List[Dict],
                                  roadmap: List[Dict], enhancements: List[Dict],
                                  patterns: List[str], files: List[str]) -> str:
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        unique_files = list({f.get('file', '') for f in findings if f.get('file')})[:15]
        file_ext = list({os.path.splitext(fp)[1] for fp in unique_files if '.' in fp})

        return f"""Based on this security and quality analysis, write a comprehensive report narrative:

Executive Summary (from orchestrator): {exec_summary}

Statistics:
- Total findings: {len(findings)}
- Critical: {len(critical)}, High: {len(high)}
- Files analyzed: {len(files) or len(unique_files)}
- Languages detected: {', '.join(file_ext) or 'unknown'}

Files with findings (sample): {', '.join(unique_files[:8])}

Critical findings: {json.dumps([{'title': f.get('title'), 'file': f.get('file'), 'description': f.get('description', '')[:100]} for f in critical[:5]], indent=2)}

Systemic patterns: {json.dumps(patterns)}

Respond in JSON:
{{
  "executive_summary": "3-4 professional paragraphs for a CTO/VP Engineering audience. Include severity overview, business risk, and urgency.",
  "architecture_overview": "2-3 paragraphs describing the inferred architecture from the codebase structure and suggesting architectural improvements.",
  "enhancements": [
    {{"title": "...", "description": "...", "priority": "critical|high|medium|low", "effort": "1 sprint|1 day|..."}},
    ...
  ]
}}"""

    def _parse_narrative_json(self, raw: str) -> Dict:
        clean = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
        clean = re.sub(r'\s*```$', '', clean.strip(), flags=re.MULTILINE)
        try:
            return json.loads(clean)
        except Exception:
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
        return {'executive_summary': raw[:500], 'architecture_overview': '', 'enhancements': []}

    # ── Stats ────────────────────────────────────────────────────────────────

    def _compute_stats(self, findings: List[Dict], data: Dict) -> Dict:
        sevs = {}
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            sevs[sev] = sum(1 for f in findings if f.get('severity') == sev)
        return {
            'total_findings': len(findings),
            'by_severity': sevs,
            'files_with_issues': len({f.get('file', '') for f in findings if f.get('file')}),
            'security_score': data.get('security_score', 5.0),
            'quality_score': data.get('quality_score', 5.0),
            'tech_debt_hours': data.get('tech_debt_hours', 0),
        }

    # ── HTML renderer ────────────────────────────────────────────────────────

    def _render_html(self, data: Dict) -> str:
        """Render the full HTML report."""
        stats = data.get('stats', {})
        sevs = stats.get('by_severity', {})
        findings = data.get('merged_findings', [])
        roadmap = data.get('remediation_roadmap', [])
        enhancements = data.get('enhancements', [])
        patterns = data.get('systemic_patterns', [])

        sev_colors = {
            'critical': '#ef4444', 'high': '#f97316',
            'medium': '#eab308', 'low': '#22c55e', 'info': '#3b82f6'
        }

        def severity_badge(sev):
            color = sev_colors.get(sev, '#94a3b8')
            return f'<span style="background:{color}20;color:{color};border:1px solid {color}40;padding:2px 8px;border-radius:99px;font-size:0.7rem;font-weight:700;text-transform:uppercase">{sev}</span>'

        # Findings rows
        finding_rows = ''
        for f in findings[:100]:
            sev = f.get('severity', 'info')
            finding_rows += f'''<tr>
            <td>{severity_badge(sev)}</td>
            <td style="font-weight:600;color:#e2e8f4">{f.get("title", "")}</td>
            <td style="font-family:monospace;font-size:0.75rem;color:#94a3b8">{f.get("file", "—")}:{f.get("line", "")}</td>
            <td style="color:#94a3b8;max-width:300px">{f.get("description", f.get("remediation", ""))[:120]}…</td>
            <td><span style="font-size:0.7rem;background:rgba(255,255,255,0.06);padding:2px 8px;border-radius:4px;color:#94a3b8">{", ".join(f.get("source_agents", [f.get("agent", "ai")]))}</span></td>
            </tr>'''

        # Roadmap phases
        roadmap_html = ''
        for phase in roadmap:
            items_html = ''.join(f'<li style="margin:4px 0;color:#94a3b8">{item}</li>' for item in phase.get('items', []))
            roadmap_html += f'''<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:12px;padding:16px;margin-bottom:12px">
            <div style="font-weight:700;color:#e2e8f4;margin-bottom:8px">Phase {phase.get("phase","?")}: {phase.get("title","")}</div>
            <ul style="padding-left:20px">{items_html}</ul></div>'''

        # Enhancements
        enh_cards = ''
        for enh in enhancements[:8]:
            priority = enh.get('priority', 'medium')
            p_color = sev_colors.get(priority, '#94a3b8')
            enh_cards += f'''<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-left:3px solid {p_color};border-radius:12px;padding:16px;margin-bottom:10px">
            <div style="font-weight:700;color:#e2e8f4;margin-bottom:4px">{enh.get("title","")}</div>
            <div style="color:#94a3b8;font-size:0.85rem">{enh.get("description","")}</div>
            <div style="margin-top:8px">{severity_badge(priority)} <span style="font-size:0.72rem;color:#64748b;margin-left:8px">{enh.get("effort","")}</span></div>
            </div>'''

        # Pattern pills
        pattern_pills = ''.join(
            f'<span style="background:rgba(234,179,8,0.1);color:#fbbf24;border:1px solid rgba(234,179,8,0.2);padding:4px 12px;border-radius:99px;font-size:0.75rem;margin:4px">{p}</span>'
            for p in patterns[:10]
        )

        overall = data.get('overall_risk_score', 5.0)
        risk_color = '#ef4444' if overall < 4 else '#f97316' if overall < 6 else '#eab308' if overall < 8 else '#22c55e'

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Code Review — Detailed Security Report</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Space+Grotesk:wght@500;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Plus Jakarta Sans',sans-serif;background:#07090f;color:#e2e8f4;min-height:100vh;padding:32px 24px}}
.report-wrap{{max-width:1100px;margin:0 auto}}
.cover{{text-align:center;padding:48px 0 32px;border-bottom:1px solid rgba(255,255,255,0.07);margin-bottom:32px}}
.cover-logo{{font-size:3rem;margin-bottom:12px}}
.cover-title{{font-family:'Space Grotesk',sans-serif;font-size:2rem;font-weight:800;background:linear-gradient(135deg,#9d93ff,#38bdf8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
.cover-sub{{color:#64748b;font-size:0.9rem}}
.section{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:16px;padding:24px;margin-bottom:20px}}
.section-title{{font-family:'Space Grotesk',sans-serif;font-size:1rem;font-weight:700;color:#e2e8f4;margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.score-ring{{display:inline-flex;align-items:center;justify-content:center;width:80px;height:80px;border-radius:50%;border:4px solid {risk_color};font-size:1.6rem;font-weight:800;color:{risk_color};font-family:'Space Grotesk',sans-serif}}
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}}
.stat-card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:14px;text-align:center}}
.stat-val{{font-size:1.8rem;font-weight:800;font-family:'Space Grotesk',sans-serif;line-height:1}}
.stat-lbl{{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
th{{color:#64748b;font-weight:600;text-transform:uppercase;font-size:0.65rem;letter-spacing:0.5px;padding:10px 12px;border-bottom:1px solid rgba(255,255,255,0.07);text-align:left}}
td{{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,0.03);vertical-align:top}}
tr:hover td{{background:rgba(255,255,255,0.02)}}
.exec-body{{color:#94a3b8;line-height:1.8;white-space:pre-line;font-size:0.88rem}}
.print-btn{{position:fixed;bottom:24px;right:24px;background:linear-gradient(135deg,#7C6FF7,#5b50e0);color:#fff;border:none;border-radius:99px;padding:12px 24px;font-weight:700;cursor:pointer;font-size:0.85rem;box-shadow:0 4px 20px rgba(124,111,247,0.4);font-family:'Plus Jakarta Sans',sans-serif}}
.print-btn:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
@media print{{body{{background:#fff;color:#000}}.print-btn{{display:none}}.section{{border:1px solid #e0e0e0;background:#fafafa}}}}
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ Download / Print</button>
<div class="report-wrap">

  <!-- Cover -->
  <div class="cover">
    <div class="cover-logo">🛡️</div>
    <div class="cover-title">Security & Quality Report</div>
    <div class="cover-sub">Generated {data.get("generated_at","").split("T")[0]} · AI Code Review Platform · Analysis ID: {data.get("uid","")[:8]}</div>
    <div style="margin-top:24px;display:flex;align-items:center;justify-content:center;gap:24px">
      <div>
        <div class="score-ring">{overall:.1f}</div>
        <div style="font-size:0.7rem;color:#64748b;margin-top:6px;text-align:center">Risk Score</div>
      </div>
      <div class="stat-grid" style="flex:1;max-width:600px">
        <div class="stat-card"><div class="stat-val" style="color:#ef4444">{sevs.get("critical",0)}</div><div class="stat-lbl">Critical</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#f97316">{sevs.get("high",0)}</div><div class="stat-lbl">High</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#eab308">{sevs.get("medium",0)}</div><div class="stat-lbl">Medium</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#22c55e">{sevs.get("low",0)}</div><div class="stat-lbl">Low</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#e2e8f4">{stats.get("total_findings",0)}</div><div class="stat-lbl">Total</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#38bdf8">{stats.get("tech_debt_hours",0)}h</div><div class="stat-lbl">Tech Debt</div></div>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">📋 Executive Summary</div>
    <div class="exec-body">{data.get("executive_summary","No summary available.")}</div>
  </div>

  <!-- Architecture Overview -->
  {f'<div class="section"><div class="section-title">🏗️ Architecture Overview</div><div class="exec-body">{data.get("architecture_overview","")}</div></div>' if data.get("architecture_overview") else ""}

  <!-- Systemic Patterns -->
  {f'<div class="section"><div class="section-title">🔍 Systemic Patterns</div><div style="display:flex;flex-wrap:wrap;gap:8px">{pattern_pills}</div></div>' if patterns else ""}

  <!-- All Findings -->
  <div class="section">
    <div class="section-title">🚨 Findings ({len(findings)} total)</div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Location</th><th>Description</th><th>Agent</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
    </div>
  </div>

  <!-- Remediation Roadmap -->
  {f'<div class="section"><div class="section-title">🗺️ Remediation Roadmap</div>{roadmap_html}</div>' if roadmap else ""}

  <!-- Enhancements -->
  {f'<div class="section"><div class="section-title">✨ Enhancement Recommendations</div>{enh_cards}</div>' if enhancements else ""}

  <div style="text-align:center;color:#1e293b;font-size:0.7rem;padding:24px 0">
    Generated by AI Code Review Platform · {data.get("generated_at","").split("T")[0]}
  </div>
</div>
</body>
</html>'''
