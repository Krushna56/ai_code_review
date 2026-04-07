"""
Orchestrator Agent — Coordinates the 4-agent pipeline and produces final merged analysis.

Uses OpenAI GPT-4o to:
  1. Wait for SecurityAgent, QualityAgent, DependencyAgent to finish
  2. Read all findings from the AgentBus
  3. Resolve conflicting severity ratings
  4. Deduplicate overlapping findings
  5. Generate prioritized remediation roadmap
  6. Produce final orchestration_summary
"""

import logging
import json
import re
import threading
from typing import Any, Dict, List, Optional

import config
from llm_agents.base_agent import BaseAgent
from llm_agents.agent_bus import AgentBus

logger = logging.getLogger(__name__)

ORCHESTRATOR_SYSTEM = """You are a principal security architect and technical lead who synthesizes
findings from multiple specialized security and quality agents.

Your job is to:
1. Merge and deduplicate findings from three agents (security, quality, dependency)
2. Resolve conflicting severity ratings with reasoning
3. Generate a prioritized remediation roadmap (what to fix first and why)
4. Identify systemic patterns (e.g. "SQLi in 3 files suggests no ORM usage policy")
5. Generate enhancement recommendations for the codebase architecture

Respond ONLY in valid JSON:
{
  "merged_findings": [
    {
      "id": "FINAL-001",
      "title": "...",
      "severity": "critical|high|medium|low|info",
      "source_agents": ["security", "quality"],
      "category": "security|quality|dependency",
      "file": "...", "line": 0,
      "description": "...",
      "remediation": "...",
      "priority": 1
    }
  ],
  "remediation_roadmap": [
    {"phase": 1, "title": "Immediate (0-7 days)", "items": ["Fix SQL injection in auth.py", "..."]},
    {"phase": 2, "title": "Short-term (1-4 weeks)", "items": ["Upgrade django to 4.x", "..."]},
    {"phase": 3, "title": "Long-term (1-3 months)", "items": ["Refactor monolith auth module", "..."]}
  ],
  "enhancements": [
    {"title": "Add SAST pipeline to CI/CD", "description": "...", "priority": "high"},
    {"title": "Migrate to parameterized queries", "description": "...", "priority": "critical"},
    {"title": "Implement structured logging", "description": "...", "priority": "medium"}
  ],
  "systemic_patterns": ["No input validation layer", "Missing authentication middleware in 3 routes"],
  "overall_risk_score": 6.2,
  "executive_summary": "3-4 sentence summary suitable for a CTO/VP Engineering audience"
}
"""


class OrchestratorAgent(BaseAgent):
    """
    OpenAI GPT-4o powered orchestrator that coordinates the full agent pipeline
    and produces synthesized findings + remediation roadmap + enhancements.
    """

    AGENT_NAME = 'orchestrator'
    WAIT_TIMEOUT = 240  # seconds to wait for other agents

    def __init__(self):
        # Force OpenAI for orchestration + report writing
        try:
            from openai import OpenAI
            self._openai_client = OpenAI(api_key=config.OPENAI_API_KEY)
            self._use_openai_direct = True
            self.provider = 'openai'
            self.model = 'gpt-4o'
            self.temperature = 0.15
            self.max_tokens = 6000
            self._llm_client = None
            self.client = None
            logger.info("[OrchestratorAgent] Initialized with OpenAI GPT-4o (direct)")
        except Exception as e:
            logger.warning(f"[OrchestratorAgent] OpenAI init failed: {e}, using BaseAgent fallback")
            self._use_openai_direct = False
            super().__init__()

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Direct analyze() call — builds orchestration from pre-collected findings."""
        all_findings = (context or {}).get('all_findings', {})
        agent_summaries = (context or {}).get('agent_summaries', {})
        prompt = self._build_orchestration_prompt(all_findings, agent_summaries, code)
        try:
            raw = self._call_openai(prompt)
            return self._parse_json_response(raw)
        except Exception as e:
            logger.error(f"[OrchestratorAgent] Analysis failed: {e}", exc_info=True)
            return self._fallback_merge(all_findings)

    def run_on_bus(self, code: str, bus: AgentBus, context: Optional[Dict] = None):
        """
        Wait for all specialist agents, then orchestrate their findings.
        This runs AFTER security, quality, dependency agents have started.
        """
        bus.set_status(self.AGENT_NAME, 'running', 5, 'Orchestrator waiting for specialist agents...')
        try:
            # Wait for all 3 specialist agents (with timeout)
            specialist_agents = ['security', 'quality', 'dependency']

            # Poll with progress updates every 5 seconds
            import time
            wait_deadline = time.time() + self.WAIT_TIMEOUT
            agents_done = set()

            while time.time() < wait_deadline:
                snapshot = bus.get_snapshot()
                currently_done = {
                    name for name in specialist_agents
                    if snapshot['agents'].get(name, {}).get('status') in ('done', 'error')
                }
                newly_done = currently_done - agents_done
                if newly_done:
                    agents_done.update(newly_done)
                    done_count = len(agents_done)
                    pct = 5 + int((done_count / 3) * 35)
                    bus.set_status(
                        self.AGENT_NAME, 'running', pct,
                        f'Received results from {done_count}/3 agents: {", ".join(sorted(agents_done))}'
                    )

                if len(agents_done) == 3:
                    break
                time.sleep(3)

            # Collect all findings
            bus.set_status(self.AGENT_NAME, 'running', 45, 'Merging findings from all agents...')
            all_findings = bus.collect_findings()
            agent_summaries = {
                'security': bus.read('security', 'summary') or '',
                'quality': bus.read('quality', 'summary') or '',
                'dependency': bus.read('dependency', 'summary') or '',
                'security_score': bus.read('security', 'security_score') or 5.0,
                'quality_score': bus.read('quality', 'quality_score') or 5.0,
                'dependency_risk_score': bus.read('dependency', 'dependency_risk_score') or 5.0,
                'tech_debt_hours': bus.read('quality', 'tech_debt_hours') or 0,
            }

            bus.set_status(self.AGENT_NAME, 'running', 60, 'AI synthesis: generating unified analysis...')

            orchestration_ctx = dict(context or {})
            orchestration_ctx['all_findings'] = all_findings
            orchestration_ctx['agent_summaries'] = agent_summaries

            result = self.analyze(code, orchestration_ctx)

            # Publish orchestration results
            bus.post(self.AGENT_NAME, 'merged_findings', result.get('merged_findings', []))
            bus.post(self.AGENT_NAME, 'remediation_roadmap', result.get('remediation_roadmap', []))
            bus.post(self.AGENT_NAME, 'enhancements', result.get('enhancements', []))
            bus.post(self.AGENT_NAME, 'systemic_patterns', result.get('systemic_patterns', []))
            bus.post(self.AGENT_NAME, 'overall_risk_score', result.get('overall_risk_score', 5.0))
            bus.post(self.AGENT_NAME, 'executive_summary', result.get('executive_summary', ''))
            bus.post(self.AGENT_NAME, 'raw_result', result)

            # Count final findings
            total_issues = len(result.get('merged_findings', []))
            bus.set_status(self.AGENT_NAME, 'running', 95,
                           f'Orchestration complete — {total_issues} unified findings')
            bus.mark_done(self.AGENT_NAME, f'Analysis pipeline complete — {total_issues} findings')

        except Exception as e:
            logger.error(f"[OrchestratorAgent] Bus run failed: {e}", exc_info=True)
            # Fallback: collect raw findings
            all_findings = bus.collect_findings()
            merged = self._fallback_merge(all_findings)
            bus.post(self.AGENT_NAME, 'merged_findings', merged.get('merged_findings', []))
            bus.post(self.AGENT_NAME, 'error', str(e))
            bus.mark_error(self.AGENT_NAME, str(e))

    # ── Internal helpers ────────────────────────────────────────────────────

    def _call_openai(self, prompt: str) -> str:
        if self._use_openai_direct:
            response = self._openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": ORCHESTRATOR_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content
        else:
            return self.generate(prompt, ORCHESTRATOR_SYSTEM) or '{}'

    def _build_orchestration_prompt(self, all_findings: Dict, agent_summaries: Dict, code: str) -> str:
        # Format findings for the prompt
        findings_str = json.dumps(all_findings, indent=2)[:10000]
        summaries_str = json.dumps(agent_summaries, indent=2)

        code_preview = code[:3000] if len(code) > 3000 else code

        return f"""Synthesize the findings from 3 specialist analysis agents:

## Agent Summaries
{summaries_str}

## Raw Findings (by agent)
{findings_str}

## Code Preview (first 3000 chars)
```
{code_preview}
```

Your tasks:
1. Merge ALL findings, deduplicating overlaps between agents
2. Resolve severity conflicts (e.g. security says 'high', quality says 'medium' for same issue)
3. Re-prioritize by exploitability and business impact
4. Generate a 3-phase remediation roadmap
5. Suggest 5-8 architectural enhancements to prevent future issues
6. Identify systemic patterns across multiple findings
7. Write a 3-4 sentence executive summary for a CTO audience

Respond ONLY with valid JSON per the specified format."""

    def _fallback_merge(self, all_findings: Dict) -> Dict[str, Any]:
        """Simple merge without LLM when orchestration fails."""
        merged = []
        priority = 1
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        for agent_name, findings in all_findings.items():
            for f in findings:
                merged.append({
                    'id': f'FINAL-{priority:03d}',
                    'title': f.get('title', 'Unknown finding'),
                    'severity': f.get('severity', 'medium'),
                    'source_agents': [agent_name],
                    'category': agent_name,
                    'file': f.get('file', ''),
                    'line': f.get('line', 0),
                    'description': f.get('description', ''),
                    'remediation': f.get('remediation', f.get('recommendation', '')),
                    'priority': priority,
                })
                priority += 1

        merged.sort(key=lambda x: severity_order.get(x['severity'], 5))

        total = len(merged)
        critical = sum(1 for f in merged if f['severity'] == 'critical')
        high = sum(1 for f in merged if f['severity'] == 'high')

        return {
            'merged_findings': merged,
            'remediation_roadmap': [
                {'phase': 1, 'title': 'Immediate (0-7 days)', 'items': [f['title'] for f in merged if f['severity'] == 'critical'][:5]},
                {'phase': 2, 'title': 'Short-term (1-4 weeks)', 'items': [f['title'] for f in merged if f['severity'] == 'high'][:5]},
                {'phase': 3, 'title': 'Long-term (1-3 months)', 'items': [f['title'] for f in merged if f['severity'] in ('medium', 'low')][:5]},
            ],
            'enhancements': [],
            'systemic_patterns': [],
            'overall_risk_score': max(1.0, 10.0 - (critical * 2 + high * 0.5)),
            'executive_summary': f'Analysis found {total} total issues ({critical} critical, {high} high severity). Immediate remediation of critical findings is recommended.',
        }

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        if not raw:
            return self._fallback_merge({})
        clean = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
        clean = re.sub(r'\s*```$', '', clean.strip(), flags=re.MULTILINE)
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
            logger.warning("[OrchestratorAgent] Could not parse JSON response")
            return self._fallback_merge({})
