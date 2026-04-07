"""
Quality Agent — Anthropic-powered code quality & tech-debt analyzer.

Part of the 4-agent coordinated analysis pipeline.
Reads SecurityAgent results from AgentBus to avoid duplicating high-risk findings
and to flag quality issues as "security-adjacent" when relevant.
"""

import logging
import json
import re
from typing import Any, Dict, List, Optional

import config
from llm_agents.base_agent import BaseAgent
from llm_agents.agent_bus import AgentBus

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior software engineer and code quality expert. Analyze code for:
- Code smells and anti-patterns
- Complexity (cyclomatic, cognitive)
- Technical debt (duplication, dead code, hard-to-test code)
- Performance issues (N+1 queries, memory leaks, blocking I/O)
- Maintainability and readability problems
- Missing error handling and defensive programming gaps
- Architectural concerns (tight coupling, missing abstractions)

Always respond in valid JSON:
{
  "findings": [
    {
      "id": "QA-001",
      "title": "High cyclomatic complexity in auth handler",
      "severity": "high|medium|low|info",
      "category": "complexity|smell|performance|error_handling|architecture|duplication|testing",
      "file": "relative/path.py",
      "line": 42,
      "code_snippet": "...",
      "description": "...",
      "recommendation": "...",
      "effort_hours": 2.5,
      "security_adjacent": false
    }
  ],
  "quality_score": 7.2,
  "tech_debt_hours": 18.5,
  "summary": "Brief quality assessment"
}

Be constructive. Prioritize actionable findings over nitpicks.
"""


class QualityAgent(BaseAgent):
    """
    Anthropic Claude-powered code quality analysis agent.

    Analyzes:
      - Code complexity & maintainability
      - Tech debt calculation
      - Performance anti-patterns
      - Error handling gaps
      - Architecture concerns

    Coordinates with SecurityAgent: reads its findings to mark
    quality issues that are also security-adjacent.
    """

    AGENT_NAME = 'quality'

    def __init__(self):
        # Force Anthropic provider for quality analysis
        try:
            from anthropic import Anthropic
            self._anthropic_client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
            self._use_anthropic_direct = True
            self.provider = 'anthropic'
            self.model = 'claude-3-5-sonnet-20241022'
            self.temperature = 0.1
            self.max_tokens = 4096
            self._llm_client = None
            self.client = None
            logger.info("[QualityAgent] Initialized with Anthropic Claude (direct)")
        except Exception as e:
            logger.warning(f"[QualityAgent] Anthropic init failed: {e}, using BaseAgent fallback")
            self._use_anthropic_direct = False
            super().__init__()

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run quality analysis on code content."""
        language = (context or {}).get('language', 'unknown')
        file_list = (context or {}).get('files', [])
        security_findings = (context or {}).get('security_findings', [])

        prompt = self._build_quality_prompt(code, language, file_list, security_findings)

        try:
            raw = self._call_anthropic(prompt)
            result = self._parse_json_response(raw)
            logger.info(f"[QualityAgent] Found {len(result.get('findings', []))} quality issues")
            return result
        except Exception as e:
            logger.error(f"[QualityAgent] Analysis failed: {e}", exc_info=True)
            return {
                'findings': [], 'quality_score': 5.0,
                'tech_debt_hours': 0, 'summary': f'Quality analysis failed: {e}', 'error': str(e)
            }

    def run_on_bus(self, code: str, bus: AgentBus, context: Optional[Dict] = None):
        """Execute quality analysis and publish results to the AgentBus."""
        bus.set_status(self.AGENT_NAME, 'running', 5, 'Quality agent starting...')
        try:
            bus.set_status(self.AGENT_NAME, 'running', 15, 'Analyzing code complexity...')

            # Read security findings if available (coordination!)
            security_findings = bus.read('security', 'findings') or []
            enriched_context = dict(context or {})
            enriched_context['security_findings'] = security_findings

            if security_findings:
                bus.set_status(self.AGENT_NAME, 'running', 20,
                               f'Coordinating with SecurityAgent ({len(security_findings)} findings)...')

            result = self.analyze(code, enriched_context)

            bus.set_status(self.AGENT_NAME, 'running', 75, 'Calculating tech debt hours...')
            findings = result.get('findings', [])

            for f in findings:
                f['agent'] = self.AGENT_NAME
                f['provider'] = 'anthropic'

            bus.post(self.AGENT_NAME, 'findings', findings)
            bus.post(self.AGENT_NAME, 'quality_score', result.get('quality_score', 5.0))
            bus.post(self.AGENT_NAME, 'tech_debt_hours', result.get('tech_debt_hours', 0))
            bus.post(self.AGENT_NAME, 'summary', result.get('summary', ''))
            bus.post(self.AGENT_NAME, 'raw_result', result)

            bus.set_status(self.AGENT_NAME, 'running', 90,
                           f'{len(findings)} quality issues, {result.get("tech_debt_hours", 0)}h debt')
            bus.mark_done(self.AGENT_NAME, f'Quality scan complete — {len(findings)} issues')

        except Exception as e:
            logger.error(f"[QualityAgent] Bus run failed: {e}", exc_info=True)
            bus.post(self.AGENT_NAME, 'findings', [])
            bus.post(self.AGENT_NAME, 'error', str(e))
            bus.mark_error(self.AGENT_NAME, str(e))

    # ── Internal helpers ────────────────────────────────────────────────────

    def _call_anthropic(self, prompt: str) -> str:
        if self._use_anthropic_direct:
            response = self._anthropic_client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        else:
            return self.generate(prompt, SYSTEM_PROMPT) or '{}'

    def _build_quality_prompt(self, code: str, language: str,
                               files: List[str], security_findings: List[Dict]) -> str:
        file_ctx = '\n'.join(f'  - {f}' for f in files[:20]) or '  (unknown)'
        # Security context for coordination
        sec_ctx = ''
        if security_findings:
            sec_summary = '\n'.join(
                f"  - [{f.get('severity','?').upper()}] {f.get('title','?')} @ {f.get('file','?')}:{f.get('line','?')}"
                for f in security_findings[:10]
            )
            sec_ctx = f"""
The SecurityAgent has already found these vulnerabilities (do NOT duplicate them, but mark related quality issues as security_adjacent=true):
{sec_summary}
"""
        code_snippet = code[:12000] if len(code) > 12000 else code
        return f"""Perform a comprehensive code quality review of this {language} codebase.

Files:
{file_ctx}
{sec_ctx}

Code:
```{language}
{code_snippet}
```

Analyze for:
1. Code complexity (cyclomatic > 10 is high risk)
2. Code smells (God classes, long methods, feature envy, etc.)
3. Technical debt (calculate effort_hours per finding)
4. Performance issues (N+1, blocking I/O, memory leaks)
5. Error handling gaps (bare except, swallowed exceptions)
6. Dead code and unused imports
7. Test coverage gaps (identify untestable code)
8. Architecture concerns (tight coupling, missing abstractions)

Respond ONLY with valid JSON."""

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        if not raw:
            return {'findings': [], 'quality_score': 5.0, 'tech_debt_hours': 0, 'summary': 'No response'}
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
            logger.warning("[QualityAgent] Could not parse JSON response")
            return {'findings': [], 'quality_score': 5.0, 'tech_debt_hours': 0, 'summary': 'Parse error'}
