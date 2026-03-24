"""
Security Reviewer Agent

Advanced multi-layered LLM agent for security analysis.
Uses structured JSON output with OWASP/CWE classification,
confidence scoring, attack paths, and patch-level diffs.
"""

import json
import logging
import re
from typing import Dict, Any, Optional, List

from .base_agent import BaseAgent

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an advanced AI code security reviewer.

Your role: Perform deep, multi-layered code review combining static analysis validation,
security reasoning, multi-file context understanding, and actionable fixes.

ANALYSIS INSTRUCTIONS:
- Analyze code using OWASP Top 10 and CWE standards
- Validate and expand static analysis findings (Bandit, Semgrep, Ruff)
- Trace full data flow from input sources to sensitive sinks
- Detect chained vulnerabilities across functions and files
- Identify business logic flaws and security bypass scenarios
- Detect missing validation, improper authentication, insecure design patterns
- Identify performance inefficiencies and code quality issues
- Avoid hallucinations — only report issues with concrete evidence from the provided code
- Assign severity: LOW | MEDIUM | HIGH | CRITICAL (based on exploitability)
- Assign confidence score 0.0–1.0 (based on evidence strength)

CRITICAL: Always respond ONLY with valid JSON matching the output schema. No markdown, no prose.

OUTPUT SCHEMA:
{
  "summary": "Brief overall assessment",
  "findings": [
    {
      "id": "ISSUE-001",
      "title": "Short issue title",
      "description": "Detailed explanation with code evidence",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "confidence": 0.0,
      "location": {"file": "path/to/file.py", "line": 0},
      "owasp": "A01:2021",
      "cwe": "CWE-79",
      "evidence": "Exact code snippet proving the issue",
      "attack_path": ["user_input → vulnerable_function → database"],
      "fix": "Explanation of the fix",
      "diff": "--- original\\n+++ fixed\\n@@ ...@@\\n-old code\\n+new code",
      "source": ["static", "llm", "cve"],
      "related_ids": []
    }
  ],
  "metrics": {
    "complexity": "LOW|MEDIUM|HIGH",
    "maintainability": "LOW|MEDIUM|HIGH",
    "security_risk_score": 0
  }
}
"""


class SecurityReviewer(BaseAgent):
    """LLM agent for structured, deep security review"""

    def __init__(self, provider: str = None, model: str = None):
        super().__init__(provider, model)
        self.system_prompt = SYSTEM_PROMPT

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze code for security issues using the advanced prompt schema.

        Returns structured JSON with findings, metrics, and diffs.
        """
        prompt = self._build_prompt(code, context)
        response = self.generate(prompt, self.system_prompt)

        if not response:
            return {'agent': 'SecurityReviewer', 'error': 'No response from LLM', 'issues': []}

        parsed = self._parse_response(response)
        parsed['agent'] = 'SecurityReviewer'
        return parsed

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_prompt(self, code: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Build the full structured analysis prompt."""
        file_path = context.get('file_path', 'unknown') if context else 'unknown'
        language = context.get('language', 'python') if context else 'python'

        prompt_data: Dict[str, Any] = {
            "role": "advanced_ai_code_reviewer",
            "input": {
                "code": code[:8000],  # Cap to avoid token limits
                "file_path": file_path,
                "language": language,
            }
        }

        if context:
            # Static analysis findings
            static = context.get('static_analysis', [])
            if static:
                prompt_data["input"]["static_findings"] = [
                    {
                        "tool": i.get('tool', 'unknown'),
                        "severity": i.get('severity', 'info'),
                        "message": i.get('issue_text') or i.get('message', ''),
                        "line": i.get('line'),
                    }
                    for i in static[:20]  # Top 20 findings
                ]

            # Code metrics
            metrics = context.get('metrics', {})
            if metrics:
                prompt_data["input"]["ast_summary"] = {
                    "complexity": metrics.get('complexity', 'unknown'),
                    "functions": metrics.get('num_functions', 0),
                    "classes": metrics.get('num_classes', 0),
                    "loc": metrics.get('loc', 0),
                }

            # Related files / call graph
            if 'related_files' in context:
                prompt_data["input"]["related_files"] = context['related_files']
            if 'call_graph' in context:
                prompt_data["input"]["call_graph"] = context['call_graph']
            if 'data_flow' in context:
                prompt_data["input"]["data_flow"] = context['data_flow']
            if 'retrieved_context' in context:
                prompt_data["input"]["retrieved_context"] = context['retrieved_context'][:2000]

        prompt_data["instructions"] = [
            "Analyze using OWASP Top 10 and CWE standards",
            "Validate and expand the provided static_findings",
            "Trace data flow from input sources to sensitive sinks",
            "Detect chained vulnerabilities across functions",
            "Identify business logic flaws and auth bypass scenarios",
            "Detect missing validation and insecure design patterns",
            "Only report issues with concrete code evidence — no speculation",
            "Assign severity based on exploitability",
            "Provide minimal, safe, production-ready patch diffs",
        ]

        return json.dumps(prompt_data, indent=2)

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response, with fallback."""
        # Try direct parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON block from markdown-wrapped response
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding the first { ... } block
        brace_match = re.search(r'\{.*\}', response, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        # Fallback: wrap raw text into schema
        logger.warning("SecurityReviewer: Could not parse JSON response, wrapping as plain text")
        return {
            'summary': 'LLM response was not valid JSON — see raw analysis below.',
            'findings': [],
            'issues': [],
            'raw_analysis': response,
            'metrics': {
                'complexity': 'UNKNOWN',
                'maintainability': 'UNKNOWN',
                'security_risk_score': 0,
            }
        }

    # Backward compat: old code calls build_prompt
    def build_prompt(self, code: str, context: Optional[Dict[str, Any]] = None) -> str:
        return self._build_prompt(code, context)
