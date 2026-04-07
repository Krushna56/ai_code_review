"""
Security Agent — Mistral-powered OWASP/CWE vulnerability scanner.

Part of the 4-agent coordinated analysis pipeline.
Posts findings to AgentBus for the OrchestratorAgent to merge.
"""

import logging
import json
import re
from typing import Any, Dict, List, Optional

import config
from llm_agents.base_agent import BaseAgent
from llm_agents.agent_bus import AgentBus

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an elite application security engineer specializing in OWASP Top 10
and CWE vulnerability patterns. Your job: analyze code snippets for security vulnerabilities.

Always respond in valid JSON with this structure:
{
  "findings": [
    {
      "id": "SEC-001",
      "title": "SQL Injection via string concatenation",
      "severity": "critical|high|medium|low|info",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "file": "relative/path.py",
      "line": 42,
      "code_snippet": "...",
      "description": "...",
      "remediation": "...",
      "confidence": "high|medium|low"
    }
  ],
  "security_score": 7.5,
  "summary": "Brief summary of security posture"
}

Be precise. Do not invent findings that are not in the code. Focus on exploitable vulnerabilities.
"""


class SecurityAgent(BaseAgent):
    """
    Mistral-powered security analysis agent.

    Scans code for:
      - Injection vulnerabilities (SQL, command, LDAP, XPath)
      - Authentication & session flaws
      - Sensitive data exposure
      - Path traversal / SSRF
      - Hardcoded credentials
      - Insecure deserialization
    """

    AGENT_NAME = 'security'

    def __init__(self):
        # Force Mistral provider for security analysis
        try:
            from mistralai import Mistral
            self._mistral_client = Mistral(api_key=config.MISTRAL_API_KEY)
            self._use_mistral_direct = True
            self.provider = 'mistral'
            self.model = 'mistral-large-latest'
            self.temperature = 0.1
            self.max_tokens = 4096
            self._llm_client = None
            self.client = None
            logger.info("[SecurityAgent] Initialized with Mistral (direct)")
        except Exception as e:
            logger.warning(f"[SecurityAgent] Mistral init failed: {e}, using BaseAgent fallback")
            self._use_mistral_direct = False
            super().__init__()

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run security analysis on code content.

        Args:
            code: Full code content or concatenated file contents
            context: Optional dict with file paths, language info

        Returns:
            Dict with 'findings', 'security_score', 'summary'
        """
        language = (context or {}).get('language', 'unknown')
        file_list = (context or {}).get('files', [])

        prompt = self._build_security_prompt(code, language, file_list)

        try:
            raw = self._call_mistral(prompt)
            result = self._parse_json_response(raw)
            logger.info(f"[SecurityAgent] Found {len(result.get('findings', []))} security issues")
            return result
        except Exception as e:
            logger.error(f"[SecurityAgent] Analysis failed: {e}", exc_info=True)
            return {'findings': [], 'security_score': 5.0, 'summary': f'Security analysis failed: {e}', 'error': str(e)}

    def run_on_bus(self, code: str, bus: AgentBus, context: Optional[Dict] = None):
        """Execute analysis and publish results to the AgentBus."""
        bus.set_status(self.AGENT_NAME, 'running', 5, 'Security agent initializing...')
        try:
            bus.set_status(self.AGENT_NAME, 'running', 20, 'Scanning for OWASP vulnerabilities...')
            result = self.analyze(code, context)

            bus.set_status(self.AGENT_NAME, 'running', 70, 'Processing injection & auth vulnerabilities...')
            findings = result.get('findings', [])

            # Enrich findings with agent metadata
            for f in findings:
                f['agent'] = self.AGENT_NAME
                f['provider'] = 'mistral'

            bus.post(self.AGENT_NAME, 'findings', findings)
            bus.post(self.AGENT_NAME, 'security_score', result.get('security_score', 5.0))
            bus.post(self.AGENT_NAME, 'summary', result.get('summary', ''))
            bus.post(self.AGENT_NAME, 'raw_result', result)

            bus.set_status(self.AGENT_NAME, 'running', 90, f'Found {len(findings)} security issues')
            bus.mark_done(self.AGENT_NAME, f'Security scan complete — {len(findings)} findings')

        except Exception as e:
            logger.error(f"[SecurityAgent] Bus run failed: {e}", exc_info=True)
            bus.post(self.AGENT_NAME, 'findings', [])
            bus.post(self.AGENT_NAME, 'error', str(e))
            bus.mark_error(self.AGENT_NAME, str(e))

    # ── Internal helpers ────────────────────────────────────────────────────

    def _call_mistral(self, prompt: str) -> str:
        if self._use_mistral_direct:
            response = self._mistral_client.chat.complete(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content
        else:
            return self.generate(prompt, SYSTEM_PROMPT) or '{}'

    def _build_security_prompt(self, code: str, language: str, files: List[str]) -> str:
        file_context = '\n'.join(f'  - {f}' for f in files[:20]) if files else '  (unknown files)'
        # Truncate code to avoid token limits
        code_snippet = code[:12000] if len(code) > 12000 else code
        return f"""Perform a comprehensive security audit of the following {language} codebase.

Files analyzed:
{file_context}

Code:
```{language}
{code_snippet}
```

Check for ALL of the following:
1. Injection (SQL, Command, LDAP, XPath, Template)
2. Broken Authentication & Session Management
3. Sensitive Data Exposure (hardcoded secrets, API keys, passwords)
4. XML External Entities (XXE)
5. Broken Access Control (path traversal, IDOR, SSRF)
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

Respond ONLY with valid JSON matching the specified format. Include line numbers where possible."""

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        if not raw:
            return {'findings': [], 'security_score': 5.0, 'summary': 'No response from model'}

        # Strip markdown code fences
        clean = re.sub(r'^```(?:json)?\s*', '', raw.strip(), flags=re.MULTILINE)
        clean = re.sub(r'\s*```$', '', clean.strip(), flags=re.MULTILINE)

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            # Try to extract JSON object from mixed content
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except Exception:
                    pass
            logger.warning("[SecurityAgent] Could not parse JSON response")
            return {'findings': [], 'security_score': 5.0, 'summary': 'Parse error', 'raw': raw[:500]}
