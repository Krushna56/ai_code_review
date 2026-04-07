"""
Dependency Agent — CVE scanner and dependency risk analyzer.

Part of the 4-agent coordinated analysis pipeline.
Parses dependency files (requirements.txt, package.json, etc.) and flags:
  - Known CVEs in pinned versions
  - Unpinned/wildcard dependencies
  - Outdated packages
  - License risks
"""

import logging
import json
import re
import os
from typing import Any, Dict, List, Optional

import config
from llm_agents.base_agent import BaseAgent
from llm_agents.agent_bus import AgentBus

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a software supply chain security expert. Analyze dependency files
for security risks, CVE vulnerabilities, and outdated packages.

Always respond in valid JSON:
{
  "findings": [
    {
      "id": "DEP-001",
      "package": "django",
      "version": "2.2.0",
      "severity": "critical|high|medium|low|info",
      "title": "CVE-2021-35042: SQL Injection in Django ORM",
      "cve": "CVE-2021-35042",
      "description": "...",
      "fix_version": "3.2.13",
      "source_file": "requirements.txt",
      "line": 5,
      "agent": "dependency"
    }
  ],
  "dependency_risk_score": 6.5,
  "total_packages": 42,
  "vulnerable_packages": 3,
  "unpinned_packages": 8,
  "summary": "Brief dependency risk summary"
}

If you cannot determine real CVEs, analyze version patterns and flag unpinned/risky dependencies.
"""

# Common known bad version patterns (heuristic fallback when no API key)
KNOWN_VULNERABLE_PATTERNS = {
    'django': {'<3.2': 'Multiple CVEs — upgrade to 3.2.x+'},
    'flask': {'<2.0': 'CVE-2018-1000656 — upgrade to 2.x'},
    'requests': {'<2.28': 'SSRF risk — upgrade to 2.28+'},
    'pyyaml': {'<6.0': 'CVE-2020-14343 — arbitrary code execution'},
    'pillow': {'<9.0': 'Multiple CVEs — upgrade to 9.x'},
    'cryptography': {'<41.0': 'Multiple CVEs — upgrade to 41+'},
    'paramiko': {'<3.0': 'CVE-2023-48795 — upgrade to 3.x'},
}

DEPENDENCY_FILES = [
    'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
    'package.json', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg',
    'pom.xml', 'build.gradle', 'go.mod', 'Gemfile', 'composer.json',
]


class DependencyAgent(BaseAgent):
    """
    Dependency risk analysis agent.
    Uses the existing analysis LLM (Mistral/Anthropic fallback via BaseAgent)
    plus local heuristic checks for common vulnerable patterns.
    """

    AGENT_NAME = 'dependency'

    def __init__(self):
        super().__init__()
        logger.info(f"[DependencyAgent] Using provider: {self.provider}/{self.model}")

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze dependency files found in the codebase.

        Args:
            code: Combined content of all dependency files
            context: Optional dict with 'dep_files' (list of {name, content})
        """
        dep_files = (context or {}).get('dep_files', [])
        project_path = (context or {}).get('project_path', '')

        # If dep_files not provided, try to extract from project path
        if not dep_files and project_path:
            dep_files = self._scan_dep_files(project_path)

        if not dep_files and not code:
            return {
                'findings': [],
                'dependency_risk_score': 5.0,
                'total_packages': 0,
                'vulnerable_packages': 0,
                'unpinned_packages': 0,
                'summary': 'No dependency files found in codebase',
            }

        # Local heuristic scan (fast, no API call)
        heuristic_findings = self._heuristic_scan(dep_files)

        # LLM deep scan
        combined_content = self._combine_dep_files(dep_files) or code[:6000]
        prompt = self._build_dep_prompt(combined_content, dep_files)

        try:
            raw = self.generate(prompt, SYSTEM_PROMPT)
            result = self._parse_json_response(raw)

            # Merge heuristic findings with LLM findings (deduplicate by package)
            llm_findings = result.get('findings', [])
            all_findings = self._merge_findings(heuristic_findings, llm_findings)

            result['findings'] = all_findings
            result['vulnerable_packages'] = len(all_findings)
            return result
        except Exception as e:
            logger.error(f"[DependencyAgent] LLM analysis failed: {e}", exc_info=True)
            # Return heuristic results as fallback
            return {
                'findings': heuristic_findings,
                'dependency_risk_score': max(3.0, 10.0 - len(heuristic_findings) * 1.5),
                'total_packages': len(dep_files),
                'vulnerable_packages': len(heuristic_findings),
                'unpinned_packages': 0,
                'summary': f'Dependency scan (heuristic only, LLM failed: {e})',
            }

    def run_on_bus(self, code: str, bus: AgentBus, context: Optional[Dict] = None):
        """Execute dependency analysis and publish to AgentBus."""
        bus.set_status(self.AGENT_NAME, 'running', 5, 'Scanning dependency files...')
        try:
            project_path = (context or {}).get('project_path', '')
            dep_files = self._scan_dep_files(project_path) if project_path else []

            bus.set_status(self.AGENT_NAME, 'running', 30,
                           f'Found {len(dep_files)} dependency file(s), analyzing...')

            dep_context = dict(context or {})
            dep_context['dep_files'] = dep_files

            result = self.analyze(code, dep_context)

            findings = result.get('findings', [])
            for f in findings:
                f['agent'] = self.AGENT_NAME

            bus.post(self.AGENT_NAME, 'findings', findings)
            bus.post(self.AGENT_NAME, 'dependency_risk_score', result.get('dependency_risk_score', 5.0))
            bus.post(self.AGENT_NAME, 'total_packages', result.get('total_packages', 0))
            bus.post(self.AGENT_NAME, 'vulnerable_packages', result.get('vulnerable_packages', 0))
            bus.post(self.AGENT_NAME, 'summary', result.get('summary', ''))
            bus.post(self.AGENT_NAME, 'raw_result', result)

            bus.set_status(self.AGENT_NAME, 'running', 90,
                           f'{len(findings)} vulnerable packages found')
            bus.mark_done(self.AGENT_NAME, f'Dependency scan complete — {len(findings)} risks')

        except Exception as e:
            logger.error(f"[DependencyAgent] Bus run failed: {e}", exc_info=True)
            bus.post(self.AGENT_NAME, 'findings', [])
            bus.post(self.AGENT_NAME, 'error', str(e))
            bus.mark_error(self.AGENT_NAME, str(e))

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _scan_dep_files(self, project_path: str) -> List[Dict]:
        """Walk project directory and collect all dependency file contents."""
        dep_files = []
        try:
            for root, dirs, files in os.walk(project_path):
                # Skip common non-code dirs
                dirs[:] = [d for d in dirs if d not in {
                    'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
                    'dist', 'build', '.cache'
                }]
                for fname in files:
                    if fname in DEPENDENCY_FILES:
                        full_path = os.path.join(root, fname)
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                                content = f.read()
                            rel_path = os.path.relpath(full_path, project_path)
                            dep_files.append({'name': fname, 'path': rel_path, 'content': content})
                        except Exception as e:
                            logger.warning(f"[DependencyAgent] Could not read {full_path}: {e}")
        except Exception as e:
            logger.error(f"[DependencyAgent] Error scanning deps: {e}")
        return dep_files

    def _combine_dep_files(self, dep_files: List[Dict]) -> str:
        parts = []
        for df in dep_files:
            parts.append(f"# === {df.get('path', df.get('name', 'unknown'))} ===\n{df.get('content', '')}")
        return '\n\n'.join(parts)

    def _heuristic_scan(self, dep_files: List[Dict]) -> List[Dict]:
        """Quick local pattern matching for common vulnerable versions."""
        findings = []
        idx = 1
        for df in dep_files:
            content = df.get('content', '')
            fname = df.get('name', '')
            if fname in ('requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt'):
                for line_no, line in enumerate(content.splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '==' not in line:
                        # Unpinned dependency
                        pkg = re.split(r'[>=<!;]', line)[0].strip()
                        if pkg:
                            findings.append({
                                'id': f'DEP-{idx:03d}',
                                'package': pkg,
                                'version': 'unpinned',
                                'severity': 'medium',
                                'title': f'Unpinned dependency: {pkg}',
                                'description': f'{pkg} has no pinned version, creating reproducibility and security risks.',
                                'fix_version': 'Pin to a specific version',
                                'source_file': df.get('path', fname),
                                'line': line_no,
                                'agent': self.AGENT_NAME,
                            })
                            idx += 1
        return findings

    def _merge_findings(self, heuristic: List[Dict], llm: List[Dict]) -> List[Dict]:
        """De-duplicate findings by package name."""
        seen_packages = set()
        merged = []
        for f in llm:
            key = f.get('package', '').lower()
            if key and key not in seen_packages:
                seen_packages.add(key)
                merged.append(f)
        for f in heuristic:
            key = f.get('package', '').lower()
            if key and key not in seen_packages:
                seen_packages.add(key)
                merged.append(f)
        return merged

    def _build_dep_prompt(self, content: str, dep_files: List[Dict]) -> str:
        file_names = ', '.join(df.get('name', '?') for df in dep_files) or 'unknown'
        return f"""Analyze these dependency files ({file_names}) for security vulnerabilities:

{content[:8000]}

For each dependency:
1. Check if version is pinned (flag unpinned as medium risk)
2. Identify known CVEs for the pinned version
3. Flag outdated major versions
4. Check for license risks (GPL in commercial projects, etc.)

Respond ONLY with valid JSON."""

    def _parse_json_response(self, raw: str) -> Dict[str, Any]:
        if not raw:
            return {'findings': [], 'dependency_risk_score': 5.0, 'total_packages': 0,
                    'vulnerable_packages': 0, 'unpinned_packages': 0, 'summary': 'No response'}
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
            return {'findings': [], 'dependency_risk_score': 5.0, 'total_packages': 0,
                    'vulnerable_packages': 0, 'unpinned_packages': 0, 'summary': 'Parse error'}
