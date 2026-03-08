"""
LLM Metrics Extractor
======================
Uses the Gemini LLM to extract all dashboard metrics from static analysis results.
This produces structured JSON data covering security rating, technical debt,
defect density, issue type breakdown, file risk scores, and OWASP coverage.

The extractor is called once per analysis after all static and CVE analysis
is complete, adding 3-8 seconds of additional time.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

import config

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Metrics schema with defaults (used when LLM fails or is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_METRICS: Dict[str, Any] = {
    "total_issues": 0,
    "critical_count": 0,
    "security_rating": 10.0,
    "technical_debt_hours": 0.0,
    "code_coverage_estimate": 0.0,
    "duplication_percent": 0.0,
    "defect_density": 0.0,
    "ai_code_percent": 0.0,
    "mttr_days": 0.0,
    "total_loc": 0,
    "total_files": 0,
    "severity_distribution": {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    },
    "issue_type_distribution": {
        "bugs": 0, "vulnerabilities": 0, "code_smells": 0, "performance": 0
    },
    "file_risk_scores": [],
    "owasp_coverage": [],
    "top_hotspots": [],
}


# ─────────────────────────────────────────────────────────────────────────────
# LLM Prompt
# ─────────────────────────────────────────────────────────────────────────────

METRICS_PROMPT = """
You are a senior code quality analyst. Given the following static analysis results
for a codebase, extract and compute structured metrics.

=== STATIC ANALYSIS DATA ===
{analysis_data}

=== FILE-LEVEL DATA ===
{file_data}
=== END DATA ===

Return ONLY a valid JSON object. No markdown, no explanation, just JSON.
Use EXACTLY this structure:

{{
  "total_issues": <integer total of all issues across all severities>,
  "critical_count": <integer count of CRITICAL + HIGH severity issues>,
  "security_rating": <float 0-10, formula: 10 - (critical*1.5 + high*0.5 + medium*0.1), min 0>,
  "technical_debt_hours": <float, formula: total_issues * 0.5 (30 min per issue average)>,
  "code_coverage_estimate": <float 0-100, estimate from test files ratio>,
  "duplication_percent": <float 0-100, estimate from repeated code patterns or 5.0 if unknown>,
  "defect_density": <float, formula: (total_issues / max(1, total_loc)) * 1000, round to 2 decimals>,
  "ai_code_percent": <float 0-100, return 0 unless AI patterns detected>,
  "mttr_days": <float, estimate 3.0 for critical, 1.5 for high, 0.5 for medium/low weighted avg>,
  "total_loc": <integer total lines of code>,
  "total_files": <integer count of analyzed files>,
  "severity_distribution": {{
    "CRITICAL": <int>,
    "HIGH": <int>,
    "MEDIUM": <int>,
    "LOW": <int>,
    "INFO": <int>
  }},
  "issue_type_distribution": {{
    "bugs": <int, logic errors + null refs + type errors>,
    "vulnerabilities": <int, security issues + CVEs + injection + XSS>,
    "code_smells": <int, style + complexity + duplication>,
    "performance": <int, memory + inefficient loops + resource leaks>
  }},
  "file_risk_scores": [
    {{"file": "<relative path>", "score": <int 0-100>, "issues": <int>, "churn": <int 0 if unknown>}}
  ],
  "owasp_coverage": [
    {{"category": "<OWASP ID e.g. A01:2021>", "name": "<short name>", "count": <int>}}
  ],
  "top_hotspots": [
    {{"file": "<relative path>", "complexity": <int>, "churn": <int>, "issues": <int>}}
  ]
}}

Rules:
- security_rating must be between 0 and 10 (float)
- defect_density = (total_issues / max(1, total_loc)) * 1000, rounded to 2 decimal places
- technical_debt_hours = total_issues * 0.5
- If total_issues = 0, security_rating = 10.0
- file_risk_scores: list the top 10 riskiest files only (most issues first)
- owasp_coverage: only include categories that have at least 1 issue
- top_hotspots: at most 10 files, sorted by issues+complexity descending
- mttr_days formula: (critical_count*3 + high_count*1.5 + medium_count*0.5) / max(1, total_issues)
"""


class MetricsExtractor:
    """
    Uses the Gemini LLM to extract comprehensive code quality metrics
    from static analysis output.
    """

    def __init__(self):
        self._model = None
        self._available = False
        self._init_model()

    def _init_model(self):
        """Initialize the Gemini generative model."""
        try:
            import google.genai as genai
            genai.configure(api_key=config.GOOGLE_API_KEY)
            self._model = genai.GenerativeModel(
                model_name=getattr(config, 'GEMINI_MODEL', 'gemini-1.5-flash'),
                generation_config={
                    'temperature': 0.1,     # Low temperature for deterministic output
                    'max_output_tokens': 4096,
                }
            )
            self._available = True
            logger.info("MetricsExtractor: Gemini model initialized")
        except Exception as e:
            logger.warning(f"MetricsExtractor: Could not initialize Gemini - {e}")
            self._available = False

    def extract(
        self,
        linter_results: Dict[str, Any],
        security_findings: List[Dict],
        cve_count: int = 0,
        file_count: int = 0,
        total_loc: int = 0,
        file_details: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Extract all dashboard metrics using the LLM.

        Falls back to rule-based computation if LLM is unavailable.

        Args:
            linter_results:     Aggregated linter output dict from MultiLinter
            security_findings:  List of security finding dicts from SecretDetector + CVE
            cve_count:          Number of CVE vulnerabilities found
            file_count:         Number of files analyzed
            total_loc:          Total lines of code in the codebase
            file_details:       Dict mapping file → metrics (optional, from AST parser)

        Returns:
            Metrics dict conforming to DEFAULT_METRICS schema
        """
        if not self._available:
            logger.info("MetricsExtractor: LLM unavailable, using rule-based fallback")
            return self._rule_based_extract(
                linter_results, security_findings, cve_count, file_count, total_loc, file_details
            )

        try:
            metrics = self._llm_extract(
                linter_results, security_findings, cve_count, file_count, total_loc, file_details
            )
            # Validate and fill any missing keys with defaults
            return self._validate(metrics, total_loc, file_count)
        except Exception as e:
            logger.error(f"MetricsExtractor LLM extraction failed: {e}, using rule-based fallback")
            return self._rule_based_extract(
                linter_results, security_findings, cve_count, file_count, total_loc, file_details
            )

    def _llm_extract(
        self,
        linter_results: Dict,
        security_findings: List[Dict],
        cve_count: int,
        file_count: int,
        total_loc: int,
        file_details: Optional[Dict],
    ) -> Dict[str, Any]:
        """Call the Gemini LLM with a structured prompt to extract metrics."""

        # ── Summarise analysis data for the prompt ──
        issues_by_severity = linter_results.get('by_severity', {})
        issues_list = linter_results.get('issues', [])

        # Build a concise summary (truncate if huge)
        analysis_summary = {
            'total_linter_issues': linter_results.get('total_issues', 0),
            'by_severity': issues_by_severity,
            'by_tool': linter_results.get('by_tool', {}),
            'sample_issues': issues_list[:30],          # first 30 for context
            'security_findings_count': len(security_findings),
            'security_findings_sample': security_findings[:10],
            'cve_count': cve_count,
            'total_loc': total_loc,
            'file_count': file_count,
        }

        # Build file-level summary
        file_summary = {}
        if file_details:
            for path, detail in list(file_details.items())[:50]:  # cap at 50 files
                metrics = detail.get('metrics', {})
                file_issues = [
                    i for i in issues_list
                    if path in str(i.get('file', ''))
                ]
                file_summary[path] = {
                    'loc': metrics.get('loc', 0),
                    'complexity': metrics.get('complexity', 0),
                    'issue_count': len(file_issues),
                }

        analysis_str = json.dumps(analysis_summary, indent=2)[:8000]   # token cap
        file_str = json.dumps(file_summary, indent=2)[:3000]

        prompt = METRICS_PROMPT.format(
            analysis_data=analysis_str,
            file_data=file_str,
        )

        resp = self._model.generate_content(prompt)
        raw = resp.text.strip()

        # Strip markdown code fences if present
        raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'```\s*$', '', raw, flags=re.MULTILINE)

        return json.loads(raw)

    def _rule_based_extract(
        self,
        linter_results: Dict,
        security_findings: List[Dict],
        cve_count: int,
        file_count: int,
        total_loc: int,
        file_details: Optional[Dict],
    ) -> Dict[str, Any]:
        """
        Deterministic rule-based metrics extraction when LLM is unavailable.
        Mirrors the formulas described in the LLM prompt.
        """
        issues = linter_results.get('issues', [])
        by_sev = linter_results.get('by_severity', {})

        total = linter_results.get('total_issues', 0) + len(security_findings)
        critical = by_sev.get('critical', 0) + by_sev.get('high', 0)
        high     = by_sev.get('high', 0)
        medium   = by_sev.get('medium', 0) + by_sev.get('warning', 0)
        low      = by_sev.get('low', 0) + by_sev.get('info', 0)

        # Security rating
        rating = max(0.0, 10.0 - (critical * 1.5 + high * 0.5 + medium * 0.1))
        rating = round(rating, 1)

        # Defect density
        density = round((total / max(1, total_loc)) * 1000, 2)

        # Technical debt
        debt_h = round(total * 0.5, 1)

        # MTTR
        mttr = round(
            (critical * 3 + high * 1.5 + medium * 0.5) / max(1, total), 2
        )

        # Severity distribution
        sev_dist = {
            'CRITICAL': by_sev.get('critical', 0),
            'HIGH':     by_sev.get('high', 0),
            'MEDIUM':   medium,
            'LOW':      low,
            'INFO':     by_sev.get('convention', 0),
        }

        # Issue type distribution from linter tool names
        bugs  = sum(1 for i in issues if i.get('tool') in ('pylint', 'flake8'))
        vulns = len(security_findings) + cve_count
        smells = sum(1 for i in issues if 'style' in str(i.get('issue_text','') + str(i.get('message',''))).lower())
        perfs  = sum(1 for i in issues if 'performance' in str(i.get('message', '')).lower())

        # File risk scores from issue counts per file
        file_issue_map: Dict[str, int] = {}
        for issue in issues:
            fpath = str(issue.get('file', ''))
            if fpath:
                file_issue_map[fpath] = file_issue_map.get(fpath, 0) + 1

        file_risk_scores = [
            {
                'file': fp.replace('\\', '/'),
                'score': min(100, cnt * 5),
                'issues': cnt,
                'churn': 0
            }
            for fp, cnt in sorted(file_issue_map.items(), key=lambda x: -x[1])[:10]
        ]

        # OWASP: use security findings categories
        owasp_map: Dict[str, Dict] = {}
        for f in security_findings:
            cat = f.get('owasp_category', 'A00:2021')
            name = f.get('owasp_name', 'Unknown')
            if cat not in owasp_map:
                owasp_map[cat] = {'category': cat, 'name': name, 'count': 0}
            owasp_map[cat]['count'] += 1
        owasp_list = list(owasp_map.values())

        # Top hotspots from file details
        hotspots = []
        if file_details:
            for path, detail in file_details.items():
                m = detail.get('metrics', {})
                hotspots.append({
                    'file': path.replace('\\', '/'),
                    'complexity': m.get('complexity', 0),
                    'churn': 0,
                    'issues': file_issue_map.get(path, 0),
                })
            hotspots.sort(key=lambda x: -(x['complexity'] + x['issues']))
            hotspots = hotspots[:10]

        return {
            'total_issues': total,
            'critical_count': critical,
            'security_rating': rating,
            'technical_debt_hours': debt_h,
            'code_coverage_estimate': 0.0,
            'duplication_percent': 5.0,
            'defect_density': density,
            'ai_code_percent': 0.0,
            'mttr_days': mttr,
            'total_loc': total_loc,
            'total_files': file_count,
            'severity_distribution': sev_dist,
            'issue_type_distribution': {
                'bugs':           bugs,
                'vulnerabilities': vulns,
                'code_smells':    smells,
                'performance':    perfs,
            },
            'file_risk_scores': file_risk_scores,
            'owasp_coverage': owasp_list,
            'top_hotspots': hotspots,
        }

    def _validate(self, metrics: Dict, total_loc: int, file_count: int) -> Dict:
        """Ensure all required keys exist and values are within valid ranges."""
        result = dict(DEFAULT_METRICS)
        result.update(metrics)

        # Clamp numeric ranges
        result['security_rating'] = max(0.0, min(10.0, float(result.get('security_rating', 10.0))))
        result['code_coverage_estimate'] = max(0.0, min(100.0, float(result.get('code_coverage_estimate', 0.0))))
        result['duplication_percent'] = max(0.0, min(100.0, float(result.get('duplication_percent', 0.0))))
        result['defect_density'] = max(0.0, float(result.get('defect_density', 0.0)))
        result['technical_debt_hours'] = max(0.0, float(result.get('technical_debt_hours', 0.0)))
        result['mttr_days'] = max(0.0, float(result.get('mttr_days', 0.0)))

        # Fill in actual counts if not set by LLM
        if not result.get('total_loc'):
            result['total_loc'] = total_loc
        if not result.get('total_files'):
            result['total_files'] = file_count

        return result
