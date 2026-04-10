"""
Report Service

Backend service for integrating Phase 4/5 security reports with the web dashboard.
Handles loading, caching, and transforming security data for API endpoints.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import os
from services.feedback_service import get_feedback_service

logger = logging.getLogger(__name__)


class ReportService:
    """Service for managing security reports and dashboard data"""

    def __init__(self, cache_ttl: int = 300):
        """
        Initialize report service

        Args:
            cache_ttl: Cache time-to-live in seconds (default: 5 minutes)
        """
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._cache_timestamps = {}
        self.reports_dir = Path(__file__).parent.parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)

    def get_latest_report(self, uid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get the most recent security report

        Args:
            uid: Optional analysis UID. If provided, loads from processed/{uid}/

        Returns:
            Latest security report dict or None if not found
        """
        # Check cache first (with uid-specific cache key)
        cache_key = f'latest_report_{uid}' if uid else 'latest_report'
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        # Determine search paths based on uid
        if uid:
            # Search in processed/{uid}/ first, then output/, then root
            search_paths = [
                Path('processed') / uid,
                Path('..') / 'output',
                Path('output'),
                Path('.')
            ]
        else:
            # Original behavior: search output/ then root
            search_paths = [
                Path('..') / 'output',
                Path('output'),
                Path('.')
            ]
            
            # Check processed directory for the latest report
            processed_dir = Path('processed')
            if processed_dir.exists() and processed_dir.is_dir():
                try:
                    # Get all subdirectories, sorted by modification time descending
                    subdirs = sorted([d for d in processed_dir.iterdir() if d.is_dir()], key=lambda x: x.stat().st_mtime, reverse=True)
                    # Add them to the beginning of search_paths
                    search_paths = subdirs + search_paths
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).warning("Could not sort processed dirs: %s", e)

        report_files = [
            'security_report.json',
            'comprehensive_report.json',
            'security-report.json'
        ]

        for search_dir in search_paths:
            for filename in report_files:
                report_path = search_dir / filename
                if report_path.exists():
                    try:
                        with open(report_path, 'r') as f:
                            report = json.load(f)

                        # Redact the entire report for safety
                        report = self._redact_recursive(report)

                        # Cache the report with uid-specific key
                        self._set_cache(cache_key, report)
                        logger.info(f"Loaded and redacted report from {report_path} for uid={uid}")
                        return report
                    except Exception as e:
                        logger.error(f"Error loading report {report_path}: {e}")

        # No report found, return sample data
        logger.warning(f"No security report found for uid={uid}, returning sample data")
        return self._get_sample_report()

    def _get_search_paths(self, uid: Optional[str]) -> list:
        """Return ordered list of Paths to search for data files."""
        if uid:
            return [
                Path('processed') / uid,
                Path('..') / 'output',
                Path('output'),
                Path('.')
            ]
        return [
            Path('..') / 'output',
            Path('output'),
            Path('.')
        ]

    def _load_json_from_paths(self, filenames: list, uid: Optional[str] = None) -> Optional[Dict]:
        """Try to load JSON from a list of filenames across all search paths."""
        for search_dir in self._get_search_paths(uid):
            for filename in filenames:
                path = search_dir / filename
                if path.exists():
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            return json.load(f)
                    except Exception as e:
                        logger.warning(f"Could not load {path}: {e}")
        return None

    def get_dashboard_data(self, uid: Optional[str] = None) -> Dict[str, Any]:
        """
        Get dashboard data for visualization — merges dashboard_data.json,
        metrics.json (LLM extracted), and git_timeline.json (commit history).
        """
        cache_key = f'dashboard_data_{uid}' if uid else 'dashboard_data'
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        # ── Load base dashboard data ──
        data = self._load_json_from_paths(
            ['dashboard_data.json', 'dashboard-data.json'], uid
        )
        if not data:
            report = self.get_latest_report(uid)
            if report and not report.get('is_sample'):
                data = self._generate_dashboard_from_report(report)
            else:
                data = {}  # No real data available

        # ── Merge LLM metrics for richer chart data ──
        llm_metrics = self._load_json_from_paths(['metrics.json'], uid)
        if llm_metrics:
            logger.info(f"Merging LLM metrics into dashboard data for uid={uid}")
            # Override/enrich specific chart datasets with LLM-extracted data
            if llm_metrics.get('severity_distribution'):
                data['severity_distribution'] = llm_metrics['severity_distribution']
                data['severity_counts']        = llm_metrics['severity_distribution']
            if llm_metrics.get('issue_type_distribution'):
                data['issue_type_distribution'] = llm_metrics['issue_type_distribution']
            if llm_metrics.get('file_risk_scores'):
                data['file_risk_scores'] = llm_metrics['file_risk_scores']
            if llm_metrics.get('owasp_coverage'):
                data['owasp_coverage'] = llm_metrics['owasp_coverage']
            if llm_metrics.get('top_hotspots'):
                data['code_hotspots'] = llm_metrics['top_hotspots']

        # ── Merge git timeline data ──
        git_timeline = self._load_json_from_paths(['git_timeline.json'], uid)
        if git_timeline:
            logger.info(
                f"Using git timeline for uid={uid}, "
                f"source={git_timeline.get('source','unknown')}, "
                f"commits={git_timeline.get('commit_count', 0)}"
            )
            data['vulnerability_trends'] = {
                'labels':   git_timeline.get('labels', []),
                'new':      git_timeline.get('new_issues', []),
                'resolved': git_timeline.get('resolved_issues', []),
                'source':   git_timeline.get('source', 'estimated'),
                'has_git':  git_timeline.get('has_git', False),
            }
        elif not data.get('vulnerability_trends'):
            # Generate fallback trends
            from git_analyzer import build_fallback_timeline
            total = llm_metrics.get('total_issues', 0) if llm_metrics else 0
            fb = build_fallback_timeline(total_issues=total, days=30)
            data['vulnerability_trends'] = {
                'labels':   fb['labels'],
                'new':      fb['new_issues'],
                'resolved': fb['resolved_issues'],
                'source':   'estimated',
                'has_git':  False,
            }

        self._set_cache(cache_key, data)
        return data


    def _calculate_security_rating(self, summary: Dict[str, Any]) -> float:
        """
        Calculate security rating on 0-10 scale using ideal formula
        
        Formula: Start at 10, deduct points based on severity
        - CRITICAL: -3 points each
        - HIGH: -1.5 points each  
        - MEDIUM: -0.5 points each
        - LOW: -0.1 points each
        """
        severity_dist = summary.get('severity_distribution', {})
        
        rating = 10.0
        rating -= severity_dist.get('CRITICAL', 0) * 3.0
        rating -= severity_dist.get('HIGH', 0) * 1.5
        rating -= severity_dist.get('MEDIUM', 0) * 0.5
        rating -= severity_dist.get('LOW', 0) * 0.1
        
        # Clamp between 0 and 10
        return max(0.0, min(10.0, round(rating, 1)))
    
    def get_summary(self, uid: Optional[str] = None) -> Dict[str, Any]:
        """
        Get executive summary data

        Args:
            uid: Optional analysis UID. If provided, loads from processed/{uid}/

        Returns:
            Summary metrics for dashboard header
        """
        report = self.get_latest_report(uid)
        if not report:
            return {}

        summary = report.get('executive_summary', {})
        metadata = report.get('metadata', {})
        
        # Calculate AI code percentage
        ai_code_percent = 0
        if uid:
            try:
                from services.ai_code_detector import get_ai_detector
                detector = get_ai_detector()
                upload_path = Path('uploads') / uid
                if upload_path.exists():
                    result = detector.analyze_project(str(upload_path))
                    ai_code_percent = result.get('ai_percentage', 0)
                    logger.info(f"AI code detection for {uid}: {ai_code_percent}%")
            except Exception as e:
                logger.error(f"Error detecting AI code: {e}")
                ai_code_percent = 0

        # ── Load LLM-extracted metrics if available ──
        llm_metrics = self._load_json_from_paths(['metrics.json'], uid)

        # Build base summary from security report
        base = {
            'risk_level':       summary.get('overall_risk_level', 'UNKNOWN'),
            'risk_score':       summary.get('risk_score', 0),
            'total_findings':   summary.get('total_findings', 0),
            'critical_count':   summary.get('severity_distribution', {}).get('CRITICAL', 0),
            'high_count':       summary.get('severity_distribution', {}).get('HIGH', 0),
            'cve_count':        summary.get('cve_count', 0),
            'dependency_health': report.get('dependency_health', {}).get('health_score', 0),
            'last_scan':        metadata.get('generated_at', datetime.now().isoformat()),
            # Dashboard redesign fields
            'total_files':      metadata.get('total_files', 0),
            'ai_code_percent':  ai_code_percent,
            'security_rating':  self._calculate_security_rating(summary),
            'security_count':   summary.get('security_issue_count', summary.get('total_findings', 0)),
            'severity_distribution': summary.get('severity_distribution', {}),
        }

        # Overlay LLM metrics where available
        if llm_metrics:
            logger.info(f"Merging LLM metrics into summary for uid={uid}")
            base.update({
                'total_findings':       llm_metrics.get('total_issues', base['total_findings']),
                'critical_count':       llm_metrics.get('critical_count', base['critical_count']),
                'security_rating':      llm_metrics.get('security_rating', base['security_rating']),
                'technical_debt_hours': llm_metrics.get('technical_debt_hours', 0),
                'defect_density':       llm_metrics.get('defect_density', 0),
                'duplication_percent':  llm_metrics.get('duplication_percent', 0),
                'code_coverage':        llm_metrics.get('code_coverage_estimate', 0),
                'mttr_days':            llm_metrics.get('mttr_days', 0),
                'total_loc':            llm_metrics.get('total_loc', 0),
                'total_files':          llm_metrics.get('total_files', base['total_files']),
                'severity_distribution': llm_metrics.get('severity_distribution', base['severity_distribution']),
                'ai_code_percent':      llm_metrics.get('ai_code_percent', ai_code_percent),
            })

        return base


    def get_findings(
        self,
        severity: Optional[str] = None,
        owasp_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        uid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get security findings with optional filtering

        Args:
            severity: Filter by severity level
            owasp_category: Filter by OWASP category
            limit: Max findings to return
            offset: Offset for pagination
            uid: Optional analysis UID. If provided, loads from processed/{uid}/

        Returns:
            Findings list with total count
        """
        report = self.get_latest_report(uid)
        if not report:
            return {'findings': [], 'total': 0}

        # Combine all findings
        all_findings = []
        all_findings.extend(report.get('security_findings', []))
        all_findings.extend(report.get('cve_findings', []))

        # Apply filters
        filtered = all_findings

        if severity:
            filtered = [f for f in filtered if f.get(
                'severity') == severity.upper()]

        if owasp_category:
            filtered = [f for f in filtered if f.get(
                'owasp_category') == owasp_category]

        # Apply pagination
        total = len(filtered)
        paginated = filtered[offset:offset + limit]

        # Enrich with feedback status and AI descriptions
        feedback_service = get_feedback_service()
        all_feedback = feedback_service.get_all_feedback()
        
        # Import description generator
        from services.description_generator import get_description_generator
        desc_gen = get_description_generator()
        
        for finding in paginated:
            fid = finding.get('id') or finding.get('cve_id')
            if fid and fid in all_feedback:
                finding['user_feedback'] = all_feedback[fid].get('feedback_type')
            
            # Generate AI description
            finding['ai_description'] = desc_gen.generate_description(finding)

        return {
            'findings': paginated,
            'total': total,
            'offset': offset,
            'limit': limit
        }

    def get_finding_by_id(self, finding_id: str, uid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific finding

        Args:
            finding_id: Finding identifier
            uid: Optional analysis UID. If provided, loads from processed/{uid}/

        Returns:
            Finding details or None if not found
        """
        report = self.get_latest_report(uid)
        if not report:
            return None

        # Search in all findings
        all_findings = []
        all_findings.extend(report.get('security_findings', []))
        all_findings.extend(report.get('cve_findings', []))

        for finding in all_findings:
            if finding.get('id') == finding_id or finding.get('cve_id') == finding_id:
                # Add fix suggestion if available
                finding['fix_suggestion'] = self._get_fix_suggestion(
                    finding_id)
                
                # Add feedback status
                feedback_service = get_feedback_service()
                feedback = feedback_service.get_feedback_by_finding(finding_id)
                if feedback:
                    finding['user_feedback'] = feedback.get('feedback_type')
                    
                return finding

        return None

    def get_remediation_plan(self, uid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get prioritized remediation plan

        Args:
            uid: Optional analysis UID. If provided, loads from processed/{uid}/

        Returns:
            List of remediation items sorted by priority
        """
        report = self.get_latest_report(uid)
        if not report:
            return []

        return report.get('remediation_plan', [])

    def generate_ai_report(self, uid: Optional[str] = None) -> str:
        """
        Generate a final markdown report using the OpenAI ReportAgent.
        
        Args:
            uid: Optional analysis UID.
            
        Returns:
            Markdown-formatted AI-written report string
        """
        report = self.get_latest_report(uid)
        if not report or report.get('is_sample'):
            return "No report data available to generate AI report."
            
        findings = report.get('security_findings', []) + report.get('cve_findings', [])
        summary = self.get_summary(uid)
        
        from llm_agents.report_agent import ReportAgent
        agent = ReportAgent()
        
        logger.info(f"Generating AI final report via ReportAgent for uid={uid}")
        md_report = agent.generate_report(findings=findings, summary=summary)
        
        # Save it to the processed output folder
        if uid:
            search_paths = self._get_search_paths(uid)
            for path in search_paths:
                if path.exists() and path.name == uid:
                    report_path = path / "security_report_ai.md"
                    try:
                        with open(report_path, "w", encoding="utf-8") as f:
                            f.write(md_report)
                        logger.info(f"AI report saved to {report_path}")
                        break
                    except Exception as e:
                        logger.error(f"Error saving AI report: {e}")
                        
        return md_report

    def _redact_recursive(self, data: Any) -> Any:
        """Recursively redact sensitive data from any structure"""
        if isinstance(data, dict):
            # Do not redact IDs as they are used for lookups
            return {k: self._redact_recursive(v) if k not in ['id', 'finding_id', 'cve_id'] else v for k, v in data.items()}
        elif isinstance(data, list):
            return [self._redact_recursive(i) for i in data]
        elif isinstance(data, str):
            return self._redact_text(data)
        else:
            return data

    def _redact_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive information from a finding"""
        return self._redact_recursive(finding)

    def _redact_text(self, text: Any) -> str:
        """Mask sensitive patterns in text"""
        if not text or not isinstance(text, str):
            return str(text) if text else ""
            
        # Redact OpenAI Keys
        text = re.sub(r'sk-[a-zA-Z0-9]{20,}', r'sk-****', text)
        text = re.sub(r'sk-proj-[a-zA-Z0-9_-]{20,}', r'sk-proj-****', text)
        
        # Redact common assignment patterns for secrets
        # Matches: KEY="secret", KEY: 'secret', etc.
        patterns = [
            r'(?i)([a-z0-9_-]*(?:password|secret|key|token|auth|token)\s*[:=]\s*["\'])([^"\']+)(["\'])',
            r'(?i)([a-z0-9_-]*(?:password|secret|key|token|auth|token)\s*[:=]\s*)([a-z0-9_-]{8,})'
        ]
        
        for p in patterns:
            text = re.sub(p, r'\1[REDACTED]', text)
            
        return text

    def _get_fix_suggestion(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Load fix suggestion for a finding"""
        # Look for fix suggestions in output directory first, then root
        # sync_results_to_dashboard saves to ../output/ (project root)
        search_paths = [
            Path('..') / 'output',
            Path('output'),
            Path('.')
        ]

        fix_files = [
            'fix_suggestions.json',
            'fix-suggestions.json'
        ]

        for search_dir in search_paths:
            for filename in fix_files:
                fix_path = search_dir / filename
                if fix_path.exists():
                    try:
                        with open(fix_path, 'r') as f:
                            fixes = json.load(f)

                        for fix in fixes:
                            if fix.get('finding_id') == finding_id:
                                return fix
                    except Exception as e:
                        logger.error(f"Error loading fixes {fix_path}: {e}")

        return None

    def _generate_dashboard_from_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate dashboard data from security report"""
        from reporting.dashboard_exporter import DashboardExporter

        exporter = DashboardExporter()

        # Extract data from report
        security_findings = report.get('security_findings', [])
        cve_findings = report.get('cve_findings', [])
        dependencies = []  # Would need to load separately

        return exporter.export_all(security_findings, cve_findings, dependencies)

    def _is_cached(self, key: str) -> bool:
        """Check if data is in cache and not expired"""
        if key not in self._cache:
            return False

        timestamp = self._cache_timestamps.get(key)
        if not timestamp:
            return False

        age = (datetime.now() - timestamp).total_seconds()
        return age < self.cache_ttl

    def _set_cache(self, key: str, value: Any):
        """Set cache value with timestamp"""
        self._cache[key] = value
        self._cache_timestamps[key] = datetime.now()

    def clear_cache(self):
        """Clear all cached data"""
        self._cache.clear()
        self._cache_timestamps.clear()

    def _get_sample_report(self) -> Dict[str, Any]:
        """Get sample report for demo purposes"""
        return {
            'is_sample': True,
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator': 'AI Code Review Platform',
                'version': '1.0'
            },
            'executive_summary': {
                'overall_risk_level': 'LOW',
                'risk_score': 2.52,
                'total_findings': 4,
                'severity_distribution': {
                    'CRITICAL': 1,
                    'HIGH': 2,
                    'MEDIUM': 1
                },
                'cve_count': 1,
                'security_issue_count': 3,
                'total_dependencies': 3,
                'vulnerable_dependencies': 1
            },
            'security_findings': [
                {
                    'id': 'SEC-001',
                    'type': 'secret',
                    'severity': 'HIGH',
                    'title': 'Hardcoded API Key',
                    'file_path': 'src/config.py',
                    'line_number': 25,
                    'owasp_category': 'A02:2021',
                    'owasp_name': 'Cryptographic Failures'
                }
            ],
            'cve_findings': [],
            'dependency_health': {'health_score': 66.67},
            'remediation_plan': []
        }


# Singleton instance
_report_service = None


def get_report_service() -> ReportService:
    """Get or create report service singleton"""
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service
