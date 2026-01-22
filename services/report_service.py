"""
Report Service

Backend service for integrating Phase 4/5 security reports with the web dashboard.
Handles loading, caching, and transforming security data for API endpoints.
"""

import json
import logging
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

    def get_latest_report(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent security report

        Returns:
            Latest security report dict or None if not found
        """
        # Check cache first
        if self._is_cached('latest_report'):
            return self._cache['latest_report']

        # Look for reports in output directory first, then root
        search_paths = [
            Path('output'),
            Path('.')
        ]

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

                        # Cache the report
                        self._set_cache('latest_report', report)
                        logger.info(f"Loaded report from {report_path}")
                        return report
                    except Exception as e:
                        logger.error(f"Error loading report {report_path}: {e}")

        # No report found, return sample data
        logger.warning("No security report found, returning sample data")
        return self._get_sample_report()

    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get dashboard data for visualization

        Returns:
            Dashboard data with charts and metrics
        """
        # Check cache
        if self._is_cached('dashboard_data'):
            return self._cache['dashboard_data']

        # Look for dashboard data in output directory first, then root
        search_paths = [
            Path('output'),
            Path('.')
        ]

        dashboard_files = [
            'dashboard_data.json',
            'dashboard-data.json'
        ]

        for search_dir in search_paths:
            for filename in dashboard_files:
                dashboard_path = search_dir / filename
                if dashboard_path.exists():
                    try:
                        with open(dashboard_path, 'r') as f:
                            data = json.load(f)

                        self._set_cache('dashboard_data', data)
                        logger.info(f"Loaded dashboard data from {dashboard_path}")
                        return data
                    except Exception as e:
                        logger.error(f"Error loading dashboard data {dashboard_path}: {e}")

        # Generate from report if dashboard data doesn't exist
        report = self.get_latest_report()
        if report:
            dashboard_data = self._generate_dashboard_from_report(report)
            self._set_cache('dashboard_data', dashboard_data)
            return dashboard_data

        return {}

    def get_summary(self) -> Dict[str, Any]:
        """
        Get executive summary data

        Returns:
            Summary metrics for dashboard header
        """
        report = self.get_latest_report()
        if not report:
            return {}

        summary = report.get('executive_summary', {})
        metadata = report.get('metadata', {})

        return {
            'risk_level': summary.get('overall_risk_level', 'UNKNOWN'),
            'risk_score': summary.get('risk_score', 0),
            'total_findings': summary.get('total_findings', 0),
            'critical_count': summary.get('severity_distribution', {}).get('CRITICAL', 0),
            'high_count': summary.get('severity_distribution', {}).get('HIGH', 0),
            'cve_count': summary.get('cve_count', 0),
            'dependency_health': report.get('dependency_health', {}).get('health_score', 0),
            'last_scan': metadata.get('generated_at', datetime.now().isoformat())
        }

    def get_findings(
        self,
        severity: Optional[str] = None,
        owasp_category: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get security findings with optional filtering

        Args:
            severity: Filter by severity level
            owasp_category: Filter by OWASP category
            limit: Max findings to return
            offset: Offset for pagination

        Returns:
            Findings list with total count
        """
        report = self.get_latest_report()
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

        # Enrich with feedback status
        feedback_service = get_feedback_service()
        all_feedback = feedback_service.get_all_feedback()
        
        for finding in paginated:
            fid = finding.get('id') or finding.get('cve_id')
            if fid and fid in all_feedback:
                finding['user_feedback'] = all_feedback[fid].get('feedback_type')

        return {
            'findings': paginated,
            'total': total,
            'offset': offset,
            'limit': limit
        }

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific finding

        Args:
            finding_id: Finding identifier

        Returns:
            Finding details or None if not found
        """
        report = self.get_latest_report()
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

    def get_remediation_plan(self) -> List[Dict[str, Any]]:
        """
        Get prioritized remediation plan

        Returns:
            List of remediation items sorted by priority
        """
        report = self.get_latest_report()
        if not report:
            return []

        return report.get('remediation_plan', [])

    def _get_fix_suggestion(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Load fix suggestion for a finding"""
        # Look for fix suggestions in output directory first, then root
        search_paths = [
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
