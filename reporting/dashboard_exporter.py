"""
Dashboard Exporter

Export security analysis data in dashboard-ready formats for visualization libraries
like Chart.js, D3.js, or custom dashboards.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class DashboardExporter:
    """Export dashboard-ready visualization data"""
    
    def export_all(
        self,
        security_findings: List[Dict[str, Any]],
        cve_results: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export all dashboard data
        
        Args:
            security_findings: Security findings list
            cve_results: CVE vulnerabilities
            dependencies: Dependency list
            
        Returns:
            Complete dashboard data package
        """
        return {
            'severity_distribution': self.export_severity_distribution(security_findings, cve_results),
            'owasp_coverage': self.export_owasp_heatmap(security_findings, cve_results),
            'vulnerability_trends': self.export_vulnerability_timeline(security_findings, cve_results),
            'file_risk_scores': self.export_file_risk_scores(security_findings),
            'dependency_stats': self.export_dependency_stats(dependencies, cve_results),
            'top_issues': self.export_top_issues(security_findings, cve_results),
            'remediation_progress': self.export_remediation_progress(security_findings, cve_results)
        }
    
    def export_severity_distribution(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export severity distribution for pie/donut charts
        
        Returns Chart.js compatible format
        """
        severity_counts = defaultdict(int)
        
        # Count findings
        for item in findings + cves:
            severity = item.get('severity', 'UNKNOWN')
            severity_counts[severity] += 1
        
        # Prepare chart data
        labels = []
        data = []
        colors = []
        
        severity_config = {
            'CRITICAL': {'color': '#dc2626', 'order': 0},
            'HIGH': {'color': '#ea580c', 'order': 1},
            'MEDIUM': {'color': '#eab308', 'order': 2},
            'LOW': {'color': '#84cc16', 'order': 3},
            'UNKNOWN': {'color': '#6b7280', 'order': 4}
        }
        
        # Sort by severity order
        for severity in sorted(severity_counts.keys(), key=lambda x: severity_config.get(x, {}).get('order', 99)):
            count = severity_counts[severity]
            if count > 0:
                labels.append(severity)
                data.append(count)
                colors.append(severity_config.get(severity, {}).get('color', '#6b7280'))
        
        return {
            'type': 'pie',
            'labels': labels,
            'datasets': [{
                'data': data,
                'backgroundColor': colors,
                'borderWidth': 2,
                'borderColor': '#ffffff'
            }],
            'total': sum(data)
        }
    
    def export_owasp_heatmap(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export OWASP Top 10 coverage for bar chart or heatmap
        """
        owasp_counts = defaultdict(int)
        owasp_names = {}
        
        # Count by OWASP category
        for item in findings + cves:
            owasp_cat = item.get('owasp_category')
            if owasp_cat:
                owasp_counts[owasp_cat] += 1
                owasp_names[owasp_cat] = item.get('owasp_name', owasp_cat)
        
        # Prepare data
        categories = []
        labels = []
        data = []
        
        # Sort by category ID
        for cat_id in sorted(owasp_counts.keys()):
            categories.append(cat_id)
            labels.append(owasp_names.get(cat_id, cat_id))
            data.append(owasp_counts[cat_id])
        
        return {
            'type': 'bar',
            'labels': labels,
            'datasets': [{
                'label': 'Findings per OWASP Category',
                'data': data,
                'backgroundColor': '#3b82f6',
                'borderColor': '#1d4ed8',
                'borderWidth': 1
            }],
            'category_ids': categories
        }
    
    def export_vulnerability_timeline(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export vulnerability timeline data for line charts
        
        Note: For actual timeline, findings would need timestamps.
        This provides a simulated timeline based on severity.
        """
        # Group by severity for trend visualization
        from datetime import datetime, timedelta
        
        # Simulate timeline data (in real scenario, use actual timestamps)
        base_date = datetime.now() - timedelta(days=30)
        dates = [(base_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(0, 31, 5)]
        
        severity_trends = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        # Get current counts
        severity_counts = defaultdict(int)
        for item in findings + cves:
            severity = item.get('severity', 'UNKNOWN')
            if severity in severity_trends:
                severity_counts[severity] += 1
        
        # Simulate trend (in practice, query historical data)
        for i, date in enumerate(dates):
            for severity in severity_trends.keys():
                # Simulate gradual accumulation
                ratio = (i + 1) / len(dates)
                count = int(severity_counts.get(severity, 0) * ratio)
                severity_trends[severity].append(count)
        
        datasets = []
        colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#eab308',
            'LOW': '#84cc16'
        }
        
        for severity, values in severity_trends.items():
            if any(v > 0 for v in values):
                datasets.append({
                    'label': severity,
                    'data': values,
                    'borderColor': colors[severity],
                    'backgroundColor': colors[severity] + '40',  # 40 = 25% opacity
                    'tension': 0.3,
                    'fill': True
                })
        
        return {
            'type': 'line',
            'labels': dates,
            'datasets': datasets
        }
    
    def export_file_risk_scores(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export file-level risk scores for horizontal bar chart
        """
        file_scores = defaultdict(lambda: {'count': 0, 'risk_score': 0})
        
        # Aggregate by file
        for finding in findings:
            file_path = finding.get('file_path', 'unknown')
            file_scores[file_path]['count'] += 1
            file_scores[file_path]['risk_score'] += finding.get('risk_score', 0)
        
        # Calculate average risk scores
        for file_path, data in file_scores.items():
            if data['count'] > 0:
                data['avg_risk'] = data['risk_score'] / data['count']
        
        # Get top 10 files by average risk
        top_files = sorted(
            file_scores.items(),
            key=lambda x: x[1]['avg_risk'],
            reverse=True
        )[:10]
        
        labels = [file_path.split('/')[-1] for file_path, _ in top_files]  # Just filename
        risk_scores = [data['avg_risk'] for _, data in top_files]
        finding_counts = [data['count'] for _, data in top_files]
        
        return {
            'type': 'horizontalBar',
            'labels': labels,
            'datasets': [
                {
                    'label': 'Average Risk Score',
                    'data': risk_scores,
                    'backgroundColor': '#ef4444',
                    'borderColor': '#dc2626',
                    'borderWidth': 1
                },
                {
                    'label': 'Finding Count',
                    'data': finding_counts,
                    'backgroundColor': '#3b82f6',
                    'borderColor': '#1d4ed8',
                    'borderWidth': 1
                }
            ],
            'full_paths': [file_path for file_path, _ in top_files]
        }
    
    def export_dependency_stats(
        self,
        dependencies: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export dependency statistics for various visualizations
        """
        # Count by ecosystem
        ecosystem_counts = defaultdict(int)
        vulnerable_ecosystems = defaultdict(int)
        
        vulnerable_packages = set(cve.get('package_name') for cve in cves)
        
        for dep in dependencies:
            ecosystem = dep.get('ecosystem', 'unknown')
            ecosystem_counts[ecosystem] += 1
            
            if dep.get('package_name') in vulnerable_packages:
                vulnerable_ecosystems[ecosystem] += 1
        
        # Ecosystem breakdown
        ecosystems = list(ecosystem_counts.keys())
        total_counts = [ecosystem_counts[e] for e in ecosystems]
        vulnerable_counts = [vulnerable_ecosystems[e] for e in ecosystems]
        
        return {
            'total_dependencies': len(dependencies),
            'vulnerable_dependencies': len(vulnerable_packages),
            'ecosystem_breakdown': {
                'type': 'bar',
                'labels': ecosystems,
                'datasets': [
                    {
                        'label': 'Total Dependencies',
                        'data': total_counts,
                        'backgroundColor': '#3b82f6'
                    },
                    {
                        'label': 'Vulnerable',
                        'data': vulnerable_counts,
                        'backgroundColor': '#ef4444'
                    }
                ]
            },
            'health_percentage': round(
                ((len(dependencies) - len(vulnerable_packages)) / len(dependencies) * 100) if len(dependencies) > 0 else 100,
                2
            )
        }
    
    def export_top_issues(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Export top issues for dashboard cards/lists
        """
        all_issues = []
        
        # Format findings
        for finding in findings:
            all_issues.append({
                'id': finding.get('id'),
                'type': finding.get('type'),
                'severity': finding.get('severity'),
                'risk_score': finding.get('risk_score', 0),
                'title': finding.get('title'),
                'file': finding.get('file_path', '').split('/')[-1],
                'line': finding.get('line_number', 0),
                'owasp': finding.get('owasp_category')
            })
        
        # Format CVEs
        for cve in cves:
            all_issues.append({
                'id': cve.get('cve_id'),
                'type': 'cve',
                'severity': cve.get('severity'),
                'risk_score': 90 if cve.get('severity') == 'CRITICAL' else 70,
                'title': f"{cve.get('package_name')} - {cve.get('cve_id')}",
                'file': 'dependency',
                'line': 0,
                'owasp': cve.get('owasp_category')
            })
        
        # Sort by risk score
        all_issues.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return all_issues[:limit]
    
    def export_remediation_progress(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Export remediation progress for progress bars/gauges
        """
        total_issues = len(findings) + len(cves)
        
        # Count by difficulty (estimate)
        by_difficulty = defaultdict(int)
        
        for finding in findings:
            # Estimate difficulty based on type
            finding_type = finding.get('type', '')
            if finding_type == 'secret':
                difficulty = 'EASY'
            elif finding_type == 'cve':
                difficulty = 'EASY'
            elif finding_type == 'pattern':
                difficulty = 'MEDIUM'
            else:
                difficulty = 'MEDIUM'
            
            by_difficulty[difficulty] += 1
        
        # CVEs are usually easy (just upgrade)
        by_difficulty['EASY'] += len(cves)
        
        return {
            'total_issues': total_issues,
            'by_difficulty': dict(by_difficulty),
            'estimated_easy_percentage': round(
                (by_difficulty['EASY'] / total_issues * 100) if total_issues > 0 else 0,
                2
            ),
            'gauges': {
                'overall_completion': 0,  # Would be updated as fixes are applied
                'critical_completion': 0,
                'dependencies_completion': 0
            }
        }


def export_dashboard_data(
    security_findings: List[Dict[str, Any]],
    cve_results: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Convenience function to export all dashboard data
    
    Args:
        security_findings: Security findings
        cve_results: CVE vulnerabilities
        dependencies: Dependencies list
        
    Returns:
        Complete dashboard data package
    """
    exporter = DashboardExporter()
    return exporter.export_all(security_findings, cve_results, dependencies)
