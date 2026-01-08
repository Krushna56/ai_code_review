"""
Security Report Generator

Generates comprehensive security reports integrating CVE findings, OWASP mapping,
and security analysis results from Phase 4.
"""

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class SecurityReportGenerator:
    """Generate comprehensive security reports"""
    
    RISK_LEVELS = {
        'CRITICAL': {'min_score': 80, 'color': '🔴', 'label': 'CRITICAL'},
        'HIGH': {'min_score': 60, 'color': '🟠', 'label': 'HIGH'},
        'MEDIUM': {'min_score': 40, 'color': '🟡', 'label': 'MEDIUM'},
        'LOW': {'min_score': 0, 'color': '⚪', 'label': 'LOW'}
    }
    
    def __init__(self):
        """Initialize security report generator"""
        self.report_data = {}
    
    def generate_comprehensive_report(
        self,
        security_findings: List[Dict[str, Any]],
        cve_results: Dict[str, List[Dict[str, Any]]],
        dependencies: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Args:
            security_findings: Findings from security aggregator
            cve_results: CVE vulnerability results
            dependencies: Dependency information
            metadata: Additional metadata
            
        Returns:
            Complete security report
        """
        # Flatten CVE results
        all_cves = []
        for pkg_id, cves in cve_results.items():
            all_cves.extend(cves)
        
        # Generate report sections
        report = {
            'metadata': self._generate_metadata(metadata),
            'executive_summary': self._generate_executive_summary(
                security_findings, all_cves, dependencies
            ),
            'owasp_breakdown': self._generate_owasp_breakdown(security_findings, all_cves),
            'cve_findings': self._generate_cve_section(all_cves),
            'security_findings': self._format_security_findings(security_findings),
            'dependency_health': self._generate_dependency_health(dependencies, cve_results),
            'remediation_plan': self._generate_remediation_plan(security_findings, all_cves)
        }
        
        return report
    
    def _generate_metadata(self, custom_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate report metadata"""
        metadata = {
            'generated_at': datetime.now().isoformat(),
            'generator': 'AI Code Review Platform - Phase 5',
            'version': '1.0',
            'report_type': 'security_analysis'
        }
        
        if custom_metadata:
            metadata.update(custom_metadata)
        
        return metadata
    
    def _generate_executive_summary(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate executive summary section"""
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.get('severity', 'UNKNOWN')] += 1
        
        for cve in cves:
            severity_counts[cve.get('severity', 'UNKNOWN')] += 1
        
        # Calculate overall risk level
        risk_score = self._calculate_overall_risk(severity_counts)
        risk_level = self._get_risk_level(risk_score)
        
        # Get affected files/components
        affected_files = set()
        for finding in findings:
            if finding.get('file_path'):
                affected_files.add(finding['file_path'])
        
        # Top critical issues
        all_issues = findings + cves
        critical_issues = sorted(
            [i for i in all_issues if i.get('severity') in ['CRITICAL', 'HIGH']],
            key=lambda x: {'CRITICAL': 0, 'HIGH': 1}.get(x.get('severity'), 2)
        )[:5]
        
        return {
            'overall_risk_level': risk_level,
            'risk_score': risk_score,
            'total_findings': len(findings) + len(cves),
            'severity_distribution': dict(severity_counts),
            'cve_count': len(cves),
            'security_issue_count': len(findings),
            'total_dependencies': len(dependencies),
            'vulnerable_dependencies': len([d for d in dependencies if any(
                cve.get('package_name') == d.get('package_name') for cve in cves
            )]),
            'affected_components': len(affected_files),
            'top_critical_issues': [
                {
                    'id': issue.get('cve_id') or issue.get('id'),
                    'severity': issue.get('severity'),
                    'title': issue.get('title') or issue.get('summary', '')[:100]
                }
                for issue in critical_issues
            ]
        }
    
    def _calculate_overall_risk(self, severity_counts: Dict[str, int]) -> float:
        """Calculate overall risk score (0-100)"""
        weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'UNKNOWN': 1
        }
        
        total_score = sum(
            severity_counts.get(severity, 0) * weight
            for severity, weight in weights.items()
        )
        
        # Normalize to 0-100 scale
        max_theoretical = 100 * 25  # 100 critical issues
        normalized = min((total_score / max_theoretical) * 100, 100)
        
        return round(normalized, 2)
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        for level, config in self.RISK_LEVELS.items():
            if risk_score >= config['min_score']:
                return level
        return 'LOW'
    
    def _generate_owasp_breakdown(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate OWASP Top 10 breakdown"""
        owasp_stats = defaultdict(lambda: {
            'count': 0,
            'severity_distribution': defaultdict(int),
            'findings': []
        })
        
        # Process all findings
        all_items = findings + cves
        
        for item in all_items:
            owasp_cat = item.get('owasp_category')
            if owasp_cat:
                owasp_stats[owasp_cat]['count'] += 1
                severity = item.get('severity', 'UNKNOWN')
                owasp_stats[owasp_cat]['severity_distribution'][severity] += 1
                owasp_stats[owasp_cat]['findings'].append({
                    'id': item.get('cve_id') or item.get('id'),
                    'severity': severity,
                    'title': item.get('title') or item.get('summary', '')[:80]
                })
        
        # Convert to regular dict and add OWASP names
        result = {}
        for cat_id, stats in owasp_stats.items():
            result[cat_id] = {
                'category_name': item.get('owasp_name', cat_id),
                'total_findings': stats['count'],
                'severity_distribution': dict(stats['severity_distribution']),
                'max_severity': self._get_max_severity(stats['severity_distribution']),
                'sample_findings': stats['findings'][:3]  # Top 3 for preview
            }
        
        return result
    
    def _get_max_severity(self, severity_dist: Dict[str, int]) -> str:
        """Get the highest severity level present"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        for severity in severity_order:
            if severity_dist.get(severity, 0) > 0:
                return severity
        return 'UNKNOWN'
    
    def _generate_cve_section(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format CVE findings section"""
        formatted_cves = []
        
        for cve in sorted(cves, key=lambda x: {
            'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3
        }.get(x.get('severity'), 4)):
            formatted_cves.append({
                'cve_id': cve.get('cve_id'),
                'severity': cve.get('severity'),
                'package': f"{cve.get('package_name')}:{cve.get('package_version')}",
                'ecosystem': cve.get('ecosystem'),
                'owasp_category': cve.get('owasp_category'),
                'owasp_name': cve.get('owasp_name'),
                'cvss_score': cve.get('cvss_score'),
                'summary': cve.get('summary'),
                'published': cve.get('published'),
                'fixed_versions': cve.get('fixed_versions', []),
                'references': cve.get('references', [])[:3],  # Top 3 references
                'cwe_ids': cve.get('cwe_ids', [])
            })
        
        return formatted_cves
    
    def _format_security_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format security findings from aggregator"""
        formatted = []
        
        for finding in sorted(findings, key=lambda x: x.get('risk_score', 0), reverse=True):
            formatted.append({
                'id': finding.get('id'),
                'type': finding.get('type'),
                'severity': finding.get('severity'),
                'risk_score': finding.get('risk_score'),
                'title': finding.get('title'),
                'description': finding.get('description'),
                'file_path': finding.get('file_path'),
                'line_number': finding.get('line_number'),
                'owasp_category': finding.get('owasp_category'),
                'owasp_name': finding.get('owasp_name'),
                'cwe_ids': finding.get('cwe_ids', []),
                'remediation': finding.get('remediation'),
                'confidence': finding.get('confidence')
            })
        
        return formatted
    
    def _generate_dependency_health(
        self,
        dependencies: List[Dict[str, Any]],
        cve_results: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Generate dependency health section"""
        # Group by ecosystem
        by_ecosystem = defaultdict(int)
        vulnerable_by_ecosystem = defaultdict(int)
        
        vulnerable_packages = set()
        for pkg_id in cve_results.keys():
            vulnerable_packages.add(pkg_id.split(':')[0])  # Extract package name
        
        for dep in dependencies:
            ecosystem = dep.get('ecosystem', 'unknown')
            by_ecosystem[ecosystem] += 1
            
            pkg_name = dep.get('package_name')
            if pkg_name in vulnerable_packages:
                vulnerable_by_ecosystem[ecosystem] += 1
        
        return {
            'total_dependencies': len(dependencies),
            'vulnerable_dependencies': len(vulnerable_packages),
            'by_ecosystem': dict(by_ecosystem),
            'vulnerable_by_ecosystem': dict(vulnerable_by_ecosystem),
            'health_score': self._calculate_dependency_health_score(
                len(dependencies), len(vulnerable_packages)
            )
        }
    
    def _calculate_dependency_health_score(self, total: int, vulnerable: int) -> float:
        """Calculate dependency health score (0-100)"""
        if total == 0:
            return 100.0
        
        health = ((total - vulnerable) / total) * 100
        return round(health, 2)
    
    def _generate_remediation_plan(
        self,
        findings: List[Dict[str, Any]],
        cves: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized remediation plan"""
        all_items = []
        
        # Add security findings
        for finding in findings:
            all_items.append({
                'priority': self._calculate_priority(finding.get('severity'), finding.get('risk_score', 0)),
                'type': 'security_finding',
                'id': finding.get('id'),
                'severity': finding.get('severity'),
                'title': finding.get('title'),
                'action': finding.get('remediation'),
                'estimated_effort': self._estimate_effort(finding),
                'impact': 'HIGH' if finding.get('severity') in ['CRITICAL', 'HIGH'] else 'MEDIUM'
            })
        
        # Add CVE remediations
        for cve in cves:
            all_items.append({
                'priority': self._calculate_priority(cve.get('severity'), 90),
                'type': 'cve_remediation',
                'id': cve.get('cve_id'),
                'severity': cve.get('severity'),
                'title': f"Upgrade {cve.get('package_name')}",
                'action': self._format_cve_action(cve),
                'estimated_effort': 'LOW',
                'impact': 'CRITICAL' if cve.get('severity') == 'CRITICAL' else 'HIGH'
            })
        
        # Sort by priority
        all_items.sort(key=lambda x: x['priority'])
        
        return all_items[:20]  # Top 20 priorities
    
    def _calculate_priority(self, severity: str, risk_score: float) -> int:
        """Calculate priority score (lower is higher priority)"""
        severity_weight = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'LOW': 4,
            'UNKNOWN': 5
        }
        
        base = severity_weight.get(severity, 5) * 100
        return base - int(risk_score)  # Higher risk score = higher priority
    
    def _estimate_effort(self, finding: Dict[str, Any]) -> str:
        """Estimate remediation effort"""
        finding_type = finding.get('type', '')
        
        if finding_type == 'secret':
            return 'LOW'  # Usually just move to env var
        elif finding_type == 'pattern':
            return 'MEDIUM'  # May require code refactoring
        elif finding_type == 'cve':
            return 'LOW'  # Usually just upgrade
        else:
            return 'MEDIUM'
    
    def _format_cve_action(self, cve: Dict[str, Any]) -> str:
        """Format CVE remediation action"""
        fixed_versions = cve.get('fixed_versions', [])
        if fixed_versions:
            return f"Upgrade to version {fixed_versions[0]} or later"
        return "Review vendor advisory for patch information"
    
    def generate_markdown_report(
        self,
        report: Dict[str, Any]
    ) -> str:
        """
        Generate markdown-formatted security report
        
        Args:
            report: Complete security report from generate_comprehensive_report
            
        Returns:
            Markdown-formatted report string
        """
        md = []
        
        # Header
        md.append("# 🔒 Security Analysis Report")
        md.append(f"\n**Generated:** {datetime.fromisoformat(report['metadata']['generated_at']).strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Platform:** {report['metadata']['generator']}\n")
        md.append("---\n")
        
        # Executive Summary
        summary = report['executive_summary']
        risk_level = summary['overall_risk_level']
        risk_emoji = self.RISK_LEVELS[risk_level]['color']
        
        md.append("## 📊 Executive Summary\n")
        md.append(f"### Overall Risk: {risk_emoji} **{risk_level}** (Score: {summary['risk_score']}/100)\n")
        md.append(f"- **Total Findings:** {summary['total_findings']}")
        md.append(f"- **CVE Vulnerabilities:** {summary['cve_count']}")
        md.append(f"- **Security Issues:** {summary['security_issue_count']}")
        md.append(f"- **Dependencies Scanned:** {summary['total_dependencies']}")
        md.append(f"- **Vulnerable Dependencies:** {summary['vulnerable_dependencies']}")
        md.append(f"- **Affected Components:** {summary['affected_components']}\n")
        
        # Severity Distribution
        md.append("### Severity Distribution\n")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = summary['severity_distribution'].get(severity, 0)
            if count > 0:
                emoji = self.RISK_LEVELS.get(severity, {}).get('color', '⚪')
                md.append(f"- {emoji} **{severity}:** {count}")
        md.append("\n")
        
        # Top Critical Issues
        if summary['top_critical_issues']:
            md.append("### 🚨 Top Critical Issues\n")
            for i, issue in enumerate(summary['top_critical_issues'], 1):
                emoji = self.RISK_LEVELS.get(issue['severity'], {}).get('color', '⚪')
                md.append(f"{i}. {emoji} `{issue['id']}` - {issue['title']}")
            md.append("\n")
        
        md.append("---\n")
        
        # OWASP Breakdown
        if report['owasp_breakdown']:
            md.append("## 🛡️ OWASP Top 10 2021 Analysis\n")
            for cat_id, data in sorted(report['owasp_breakdown'].items()):
                severity_emoji = self.RISK_LEVELS.get(data['max_severity'], {}).get('color', '⚪')
                md.append(f"### {cat_id} - {data['category_name']} {severity_emoji}\n")
                md.append(f"- **Total Findings:** {data['total_findings']}")
                md.append(f"- **Max Severity:** {data['max_severity']}\n")
            md.append("---\n")
        
        # CVE Findings
        if report['cve_findings']:
            md.append("## 🔍 CVE Vulnerabilities\n")
            for cve in report['cve_findings'][:10]:  # Top 10
                emoji = self.RISK_LEVELS.get(cve['severity'], {}).get('color', '⚪')
                md.append(f"### {emoji} {cve['cve_id']} - {cve['severity']}\n")
                md.append(f"- **Package:** `{cve['package']}`")
                md.append(f"- **OWASP:** {cve['owasp_name'] or 'Not Mapped'}")
                if cve['cvss_score']:
                    md.append(f"- **CVSS Score:** {cve['cvss_score']}")
                md.append(f"- **Summary:** {cve['summary'][:200]}")
                if cve['fixed_versions']:
                    md.append(f"- **Fix:** Upgrade to `{cve['fixed_versions'][0]}`")
                md.append("")
            md.append("---\n")
        
        # Remediation Plan
        if report['remediation_plan']:
            md.append("## 🔧 Remediation Plan\n")
            md.append("### High Priority Actions\n")
            for i, item in enumerate(report['remediation_plan'][:10], 1):
                emoji = self.RISK_LEVELS.get(item['severity'], {}).get('color', '⚪')
                md.append(f"{i}. {emoji} **{item['title']}**")
                md.append(f"   - Severity: {item['severity']}")
                md.append(f"   - Effort: {item['estimated_effort']}")
                md.append(f"   - Action: {item['action']}\n")
        
        return '\n'.join(md)
    
    def save_report(
        self,
        report: Dict[str, Any],
        output_path: str,
        format: str = 'json'
    ):
        """
        Save report to file
        
        Args:
            report: Report data
            output_path: Output file path
            format: 'json' or 'markdown'
        """
        from pathlib import Path
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            if format == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
            elif format == 'markdown':
                md_report = self.generate_markdown_report(report)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(md_report)
            
            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise


def generate_security_report(
    security_findings: List[Dict[str, Any]],
    cve_results: Dict[str, List[Dict[str, Any]]],
    dependencies: List[Dict[str, Any]],
    output_path: str = None,
    format: str = 'json'
) -> Dict[str, Any]:
    """
    Convenience function to generate security report
    
    Args:
        security_findings: Security findings from aggregator
        cve_results: CVE vulnerability results
        dependencies: Dependency list
        output_path: Optional output file path
        format: Output format ('json' or 'markdown')
        
    Returns:
        Complete security report
    """
    generator = SecurityReportGenerator()
    report = generator.generate_comprehensive_report(
        security_findings, cve_results, dependencies
    )
    
    if output_path:
        generator.save_report(report, output_path, format)
    
    return report
