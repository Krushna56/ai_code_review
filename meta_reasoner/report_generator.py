"""
Report Generator

Generates structured reports in multiple formats
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates structured reports"""

    def __init__(self):
        self.report_data = {}

    def generate_json_report(
        self,
        issues: List[Dict[str, Any]],
        summary: Dict[str, Any],
        metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate structured JSON report

        Args:
            issues: List of ranked issues
            summary: Analysis summary
            metadata: Additional metadata

        Returns:
            Complete report dictionary
        """
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0',
                'tool': 'AI Code Review Platform'
            },
            'summary': summary,
            'issues': issues,
            'statistics': self._calculate_statistics(issues)
        }

        if metadata:
            report['metadata'].update(metadata)

        return report

    def generate_markdown_report(
        self,
        issues: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> str:
        """Generate Markdown report"""
        md = []

        # Header
        md.append("# Code Review Report")
        md.append(
            f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Summary
        md.append("## Summary\n")
        md.append(f"- **Files Analyzed:** {summary.get('files_analyzed', 0)}")
        md.append(f"- **Total Issues:** {len(issues)}")
        md.append(
            f"- **Critical Issues:** {sum(1 for i in issues if i.get('severity') in ['critical', 'high'])}")
        md.append(
            f"- **Security Issues:** {summary.get('security_issues', 0)}\n")

        # Top Issues
        md.append("## Top Issues\n")
        top_issues = issues[:10]

        for i, issue in enumerate(top_issues, 1):
            severity = issue.get('severity', 'info').upper()
            file = issue.get('file', 'unknown')
            line = issue.get('line', 0)
            message = issue.get('message', 'No description')
            source = issue.get('source', 'unknown')

            md.append(f"### {i}. [{severity}] {file}:{line}")
            md.append(f"**Source:** {source}")
            md.append(f"**Message:** {message}\n")

            if 'also_found_by' in issue:
                md.append(
                    f"*Also detected by: {', '.join(issue['also_found_by'])}*\n")

        # Statistics
        md.append("## Statistics\n")
        stats = self._calculate_statistics(issues)

        md.append("### By Severity")
        for severity, count in stats['by_severity'].items():
            md.append(f"- **{severity.capitalize()}:** {count}")

        md.append("\n### By Source")
        for source, count in stats['by_source'].items():
            md.append(f"- **{source}:** {count}")

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
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            if format == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
            elif format == 'markdown':
                # Assume report is already markdown string
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)

            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")

    def _calculate_statistics(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from issues"""
        from collections import defaultdict

        by_severity = defaultdict(int)
        by_source = defaultdict(int)
        by_file = defaultdict(int)

        for issue in issues:
            by_severity[issue.get('severity', 'info')] += 1
            by_source[issue.get('source', 'unknown')] += 1
            by_file[issue.get('file', 'unknown')] += 1

        return {
            'total_issues': len(issues),
            'by_severity': dict(by_severity),
            'by_source': dict(by_source),
            'files_with_issues': len(by_file),
            'top_files': sorted(
                by_file.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }


def generate_comprehensive_report(
    linter_results: Dict[str, Any],
    llm_insights: Dict[str, Any] = None,
    summary: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Convenience function to generate complete report

    Args:
        linter_results: Results from multi-linter
        llm_insights: Results from LLM agents
        summary: Analysis summary

    Returns:
        Complete report dictionary
    """
    from .issue_aggregator import IssueAggregator
    from .severity_ranker import SeverityRanker

    # Aggregate issues
    aggregator = IssueAggregator()
    aggregator.add_static_analysis_results(linter_results)

    if llm_insights:
        aggregator.add_llm_results(llm_insights)

    issues = aggregator.get_aggregated_issues()

    # Rank issues
    ranker = SeverityRanker()
    ranked_issues = ranker.rank_issues(issues)

    # Generate report
    generator = ReportGenerator()
    report = generator.generate_json_report(
        issues=ranked_issues,
        summary=summary or {},
        metadata={'aggregation_stats': aggregator.get_statistics()}
    )

    return report
