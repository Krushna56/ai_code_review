"""
Issue Aggregator

Consolidates findings from multiple sources:
- Static analysis (Bandit, Semgrep, Pylint, Ruff)
- ML models
- Deep learning models
- LLM agents
"""

import logging
from typing import Dict, List, Any, Set
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


class Issue:
    """Represents a single code issue"""

    def __init__(self, source: str, data: Dict[str, Any]):
        self.source = source  # bandit, semgrep, llm_security, etc.
        self.file = data.get('file', '')
        self.line = data.get('line', 0)
        self.severity = data.get('severity', 'info')
        self.message = data.get('message') or data.get('issue_text', '')
        self.code = data.get('code', '')
        self.rule_id = data.get('rule_id') or data.get('test_id', '')
        self.confidence = data.get('confidence', 'medium')
        self.raw_data = data

        # Generate unique ID for deduplication
        self.id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate unique ID based on file, line, and message"""
        content = f"{self.file}:{self.line}:{self.message[:100]}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'source': self.source,
            'file': self.file,
            'line': self.line,
            'severity': self.severity,
            'message': self.message,
            'code': self.code,
            'rule_id': self.rule_id,
            'confidence': self.confidence
        }


class IssueAggregator:
    """Aggregates and deduplicates issues from multiple sources"""

    def __init__(self):
        self.issues: List[Issue] = []
        self.issue_map: Dict[str, Issue] = {}
        self.duplicates: Dict[str, List[str]] = defaultdict(list)

    def add_static_analysis_results(self, results: Dict[str, Any]):
        """Add results from multi-linter"""
        issues_list = results.get('issues', [])

        for issue_data in issues_list:
            source = issue_data.get('tool', 'static')
            issue = Issue(source, issue_data)
            self._add_issue(issue)

    def add_llm_results(self, llm_insights: Dict[str, Any]):
        """Add results from LLM agents"""
        for agent_name, result in llm_insights.items():
            if 'analysis' in result:
                # Parse LLM analysis into structured issues
                # For now, create a single issue per agent
                issue_data = {
                    'file': 'multiple',
                    'line': 0,
                    'severity': 'info',
                    'message': result['analysis'][:200] + '...',
                    'confidence': 'high'
                }
                issue = Issue(f'llm_{agent_name}', issue_data)
                self._add_issue(issue)

    def add_ml_results(self, ml_predictions: Dict[str, Any]):
        """Add results from ML models"""
        # Placeholder for ML model results
        pass

    def _add_issue(self, issue: Issue):
        """Add issue with deduplication"""
        if issue.id in self.issue_map:
            # Duplicate found
            existing = self.issue_map[issue.id]
            self.duplicates[issue.id].append(issue.source)

            # Merge information (keep higher severity)
            if self._severity_value(issue.severity) > self._severity_value(existing.severity):
                existing.severity = issue.severity
        else:
            # New issue
            self.issue_map[issue.id] = issue
            self.issues.append(issue)

    def _severity_value(self, severity: str) -> int:
        """Convert severity to numeric value for comparison"""
        severity_map = {
            'critical': 5,
            'high': 4,
            'error': 4,
            'medium': 3,
            'warning': 3,
            'low': 2,
            'info': 1
        }
        return severity_map.get(severity.lower(), 0)

    def get_aggregated_issues(self) -> List[Dict[str, Any]]:
        """Get all issues with deduplication info"""
        result = []
        for issue in self.issues:
            issue_dict = issue.to_dict()
            if issue.id in self.duplicates:
                issue_dict['also_found_by'] = self.duplicates[issue.id]
            result.append(issue_dict)
        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregation statistics"""
        by_severity = defaultdict(int)
        by_source = defaultdict(int)

        for issue in self.issues:
            by_severity[issue.severity] += 1
            by_source[issue.source] += 1

        return {
            'total_issues': len(self.issues),
            'unique_issues': len(self.issue_map),
            'duplicates_found': sum(len(v) for v in self.duplicates.values()),
            'by_severity': dict(by_severity),
            'by_source': dict(by_source)
        }
