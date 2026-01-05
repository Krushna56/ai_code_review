"""
Severity Ranker

Ranks issues by severity, confidence, and impact
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RankingScore:
    """Score for an issue"""
    severity_score: float
    confidence_score: float
    impact_score: float
    total_score: float
    rank: int


class SeverityRanker:
    """Ranks issues by multiple criteria"""
    
    def __init__(self):
        self.severity_weights = {
            'critical': 10.0,
            'high': 8.0,
            'error': 8.0,
            'medium': 5.0,
            'warning': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        
        self.confidence_weights = {
            'high': 1.0,
            'medium': 0.7,
            'low': 0.4
        }
    
    def rank_issues(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank issues by severity, confidence, and impact
        
        Args:
            issues: List of issue dictionaries
            
        Returns:
            Sorted list of issues with ranking scores
        """
        scored_issues = []
        
        for issue in issues:
            score = self._calculate_score(issue)
            issue['ranking_score'] = score.total_score
            issue['rank'] = 0  # Will be set after sorting
            scored_issues.append(issue)
        
        # Sort by total score (descending)
        scored_issues.sort(key=lambda x: x['ranking_score'], reverse=True)
        
        # Assign ranks
        for i, issue in enumerate(scored_issues, 1):
            issue['rank'] = i
        
        return scored_issues
    
    def _calculate_score(self, issue: Dict[str, Any]) -> RankingScore:
        """Calculate ranking score for an issue"""
        # Severity score
        severity = issue.get('severity', 'info').lower()
        severity_score = self.severity_weights.get(severity, 1.0)
        
        # Confidence score
        confidence = issue.get('confidence', 'medium').lower()
        confidence_score = self.confidence_weights.get(confidence, 0.7)
        
        # Impact score (based on multiple factors)
        impact_score = self._calculate_impact(issue)
        
        # Total score (weighted combination)
        total_score = (
            severity_score * 0.5 +
            confidence_score * severity_score * 0.3 +
            impact_score * 0.2
        )
        
        return RankingScore(
            severity_score=severity_score,
            confidence_score=confidence_score,
            impact_score=impact_score,
            total_score=total_score,
            rank=0
        )
    
    def _calculate_impact(self, issue: Dict[str, Any]) -> float:
        """Calculate impact score based on various factors"""
        impact = 5.0  # Base impact
        
        # Higher impact if found by multiple sources
        if 'also_found_by' in issue:
            impact += len(issue['also_found_by']) * 1.5
        
        # Higher impact for security issues
        message = issue.get('message', '').lower()
        if any(keyword in message for keyword in ['sql', 'injection', 'xss', 'csrf', 'auth']):
            impact += 2.0
        
        # Higher impact for certain file types
        file = issue.get('file', '')
        if any(pattern in file for pattern in ['auth', 'security', 'admin', 'config']):
            impact += 1.5
        
        return min(impact, 10.0)  # Cap at 10
    
    def get_top_issues(self, issues: List[Dict[str, Any]], n: int = 10) -> List[Dict[str, Any]]:
        """Get top N issues by ranking"""
        ranked = self.rank_issues(issues)
        return ranked[:n]
    
    def get_critical_issues(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get only critical/high severity issues"""
        ranked = self.rank_issues(issues)
        return [
            issue for issue in ranked
            if issue.get('severity', '').lower() in ['critical', 'high', 'error']
        ]
