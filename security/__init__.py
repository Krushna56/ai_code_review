"""
Security Analysis Module

Comprehensive security analysis including:
- Secret detection (hardcoded credentials, API keys)
- Dependency vulnerability scanning (CVE detection)
- OWASP Top 10 mapping
- Security finding aggregation
"""

from .secret_detector import SecretDetector, scan_for_secrets
from .dependency_analyzer import DependencyAnalyzer, Dependency, analyze_dependencies
from .cve_tracker import CVETracker, CVEVulnerability, scan_dependencies_for_cves
from .owasp_mapper import OWASPMapper, OWASPCategory, enrich_with_owasp
from .security_aggregator import SecurityAggregator, SecurityFinding, aggregate_security_findings

__all__ = [
    'SecretDetector',
    'scan_for_secrets',
    'DependencyAnalyzer',
    'Dependency',
    'analyze_dependencies',
    'CVETracker',
    'CVEVulnerability',
    'scan_dependencies_for_cves',
    'OWASPMapper',
    'OWASPCategory',
    'enrich_with_owasp',
    'SecurityAggregator',
    'SecurityFinding',
    'aggregate_security_findings',
]
