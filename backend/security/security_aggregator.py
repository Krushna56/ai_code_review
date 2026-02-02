"""
Security Aggregator

Combine and prioritize security findings from multiple sources:
- Secret detection
- Pattern matching
- CVE tracking
- Static analysis
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Unified security finding"""
    id: str
    type: str  # secret, pattern, cve, static_analysis
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    file_path: str
    line_number: int = 0
    owasp_category: Optional[str] = None
    owasp_name: Optional[str] = None
    cwe_ids: List[str] = None
    remediation: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    risk_score: float = 0.0

    def __post_init__(self):
        """Initialize mutable defaults"""
        if self.cwe_ids is None:
            self.cwe_ids = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class SecurityAggregator:
    """Aggregate and prioritize security findings"""

    SEVERITY_WEIGHTS = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 2,
        'UNKNOWN': 1
    }

    def __init__(self):
        """Initialize security aggregator"""
        self.findings: List[SecurityFinding] = []

    def add_secrets(self, secrets: List[Dict[str, Any]]):
        """
        Add secret detection findings

        Args:
            secrets: List of detected secrets
        """
        for secret in secrets:
            finding = SecurityFinding(
                id=f"SEC-{len(self.findings) + 1:04d}",
                type="secret",
                severity=secret.get('severity', 'HIGH'),
                title=f"Hardcoded {secret.get('type', 'Secret')} Detected",
                description=f"Found hardcoded {secret.get('type', 'secret')}: {
                    secret.get('keyword', '')}",
                file_path=secret.get('file_path', ''),
                line_number=secret.get('line_number', 0),
                owasp_category="A02:2021",
                owasp_name="Cryptographic Failures",
                cwe_ids=["CWE-798", "CWE-259"],
                remediation="Remove hardcoded secrets and use environment variables or a secrets manager.",
                confidence=secret.get('confidence', 0.9)
            )
            self.findings.append(finding)

    def add_patterns(self, patterns: List[Dict[str, Any]]):
        """
        Add insecure pattern findings

        Args:
            patterns: List of detected insecure patterns
        """
        for pattern in patterns:
            finding = SecurityFinding(
                id=f"SEC-{len(self.findings) + 1:04d}",
                type="pattern",
                severity=pattern.get('severity', 'MEDIUM'),
                title=pattern.get('title', 'Insecure Pattern Detected'),
                description=pattern.get('description', ''),
                file_path=pattern.get('file_path', ''),
                line_number=pattern.get('line_number', 0),
                owasp_category=pattern.get('owasp_category'),
                owasp_name=pattern.get('owasp_name'),
                cwe_ids=pattern.get('cwe_ids', []),
                remediation=pattern.get('remediation', ''),
                confidence=pattern.get('confidence', 0.8)
            )
            self.findings.append(finding)

    def add_cves(self, cves: Dict[str, List[Dict[str, Any]]]):
        """
        Add CVE findings

        Args:
            cves: Dictionary mapping package IDs to CVE vulnerabilities
        """
        for pkg_id, vulnerabilities in cves.items():
            for cve in vulnerabilities:
                finding = SecurityFinding(
                    id=f"SEC-{len(self.findings) + 1:04d}",
                    type="cve",
                    severity=cve.get('severity', 'UNKNOWN'),
                    title=f"{cve.get('cve_id', 'Unknown CVE')} in {pkg_id}",
                    description=cve.get('summary', ''),
                    file_path=cve.get('file_path', ''),
                    line_number=0,
                    owasp_category="A06:2021",
                    owasp_name="Vulnerable and Outdated Components",
                    cwe_ids=cve.get('cwe_ids', []),
                    remediation=self._generate_cve_remediation(cve),
                    confidence=1.0
                )
                self.findings.append(finding)

    def add_static_analysis(self, issues: List[Dict[str, Any]]):
        """
        Add static analysis findings

        Args:
            issues: List of static analysis issues
        """
        for issue in issues:
            finding = SecurityFinding(
                id=f"SEC-{len(self.findings) + 1:04d}",
                type="static_analysis",
                severity=issue.get('severity', 'MEDIUM'),
                title=issue.get('title', 'Static Analysis Issue'),
                description=issue.get('message', ''),
                file_path=issue.get('file_path', ''),
                line_number=issue.get('line_number', 0),
                owasp_category=issue.get('owasp_category'),
                owasp_name=issue.get('owasp_name'),
                cwe_ids=issue.get('cwe_ids', []),
                remediation=issue.get('remediation', ''),
                confidence=issue.get('confidence', 0.7)
            )
            self.findings.append(finding)

    def _generate_cve_remediation(self, cve: Dict[str, Any]) -> str:
        """
        Generate remediation advice for CVE

        Args:
            cve: CVE vulnerability dictionary

        Returns:
            Remediation string
        """
        fixed_versions = cve.get('fixed_versions', [])
        if fixed_versions:
            versions_str = ", ".join(fixed_versions[:3])
            return f"Upgrade to a fixed version: {versions_str}"
        else:
            return "Check vendor advisory for patches or workarounds."

    def deduplicate_issues(self) -> List[SecurityFinding]:
        """
        Remove duplicate findings

        Returns:
            Deduplicated list of findings
        """
        seen = set()
        unique_findings = []

        for finding in self.findings:
            # Create unique key based on type, file, line, and title
            key = (finding.type, finding.file_path,
                   finding.line_number, finding.title)

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                logger.debug(f"Duplicate finding removed: {finding.title}")

        logger.info(f"Deduplicated {len(self.findings)} → {
                    len(unique_findings)} findings")
        self.findings = unique_findings
        return unique_findings

    def calculate_risk_scores(self):
        """Calculate risk scores for all findings"""
        for finding in self.findings:
            finding.risk_score = self._calculate_risk_score(finding)

    def _calculate_risk_score(self, finding: SecurityFinding) -> float:
        """
        Calculate risk score for a finding

        Args:
            finding: Security finding

        Returns:
            Risk score (0-100)
        """
        # Base score from severity
        severity_weight = self.SEVERITY_WEIGHTS.get(finding.severity, 1)

        # Exploitability weight (CVEs and secrets are more exploitable)
        exploitability_weight = 1.0
        if finding.type == 'cve':
            exploitability_weight = 1.5
        elif finding.type == 'secret':
            exploitability_weight = 1.3
        elif finding.type == 'pattern':
            exploitability_weight = 1.2

        # Prevalence weight (critical OWASP categories)
        prevalence_weight = 1.0
        critical_categories = ['A01:2021', 'A02:2021', 'A03:2021', 'A06:2021']
        if finding.owasp_category in critical_categories:
            prevalence_weight = 1.2

        # Detectability (higher confidence = easier to detect = higher priority)
        detectability_weight = finding.confidence

        # Calculate composite score
        risk_score = (
            severity_weight * 0.4 +
            exploitability_weight * 0.3 +
            prevalence_weight * 0.2 +
            detectability_weight * 0.1
        ) * 10  # Scale to 0-100

        return min(risk_score, 100.0)

    def prioritize_by_severity(self) -> List[SecurityFinding]:
        """
        Sort findings by risk score and severity

        Returns:
            Sorted list of findings
        """
        # First calculate risk scores
        self.calculate_risk_scores()

        # Sort by risk score (descending), then severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1,
                          'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (-f.risk_score, severity_order.get(f.severity, 5))
        )

        self.findings = sorted_findings
        return sorted_findings

    def generate_security_summary(self) -> Dict[str, Any]:
        """
        Generate executive summary of security findings

        Returns:
            Summary dictionary
        """
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1

        # Count by type
        type_counts = defaultdict(int)
        for finding in self.findings:
            type_counts[finding.type] += 1

        # Count by OWASP category
        owasp_counts = defaultdict(int)
        for finding in self.findings:
            if finding.owasp_category:
                owasp_counts[finding.owasp_category] += 1

        # Top 5 critical findings
        top_critical = [
            f.to_dict() for f in self.findings
            if f.severity in ['CRITICAL', 'HIGH']
        ][:5]

        summary = {
            'total_issues': len(self.findings),
            'by_severity': dict(severity_counts),
            'by_type': dict(type_counts),
            'by_owasp': dict(owasp_counts),
            'top_critical_findings': top_critical,
            'average_risk_score': sum(f.risk_score for f in self.findings) / len(self.findings) if self.findings else 0
        }

        return summary

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings as dictionaries

        Returns:
            List of finding dictionaries
        """
        return [f.to_dict() for f in self.findings]

    def aggregate_all(
        self,
        secrets: List[Dict[str, Any]] = None,
        patterns: List[Dict[str, Any]] = None,
        cves: Dict[str, List[Dict[str, Any]]] = None,
        static_issues: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Aggregate findings from all sources

        Args:
            secrets: Secret detection findings
            patterns: Insecure pattern findings
            cves: CVE findings
            static_issues: Static analysis findings

        Returns:
            Aggregated security report
        """
        # Clear existing findings
        self.findings = []

        # Add findings from each source
        if secrets:
            self.add_secrets(secrets)

        if patterns:
            self.add_patterns(patterns)

        if cves:
            self.add_cves(cves)

        if static_issues:
            self.add_static_analysis(static_issues)

        # Process findings
        self.deduplicate_issues()
        self.prioritize_by_severity()

        # Generate report
        summary = self.generate_security_summary()
        findings = self.get_findings()

        return {
            'summary': summary,
            'findings': findings
        }


def aggregate_security_findings(
    secrets: List[Dict[str, Any]] = None,
    patterns: List[Dict[str, Any]] = None,
    cves: Dict[str, List[Dict[str, Any]]] = None,
    static_issues: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to aggregate security findings

    Args:
        secrets: Secret detection findings
        patterns: Insecure pattern findings
        cves: CVE findings
        static_issues: Static analysis findings

    Returns:
        Aggregated security report
    """
    aggregator = SecurityAggregator()
    return aggregator.aggregate_all(secrets, patterns, cves, static_issues)
