"""
Phase 5 Demo Script - Security Reporting & Recommendations

Demonstrates comprehensive security reporting with CVE findings, OWASP mapping,
fix suggestions, and dashboard data export.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from security.dependency_analyzer import DependencyAnalyzer
from security.cve_tracker import CVETracker
from security.owasp_mapper import OWASPMapper
from security.security_aggregator import SecurityAggregator, SecurityFinding
from reporting.security_report_generator import SecurityReportGenerator
from reporting.fix_generator import FixGenerator
from reporting.dashboard_exporter import DashboardExporter


def demo_phase5_reporting():
    """Demonstrate Phase 5 reporting capabilities"""
    
    print("\n" + "="*60)
    print("PHASE 5 SECURITY REPORTING DEMO")
    print("="*60)
    
    # Step 1: Load Phase 4 results (or generate sample data)
    print("\nStep 1: Loading security analysis data...")
    
    # Check if Phase 4 demo results exist
    phase4_results = Path("demo-cve-results.json")
    
    if phase4_results.exists():
        print(f"  [OK] Loading results from {phase4_results}")
        with open(phase4_results, 'r') as f:
            data = json.load(f)
        
        dependencies = data.get('dependencies', [])
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Convert to expected format
        cve_results = {}
        for vuln in vulnerabilities:
            pkg_id = f"{vuln['package_name']}:{vuln['package_version']}"
            if pkg_id not in cve_results:
                cve_results[pkg_id] = []
            cve_results[pkg_id].append(vuln)
    else:
        print("  [WARN] No Phase 4 results found, using sample data...")
        dependencies, cve_results = _generate_sample_data()
    
    # Create sample security findings
    security_findings = _create_sample_findings()
    
    print(f"  [OK] Loaded {len(dependencies)} dependencies")
    print(f"  [OK] Found {len(cve_results)} vulnerable packages")
    print(f"  [OK] Created {len(security_findings)} security findings")

    
    # Step 2: Generate comprehensive security report
    print("\nStep 2: Generating comprehensive security report...")
    
    # Flatten CVE results
    all_cves = []
    for pkg_id, cves in cve_results.items():
        all_cves.extend(cves)
    
    generator = SecurityReportGenerator()
    report = generator.generate_comprehensive_report(
        security_findings=security_findings,
        cve_results=cve_results,
        dependencies=dependencies,
        metadata={'project': 'Demo Project', 'scan_type': 'full'}
    )
    
    print(f"  [OK] Generated executive summary")
    print(f"  [OK] Created OWASP Top 10 breakdown")
    print(f"  [OK] Formatted {len(all_cves)} CVE findings")
    print(f"  [OK] Built remediation plan with {len(report['remediation_plan'])} items")
    
    # Step 3: Generate fix suggestions
    print("\nStep 3: Generating fix suggestions...")
    
    fix_gen = FixGenerator()
    sample_fixes = []
    
    for finding in security_findings[:3]:  # Top 3 findings
        try:
            fix = fix_gen.generate_fix_suggestion(finding,  context={'language': 'python'})
            sample_fixes.append(fix)
            print(f"  [OK] Generated fix for {finding['id']}: {fix['difficulty']} ({fix['estimated_time']})")
        except Exception as e:
            print(f"  [WARN] Error generating fix: {e}")
    
    # Step 4: Export dashboard data
    print("\nStep 4: Exporting dashboard visualization data...")
    
    exporter = DashboardExporter()
    dashboard_data = exporter.export_all(
        security_findings=security_findings,
        cve_results=all_cves,
        dependencies=dependencies
    )
    
    print(f"  [OK] Exported severity distribution chart")
    print(f"  [OK] Exported OWASP coverage for {len(dashboard_data['owasp_coverage']['labels'])} categories")
    print(f"  [OK] Exported vulnerability trends")
    print(f"  [OK] Exported file risk scores for top {len(dashboard_data['file_risk_scores']['labels'])} files")
    
    # Step 5: Save reports
    print("\nStep 5: Saving reports...")
    
    # Save JSON report
    json_output = "phase5-security-report.json"
    generator.save_report(report, json_output, format='json')
    print(f"  [OK] Saved JSON report: {json_output}")
    
    # Save Markdown report
    md_output = "phase5-security-report.md"
    generator.save_report(report, md_output, format='markdown')
    print(f"  [OK] Saved Markdown report: {md_output}")
    
    # Save dashboard data
    dashboard_output = "phase5-dashboard-data.json"
    with open(dashboard_output, 'w') as f:
        json.dump(dashboard_data, f, indent=2)
    print(f"  [OK] Saved dashboard data: {dashboard_output}")
    
    # Save fix suggestions
    fixes_output = "phase5-fix-suggestions.json"
    with open(fixes_output, 'w') as f:
        json.dump(sample_fixes, f, indent=2)
    print(f"  [OK] Saved fix suggestions: {fixes_output}")
    
    # Step 6: Display summary
    print("\n" + "="*60)
    print("PHASE 5 DEMO SUMMARY")
    print("="*60)
    
    summary = report['executive_summary']
    print(f"\nOverall Risk: {summary['overall_risk_level']} (Score: {summary['risk_score']}/100)")
    print(f"Total Findings: {summary['total_findings']}")
    print(f"  - CVE Vulnerabilities: {summary['cve_count']}")
    print(f"  - Security Issues: {summary['security_issue_count']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in summary['severity_distribution'].items():
        print(f"  {severity}: {count}")
    
    print(f"\nDependency Health: {report['dependency_health']['health_score']}%")
    print(f"  - Total Dependencies: {report['dependency_health']['total_dependencies']}")
    print(f"  - Vulnerable: {report['dependency_health']['vulnerable_dependencies']}")
    
    print(f"\nTop Priority Fixes:")
    for i, item in enumerate(report['remediation_plan'][:5], 1):
        print(f"  {i}. [{item['severity']}] {item['title']}")
        print(f"     Effort: {item['estimated_effort']} | Impact: {item['impact']}")
    
    print("\n" + "="*60)
    print("Phase 5 Demo Complete! [SUCCESS]")
    print("="*60)

    print(f"\nGenerated Reports:")
    print(f"  - {json_output}")
    print(f"  - {md_output}")
    print(f"  - {dashboard_output}")
    print(f"  - {fixes_output}")
    print("\nView the Markdown report for a human-readable security analysis!")
    print("="*60 + "\n")


def _generate_sample_data():
    """Generate sample data if Phase 4 results don't exist"""
    dependencies = [
        {'package_name': 'flask', 'version': '2.0.1', 'ecosystem': 'pypi'},
        {'package_name': 'requests', 'version': '2.25.0', 'ecosystem': 'pypi'},
        {'package_name': 'django', 'version': '2.2.0', 'ecosystem': 'pypi'}
    ]
    
    cve_results = {
        'django:2.2.0': [
            {
                'cve_id': 'CVE-2021-33571',
                'package_name': 'django',
                'package_version': '2.2.0',
                'ecosystem': 'pypi',
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'summary': 'Potential directory-traversal via archive.extract()',
                'fixed_versions': ['2.2.24', '3.1.13', '3.2.5'],
                'references': ['https://www.djangoproject.com/weblog/2021/jul/01/security-releases/'],
                'cwe_ids': ['CWE-22'],
                'owasp_category': 'A01:2021',
                'owasp_name': 'Broken Access Control'
            }
        ]
    }
    
    return dependencies, cve_results


def _create_sample_findings():
    """Create sample security findings"""
    return [
        {
            'id': 'SEC-001',
            'type': 'secret',
            'severity': 'HIGH',
            'risk_score': 85,
            'title': 'Hardcoded API Key Detected',
            'description': 'API key hardcoded in configuration file',
            'file_path': 'src/config.py',
            'line_number': 25,
            'owasp_category': 'A02:2021',
            'owasp_name': 'Cryptographic Failures',
            'cwe_ids': ['CWE-798'],
            'remediation': 'Move API key to environment variables',
            'confidence': 0.95
        },
        {
            'id': 'SEC-002',
            'type': 'pattern',
            'severity': 'CRITICAL',
            'risk_score': 92,
            'title': 'SQL Injection Vulnerability',
            'description': 'User input directly concatenated into SQL query',
            'file_path': 'src/database.py',
            'line_number': 45,
            'owasp_category': 'A03:2021',
            'owasp_name': 'Injection',
            'cwe_ids': ['CWE-89'],
            'remediation': 'Use parameterized queries or ORM',
            'confidence': 0.90
        },
        {
            'id': 'SEC-003',
            'type': 'pattern',
            'severity': 'MEDIUM',
            'risk_score': 65,
            'title': 'Weak Cryptographic Hash (MD5)',
            'description': 'MD5 hash used for password storage',
            'file_path': 'src/auth.py',
            'line_number': 78,
            'owasp_category': 'A02:2021',
            'owasp_name': 'Cryptographic Failures',
            'cwe_ids': ['CWE-327'],
            'remediation': 'Use bcrypt or Argon2 for password hashing',
            'confidence': 1.0
        }
    ]


if __name__ == '__main__':
    try:
        demo_phase5_reporting()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
