"""
Standalone Demo Script for Phase 4 CVE Detection

Demonstrates dependency scanning and CVE detection without requiring
the full code indexing infrastructure.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from security.dependency_analyzer import DependencyAnalyzer
from security.cve_tracker import CVETracker
from security.owasp_mapper import OWASPMapper
import json


def demo_cve_check(directory_path: str):
    """
    Demonstrate CVE checking functionality
    
    Args:
        directory_path: Path to directory containing dependency files
    """
    print("\n" + "="*60)
    print("PHASE 4 CVE DETECTION DEMO")
    print("="*60)
    
    # Step 1: Analyze dependencies
    print(f"\nStep 1: Scanning for dependencies in {directory_path}...")
    analyzer = DependencyAnalyzer()
    dependencies = analyzer.scan_directory(directory_path)
    
    print(f"Found {len(dependencies)} dependencies")
    
    # Group by ecosystem
    by_ecosystem = {}
    for dep in dependencies:
        ecosystem = dep.ecosystem
        by_ecosystem.setdefault(ecosystem, []).append(dep)
    
    for ecosystem, deps in by_ecosystem.items():
        print(f"  {ecosystem}: {len(deps)} packages")
    
    if not dependencies:
        print("\nNo dependencies found. Please provide a directory with:")
        print("  - pom.xml (Maven)")
        print("  - package.json (npm)")
        print("  - requirements.txt (Python)")
        print("  - build.gradle (Gradle)")
        return
    
    # Step 2: Check for CVEs
    print("\nStep 2: Querying OSV API for CVEs...")
    tracker = CVETracker()
    dep_dicts = [dep.to_dict() for dep in dependencies]
    cve_results = tracker.batch_query_osv(dep_dicts)
    
    print("="*60)
    print("CVE SCAN RESULTS")
    print("="*60)
    print(f"Vulnerable packages: {len(cve_results)}")
    
    # Step 3: Enrich with OWASP mapping
    print("\nStep 3: Mapping vulnerabilities to OWASP Top 10 2021...")
    mapper = OWASPMapper()
    
    # Count by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    all_vulns = []
    
    for pkg_id, vulns in cve_results.items():
        for vuln in vulns:
            vuln_dict = vuln.to_dict()
            vuln_dict = mapper.add_owasp_context(vuln_dict)
            all_vulns.append(vuln_dict)
            severity_counts[vuln.severity] += 1
    
    print(f"\nVulnerabilities by severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts[severity]
        if count > 0:
            print(f"  {severity}: {count}")
    
    # Step 4: Display top vulnerabilities
    if all_vulns:
        print(f"\nTop 5 Vulnerabilities:")
        sorted_vulns = sorted(
            all_vulns,
            key=lambda v: (
                {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}.get(v['severity'], 5)
            )
        )
        
        for i, vuln in enumerate(sorted_vulns[:5], 1):
            print(f"\n[{i}] {vuln['cve_id']} - {vuln['severity']}")
            print(f"    Package: {vuln['package_name']}:{vuln['package_version']}")
            print(f"    OWASP Category: {vuln.get('owasp_name', 'Not Mapped')}")
            
            summary = vuln['summary']
            if len(summary) > 100:
                print(f"    Summary: {summary[:100]}...")
            else:
                print(f"    Summary: {summary}")
            
            if vuln['fixed_versions']:
                fix_versions = ', '.join(vuln['fixed_versions'][:2])
                print(f"    Fix: Upgrade to {fix_versions}")
            else:
                print(f"    Fix: Check vendor advisory for patches")
    else:
        print("\n✅ No known vulnerabilities found!")
    
    print("="*60)
    
    # Save results
    output_file = "demo-cve-results.json"
    output_data = {
        'dependencies': [dep.to_dict() for dep in dependencies],
        'vulnerabilities': all_vulns,
        'summary': {
            'total_dependencies': len(dependencies),
            'vulnerable_packages': len(cve_results),
            'total_vulnerabilities': len(all_vulns),
            'by_severity': severity_counts
        }
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print("\nPhase 4 Demo Complete! ✅")
    print("="*60 + "\n")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        # Default to test fixtures
        directory = str(Path(__file__).parent / 'tests' / 'fixtures' / 'dependencies')
    
    try:
        demo_cve_check(directory)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
