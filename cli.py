"""
AI Code Review Platform - CLI Tool

Command-line interface for indexing, querying, and security analysis.
"""

import argparse
import sys
import logging
from pathlib import Path
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from indexing.code_indexer import CodeIndexer
from query.query_handler import QueryHandler
from security.secret_detector import SecretDetector
from security.dependency_analyzer import DependencyAnalyzer
from security.cve_tracker import CVETracker
from security.owasp_mapper import OWASPMapper
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_index(args):
    """Index a codebase"""
    logger.info(f"Indexing codebase: {args.path}")
    
    indexer = CodeIndexer(embedding_provider=args.embedding_provider)
    
    if args.clear:
        logger.info("Clearing existing index...")
        indexer.clear_index()
    
    summary = indexer.index_directory(args.path, force=args.force)
    
    print("\n" + "="*60)
    print("INDEXING COMPLETE")
    print("="*60)
    print(f"Directory: {summary['directory']}")
    print(f"Total files found: {summary['total_files']}")
    print(f"Files indexed: {summary['indexed_files']}")
    print(f"Files skipped (unchanged): {summary['skipped_files']}")
    print(f"Files failed: {summary['failed_files']}")
    print(f"Total code chunks: {summary['total_chunks']}")
    
    if summary['failed_file_list']:
        print(f"\nFailed files:")
        for f in summary['failed_file_list']:
            print(f"  - {f}")
    
    # Show stats
    stats = indexer.get_stats()
    print(f"\nIndex Statistics:")
    print(f"  Total chunks in index: {stats['total_chunks']}")
    print(f"  Embedding provider: {stats['embedding_provider']}")
    print(f"  Embedding dimension: {stats['embedding_dimension']}")
    print("="*60 + "\n")


def cmd_query(args):
    """Ask a security question"""
    logger.info(f"Processing query: {args.question}")
    
    indexer = CodeIndexer(embedding_provider=args.embedding_provider)
    handler = QueryHandler(indexer=indexer)
    
    response = handler.query(args.question, k=args.max_results)
    
    print("\n" + "="*60)
    print("QUERY RESPONSE")
    print("="*60)
    print(f"Question: {response['question']}")
    print(f"Intent: {response['intent']}")
    print(f"Chunks found: {response['chunks_found']}")
    
    if response.get('filters_applied'):
        print(f"Filters applied: {response['filters_applied']}")
    
    print(f"\nAnswer:")
    print("-" * 60)
    print(response['answer'])
    print("-" * 60)
    
    print(f"\nSources ({len(response['sources'])} code chunks):")
    for i, source in enumerate(response['sources'], 1):
        print(f"\n[{i}] {source['file']}:{source['lines']}")
        print(f"    Type: {source['type']}, Name: {source['name']}, Score: {source['score']}")
        if args.show_code:
            print(f"    Code preview:")
            print(f"    {source['code_preview']}")
    
    print("="*60 + "\n")
    
    # Save to JSON if requested
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(response, f, indent=2)
        print(f"Saved response to: {args.output}\n")


def cmd_scan_secrets(args):
    """Scan for hardcoded secrets"""
    logger.info(f"Scanning for secrets in: {args.path}")
    
    path = Path(args.path)
    detector = SecretDetector()
    all_secrets = []
    
    if path.is_file():
        # Single file
        with open(path, 'r', encoding='utf-8') as f:
            code = f.read()
        secrets = detector.scan_code(code, str(path))
        all_secrets.extend(secrets)
    
    else:
        # Directory
        for ext in ['.py', '.java', '.js', '.go', '.rb', '.php']:
            for file_path in path.rglob(f"*{ext}"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    secrets = detector.scan_code(code, str(file_path))
                    all_secrets.extend(secrets)
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")
    
    print("\n" + "="*60)
    print("SECRET SCAN RESULTS")
    print("="*60)
    print(f"Total secrets found: {len(all_secrets)}")
    
    # Group by severity
    by_severity = {}
    for secret in all_secrets:
        severity = secret.get('severity', 'unknown')
        by_severity.setdefault(severity, []).append(secret)
    
    for severity in ['critical', 'high', 'medium', 'low']:
        secrets = by_severity.get(severity, [])
        if secrets:
            print(f"\n{severity.upper()} Severity ({len(secrets)}):")
            for secret in secrets[:10]:  # Show top 10
                print(f"  - {secret['file']}:{secret['line']}")
                print(f"    Type: {secret['type']}")
                print(f"    Value: {secret['value'][:50]}...")
                if 'context' in secret:
                    print(f"    Context: {secret['context'][:80]}")
    
    print("="*60 + "\n")
    
    # Save to JSON if requested
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(all_secrets, f, indent=2)
        print(f"Saved results to: {args.output}\n")


def cmd_stats(args):
    """Show index statistics"""
    indexer = CodeIndexer()
    stats = indexer.get_stats()
    
    print("\n" + "="*60)
    print("INDEX STATISTICS")
    print("="*60)
    print(f"Total chunks indexed: {stats['total_chunks']}")
    print(f"Total files indexed: {stats['total_files']}")
    print(f"Embedding provider: {stats['embedding_provider']}")
    print(f"Embedding dimension: {stats['embedding_dimension']}")
    print(f"Last updated: {stats.get('last_updated', 'Never')}")
    print("="*60 + "\n")


def cmd_cve_check(args):
    """Check dependencies for CVEs"""
    logger.info(f"Checking dependencies for CVEs in: {args.path}")
    
    # Analyze dependencies
    analyzer = DependencyAnalyzer()
    dependencies = analyzer.scan_directory(args.path)
    
    print("\n" + "="*60)
    print("DEPENDENCY SCAN")
    print("="*60)
    print(f"Total dependencies found: {len(dependencies)}")
    
    # Group by ecosystem
    by_ecosystem = {}
    for dep in dependencies:
        ecosystem = dep.ecosystem
        by_ecosystem.setdefault(ecosystem, []).append(dep)
    
    for ecosystem, deps in by_ecosystem.items():
        print(f"  {ecosystem}: {len(deps)} packages")
    
    # Check for CVEs
    if dependencies:
        print("\nScanning for CVEs...")
        
        tracker = CVETracker(cache_dir=args.cache_dir)
        dep_dicts = [dep.to_dict() for dep in dependencies]
        cve_results = tracker.batch_query_osv(dep_dicts)
        
        print("="*60)
        print("CVE SCAN RESULTS")
        print("="*60)
        print(f"Vulnerable packages: {len(cve_results)}")
        
        # Enrich with OWASP mapping
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
        
        # Show top vulnerabilities
        if all_vulns:
            print(f"\nTop Vulnerabilities:")
            sorted_vulns = sorted(all_vulns, key=lambda v: severity_counts.get(v['severity'], 0), reverse=True)
            
            for i, vuln in enumerate(sorted_vulns[:10], 1):
                print(f"\n[{i}] {vuln['cve_id']} - {vuln['severity']}")
                print(f"    Package: {vuln['package_name']}:{vuln['package_version']}")
                print(f"    OWASP: {vuln.get('owasp_name', 'Not Mapped')}")
                print(f"    Summary: {vuln['summary'][:100]}...") if len(vuln['summary']) > 100 else print(f"    Summary: {vuln['summary']}")
                if vuln['fixed_versions']:
                    print(f"    Fix: Upgrade to {', '.join(vuln['fixed_versions'][:2])}")
        
        print("="*60 + "\n")
        
        # Save to JSON if requested
        if args.output:
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
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            print(f"Saved results to: {args.output}\n")
    else:
        print("No dependencies found.")
        print("="*60 + "\n")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI Code Review Platform - Security Q&A System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Index a codebase
  python cli.py index ./my-java-project
  
  # Ask a security question
  python cli.py query "Are there any hardcoded API keys?"
  
  # Scan for secrets
  python cli.py scan-secrets ./src
  
  # Check dependencies for CVEs
  python cli.py cve-check ./my-java-project
  
  # Show index stats
  python cli.py stats
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Index command
    index_parser = subparsers.add_parser('index', help='Index a codebase')
    index_parser.add_argument('path', help='Path to codebase directory')
    index_parser.add_argument('--force', action='store_true', help='Force re-indexing')
    index_parser.add_argument('--clear', action='store_true', help='Clear existing index first')
    index_parser.add_argument('--embedding-provider', choices=['local', 'openai', 'codestral'],
                             help='Embedding provider to use')
    index_parser.set_defaults(func=cmd_index)
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Ask a security question')
    query_parser.add_argument('question', help='Natural language security question')
    query_parser.add_argument('--max-results', type=int, default=5, help='Max code chunks to retrieve')
    query_parser.add_argument('--show-code', action='store_true', help='Show code previews in output')
    query_parser.add_argument('--output', help='Save response to JSON file')
    query_parser.add_argument('--embedding-provider', choices=['local', 'openai', 'codestral'],
                             help='Embedding provider to use')
    query_parser.set_defaults(func=cmd_query)
    
    # Scan secrets command
    secrets_parser = subparsers.add_parser('scan-secrets', help='Scan for hardcoded secrets')
    secrets_parser.add_argument('path', help='Path to file or directory')
    secrets_parser.add_argument('--output', help='Save results to JSON file')
    secrets_parser.set_defaults(func=cmd_scan_secrets)
    
    # CVE check command
    cve_parser = subparsers.add_parser('cve-check', help='Check dependencies for CVEs')
    cve_parser.add_argument('path', help='Path to project directory')
    cve_parser.add_argument('--output', help='Save results to JSON file')
    cve_parser.add_argument('--cache-dir', help='Directory for caching CVE results')
    cve_parser.set_defaults(func=cmd_cve_check)
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show index statistics')
    stats_parser.set_defaults(func=cmd_stats)
    
    # Parse args
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
