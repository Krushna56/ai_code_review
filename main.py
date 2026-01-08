#!/usr/bin/env python
"""
AI-Powered Code Review Platform - Main Entry Point

A unified interface for all 6 phases of the AI code review system:
- Phase 1: Static Analysis (AST metrics, multi-linter)
- Phase 2: Semantic Embeddings (vector search)
- Phase 3: RAG-based Q&A System
- Phase 4: CVE Detection (dependency scanning)
- Phase 5: Security Reporting (comprehensive reports)
- Phase 6: Web Dashboard (visualization)
"""

import sys
import argparse
from pathlib import Path
import logging

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from code_analysis import analyze_codebase
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print welcome banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║      🔒 AI-Powered Code Review Platform                 ║
║                                                          ║
║  A comprehensive security and quality analysis tool     ║
║  with CVE detection, LLM agents, and visualization      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Features:
  ✓ Phase 1: Static Analysis (AST, linters)
  ✓ Phase 2: Semantic Embeddings
  ✓ Phase 3: RAG Q&A System
  ✓ Phase 4: CVE Detection
  ✓ Phase 5: Security Reports
  ✓ Phase 6: Web Dashboard

"""
    print(banner)


def cmd_analyze(args):
    """Run comprehensive code analysis"""
    print_banner()
    
    logger.info(f"Analyzing codebase: {args.input}")
    logger.info(f"Output directory: {args.output}")
    
    # Create output directory
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*60}")
    print("STARTING COMPREHENSIVE ANALYSIS")
    print(f"{'='*60}\n")
    
    # Run full analysis
    results = analyze_codebase(args.input, str(output_path))
    
    # Print summary
    print(f"\n{'='*60}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*60}\n")
    
    summary = results.get('summary', {})
    print(f"📊 Files Analyzed: {summary.get('files_analyzed', 0)}")
    print(f"🐛 Code Quality Issues: {summary.get('code_quality_issues', 0)}")
    print(f"🔴 Security Issues: {summary.get('security_issues', 0)}")
    print(f"🛡️  CVE Vulnerabilities: {summary.get('cve_vulnerabilities', 0)}")
    print(f"🔑 Hardcoded Secrets: {summary.get('hardcoded_secrets', 0)}")
    print(f"📦 Dependencies Scanned: {summary.get('total_dependencies', 0)}")
    print(f"⚠️  Vulnerable Packages: {summary.get('vulnerable_packages', 0)}")
    
    print(f"\n📁 Results saved to: {output_path}")
    print(f"\nGenerated Files:")
    print(f"  • linter_results.json - Static analysis results")
    
    if results.get('cve_results'):
        print(f"  • cve_results.json - CVE scan results")
    
    if results.get('security_report'):
        print(f"  • security_report.json - Comprehensive security report")
        print(f"  • security_report.md - Human-readable security report")
    
    if results.get('fix_suggestions'):
        print(f"  • fix_suggestions.json - Automated fix recommendations")
    
    if results.get('dashboard_data'):
        print(f"  • dashboard_data.json - Dashboard visualization data")
    
    # Print security report summary
    if results.get('security'):
        print(f"\n{results['security']}")
    
    print(f"{'='*60}\n")
    
    # Suggest next steps
    print("Next Steps:")
    print("  1. Review security_report.md for detailed findings")
    print("  2. Check fix_suggestions.json for remediation guidance")
    print("  3. View dashboard: python app.py (then open http://localhost:5000/dashboard)")
    print("  4. Ask questions: python cli.py query \"Are there any SQL injection risks?\"")
    print()


def cmd_web(args):
    """Launch web application and dashboard"""
    print_banner()
    
    print("Starting Flask web application...")
    print("Features:")
    print("  • Upload ZIP files for analysis")
    print("  • View comprehensive results")
    print("  • Interactive security dashboard")
    print("  • Real-time visualizations")
    print()
    print(f"Dashboard will be available at: http://localhost:{args.port}")
    print("Press Ctrl+C to stop the server\n")
    
    # Import and run Flask app
    from app import app
    app.run(host='0.0.0.0', port=args.port, debug=args.debug, use_reloader=False)


def cmd_demo(args):
    """Run demonstration of specific phase"""
    print_banner()
    
    if args.phase == '4':
        print("Running Phase 4 Demo: CVE Detection")
        print(f"{'='*60}\n")
        from demo_phase4 import demo_cve_check
        demo_cve_check(args.path or '.')
        
    elif args.phase == '5':
        print("Running Phase 5 Demo: Security Reporting")
        print(f"{'='*60}\n")
        from demo_phase5 import demo_phase5_reporting
        demo_phase5_reporting()
        
    else:
        print(f"Demo for phase {args.phase} not available.")
        print("Available demos: 4, 5")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Powered Code Review Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run comprehensive analysis
  python main.py analyze ./my-project -o ./results
  
  # Launch web dashboard
  python main.py web
  
  # Run Phase 4 demo (CVE detection)
  python main.py demo 4 --path ./tests/fixtures/dependencies
  
  # Run Phase 5 demo (Security reporting)
  python main.py demo 5

For more options, use the CLI tool:
  python cli.py --help
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Run comprehensive code analysis')
    analyze_parser.add_argument('input', help='Path to codebase directory')
    analyze_parser.add_argument('-o', '--output', default='./output', 
                               help='Output directory for results (default: ./output)')
    analyze_parser.set_defaults(func=cmd_analyze)
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Launch web dashboard')
    web_parser.add_argument('-p', '--port', type=int, default=5000, 
                           help='Port to run on (default: 5000)')
    web_parser.add_argument('--debug', action='store_true', 
                           help='Run in debug mode')
    web_parser.set_defaults(func=cmd_web)
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run phase demonstration')
    demo_parser.add_argument('phase', choices=['4', '5'], 
                            help='Phase to demonstrate (4=CVE, 5=Reporting)')
    demo_parser.add_argument('--path', help='Path for demo (if applicable)')
    demo_parser.set_defaults(func=cmd_demo)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return
    
    # Execute command
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
