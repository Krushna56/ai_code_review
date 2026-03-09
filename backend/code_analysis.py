"""
Comprehensive Code Analysis Pipeline

Integrates:
- Static analysis (AST metrics, multi-linter)
- Embeddings and semantic search
- LLM agents for intelligent review
- Meta-reasoning and reporting
"""

import os
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from autopep8 import fix_code
import difflib
from datetime import datetime

import config
import google.genai as genai # Added this import

# Phase 6: LLM Metrics Extraction
try:
    from llm_agents.metrics_extractor import MetricsExtractor
    METRICS_EXTRACTOR_AVAILABLE = True
except ImportError:
    logging.warning("MetricsExtractor not available")
    METRICS_EXTRACTOR_AVAILABLE = False

# Phase 6: Git History Analysis
try:
    from git_analyzer import analyze_repo_git
    GIT_ANALYZER_AVAILABLE = True
except ImportError:
    logging.warning("git_analyzer not available")
    GIT_ANALYZER_AVAILABLE = False
from static_analysis.ast_parser import ASTParser
from static_analysis.multi_linter import MultiLinter
from utils.file_filter import should_ignore_file, should_ignore_directory, is_code_file

# Optional imports based on feature flags
if config.ENABLE_SEMANTIC_SEARCH:
    try:
        from embeddings.code_embedder import CodeEmbedder
        from embeddings.vector_store import VectorStore
    except ImportError:
        logging.warning("Embeddings not available")
        config.ENABLE_SEMANTIC_SEARCH = False

if config.ENABLE_LLM_AGENTS:
    try:
        from llm_agents.security_reviewer import SecurityReviewer
        from llm_agents.refactor_agent import RefactorAgent
    except ImportError:
        logging.warning("LLM agents not available")
        config.ENABLE_LLM_AGENTS = False

# Import meta-reasoner
try:
    from meta_reasoner import generate_comprehensive_report
    META_REASONER_AVAILABLE = True
except ImportError:
    logging.warning("Meta-reasoner not available")
    META_REASONER_AVAILABLE = False

# Phase 4: CVE Detection
try:
    from security.dependency_analyzer import DependencyAnalyzer
    from security.cve_tracker import CVETracker
    from security.owasp_mapper import OWASPMapper
    from security.secret_detector import SecretDetector
    CVE_DETECTION_AVAILABLE = True
except ImportError:
    logging.warning("CVE detection not available")
    CVE_DETECTION_AVAILABLE = False

# Phase 5: Security Reporting
try:
    from reporting.security_report_generator import SecurityReportGenerator
    from reporting.fix_generator import FixGenerator
    from reporting.dashboard_exporter import DashboardExporter
    SECURITY_REPORTING_AVAILABLE = True
except ImportError:
    logging.warning("Security reporting not available")
    SECURITY_REPORTING_AVAILABLE = False

logging.basicConfig(level=getattr(logging, config.LOG_LEVEL))
logger = logging.getLogger(__name__)


def highlight_code_diff(original_code, modified_code):
    """
    Highlights differences in modified code using <span class="highlight">.
    Only highlights added or changed lines.
    """
    original_lines = original_code.splitlines()
    modified_lines = modified_code.splitlines()
    diff = list(difflib.ndiff(original_lines, modified_lines))

    highlighted = []
    for line in diff:
        if line.startswith('+ '):
            highlighted.append(f'<span class="highlight">{line[2:]}</span>')
        elif line.startswith('? '):
            continue
        elif line.startswith('  '):
            highlighted.append(line[2:])
        # Do not include removed lines
    return '\n'.join(highlighted)


class CodeAnalyzer:
    """Comprehensive code analyzer"""

    def __init__(self):
        self.ast_parser = ASTParser()
        self.multi_linter = MultiLinter()

        # Initialize optional components
        if config.ENABLE_SEMANTIC_SEARCH:
            try:
                self.embedder = CodeEmbedder()
                self.vector_store = None  # Initialized per analysis
            except Exception as e:
                logger.warning(f"Failed to initialize embeddings: {e}")
                config.ENABLE_SEMANTIC_SEARCH = False

        if config.ENABLE_LLM_AGENTS:
            try:
                self.security_agent = SecurityReviewer()
                self.refactor_agent = RefactorAgent()
            except Exception as e:
                logger.warning(f"Failed to initialize LLM agents: {e}")
                config.ENABLE_LLM_AGENTS = False

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single Python file"""
        result = {
            'file': file_path,
            'metrics': {},
            'static_issues': [],
            'llm_insights': {},
            'formatted_code': None
        }

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_code = f.read()

            # 1. AST Metrics
            metrics = self.ast_parser.parse_code(original_code, file_path)
            if metrics:
                result['metrics'] = self.ast_parser.get_metrics_dict()

            # 2. Code formatting
            formatted_code = fix_code(original_code)
            result['formatted_code'] = highlight_code_diff(
                original_code, formatted_code)

            # 3. LLM Analysis (if enabled)
            if config.ENABLE_LLM_AGENTS:
                # For large files, analyze in chunks or summarize
                if len(original_code) > 10000:
                    logger.info(
                        f"Large file detected ({len(original_code)} chars), analyzing key sections")
                    result['llm_insights'] = self._run_llm_analysis_chunked(
                        original_code,
                        result['metrics'],
                        result['static_issues'],
                        file_path
                    )
                else:
                    result['llm_insights'] = self._run_llm_analysis(
                        original_code,
                        result['metrics'],
                        result['static_issues']
                    )

            return result

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            result['error'] = str(e)
            return result

    def _run_llm_analysis(self, code: str, metrics: Dict, static_issues: List) -> Dict[str, Any]:
        """Run LLM agents for intelligent analysis"""
        insights = {
            'security': {},
            'refactoring': {},
            'analyzed': True,
            'timestamp': datetime.now().isoformat()
        }

        context = {
            'metrics': metrics,
            'static_analysis': static_issues,
            'code_length': len(code)
        }

        try:
            # Security review with enhanced context
            logger.info("Running LLM security analysis...")
            security_result = self.security_agent.analyze(code, context)
            insights['security'] = security_result
            logger.info(f"LLM security analysis complete: "
                        f"{len(security_result.get('issues', []))} issues found")

            # Refactoring suggestions
            logger.info("Running LLM refactoring analysis...")
            refactor_result = self.refactor_agent.analyze(code, context)
            insights['refactoring'] = refactor_result
            logger.info(f"LLM refactoring complete: "
                        f"{len(refactor_result.get('suggestions', []))} suggestions")

        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            insights['error'] = str(e)
            insights['analyzed'] = False

        return insights

    def _run_llm_analysis_chunked(self, code: str, metrics: Dict, static_issues: List, file_path: str) -> Dict[str, Any]:
        """Run LLM analysis on large files by focusing on problematic sections"""
        insights = {
            'security': {},
            'refactoring': {},
            'analyzed': True,
            'chunked': True,
            'timestamp': datetime.now().isoformat()
        }

        try:
            # Extract critical sections (functions with issues, high complexity areas)
            critical_sections = self._extract_critical_sections(
                code, metrics, static_issues)

            # Analyze each critical section
            all_security_issues = []
            all_refactor_suggestions = []

            for section in critical_sections[:5]:  # Limit to top 5 sections
                context = {
                    'metrics': metrics,
                    'static_analysis': static_issues,
                    'section_type': section['type'],
                    'file_path': file_path
                }

                security_result = self.security_agent.analyze(
                    section['code'], context)
                if 'issues' in security_result:
                    all_security_issues.extend(security_result['issues'])

                refactor_result = self.refactor_agent.analyze(
                    section['code'], context)
                if 'suggestions' in refactor_result:
                    all_refactor_suggestions.extend(
                        refactor_result['suggestions'])

            insights['security'] = {
                'issues': all_security_issues, 'analyzed_sections': len(critical_sections)}
            insights['refactoring'] = {
                'suggestions': all_refactor_suggestions, 'analyzed_sections': len(critical_sections)}

        except Exception as e:
            logger.error(f"Error in chunked LLM analysis: {e}")
            insights['error'] = str(e)
            insights['analyzed'] = False

        return insights

    def _extract_critical_sections(self, code: str, metrics: Dict, static_issues: List) -> List[Dict[str, Any]]:
        """Extract critical code sections for focused analysis"""
        sections = []

        # Split code into logical sections (functions, classes)
        lines = code.split('\n')
        current_section = []
        section_start = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detect function or class definitions
            if stripped.startswith('def ') or stripped.startswith('class '):
                # Save previous section if it exists
                if current_section:
                    sections.append({
                        'type': 'function' if 'def ' in current_section[0] else 'class',
                        'code': '\n'.join(current_section),
                        'start_line': section_start,
                        'end_line': i - 1
                    })

                current_section = [line]
                section_start = i
            else:
                current_section.append(line)

        # Add last section
        if current_section:
            sections.append({
                'type': 'function',
                'code': '\n'.join(current_section),
                'start_line': section_start,
                'end_line': len(lines) - 1
            })

        # Prioritize sections with static issues
        issue_lines = {issue.get('line', 0) for issue in static_issues}
        for section in sections:
            section['has_issues'] = any(
                section['start_line'] <= line <= section['end_line']
                for line in issue_lines
            )

        # Sort by issues first, then by size
        sections.sort(key=lambda s: (
            not s.get('has_issues', False), -len(s['code'])))

        return sections


def _generate_secret_description(secret_type: str, context: Optional[str] = None) -> str:
    """Generate detailed description for a secret finding"""
    
    definitions = {
        'api_key': {
            'meaning': 'An API key was found hardcoded directly in the source code.',
            'reason': 'Hardcoded keys can be easily harvested by attackers scanning public repositories.'
        },
        'password': {
            'meaning': 'A password string was detected in plain text.',
            'reason': 'Passwords should never be stored in code as it compromises account security.'
        },
        'private_key': {
            'meaning': 'A private cryptographic key was found.',
            'reason': 'Private keys are the root of trust; exposing them compromises all encrypted data.'
        },
        'token': {
            'meaning': 'An authentication token was identified.',
            'reason': 'Tokens provide access to services and should be treated as temporary credentials.'
        },
        'aws': {
            'meaning': 'AWS credentials were detected.',
            'reason': 'Leaked AWS keys can lead to massive resource theft and data breaches.'
        },
        'high_entropy': {
            'meaning': 'A high-entropy string (possible secret) was detected.',
            'reason': 'Randomized strings often indicate API keys or secrets that should be externalized.'
        },
        'generic': {
            'meaning': 'Sensitive data appears to be hardcoded.',
            'reason': 'Hardcoding secrets violates the separation of config and code.'
        }
    }
    
    # Find best match
    info = definitions.get('generic')
    for key, val in definitions.items():
        if key in secret_type.lower():
            info = val
            break
            
    description = f"Meaning: {info['meaning']}\nReason: {info['reason']}"
    
    if context:
        description += f"\n\nContext:\n{context.strip()}"
        
    return description


def analyze_codebase(input_path, output_path):
    """
    Main analysis function - analyzes entire codebase

    Args:
        input_path: Path to code directory
        output_path: Path to save results

    Returns:
        Analysis results dictionary
    """
    summary = {
        "files_analyzed": 0,
        "files_formatted": 0,
        "security_issues": 0,
        "code_quality_issues": 0,
        "files_updated": 0
    }
    details = {}
    total_loc = 0  # Track total lines of code
    _start_time = time.time()

    # ── File cap: limit how many files are analyzed to prevent timeouts ──
    max_files = int(os.getenv('MAX_FILES_TO_ANALYZE', '100'))
    logger.info(f"Analysis will process up to {max_files} files")

    analyzer = CodeAnalyzer()

    # Analyze Python files
    for root, dirs, files in os.walk(input_path):
        # Filter out ignored directories (modify in-place to prevent os.walk from entering them)
        dirs[:] = [d for d in dirs if not should_ignore_directory(os.path.join(root, d))]
        
        for file in files:
            if not file.endswith(".py"):
                continue

            # Respect the file cap
            if summary["files_analyzed"] >= max_files:
                logger.info(f"Reached file cap of {max_files}. Skipping remaining files.")
                break

            file_path = os.path.join(root, file)

            # Skip ignored files
            if should_ignore_file(file_path):
                continue

            rel_path = os.path.relpath(file_path, input_path)
            logger.info(f"Analyzing {rel_path}")

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    original_code = f.read()

                # Get AST metrics
                metrics = analyzer.ast_parser.parse_code(
                    original_code, file_path)
                metrics_dict = analyzer.ast_parser.get_metrics_dict() if metrics else {}

                # Format code — skip large files to save time
                file_lines = len(original_code.splitlines())
                if file_lines <= 500:
                    formatted_code = fix_code(original_code)
                else:
                    logger.debug(f"Skipping autopep8 on large file ({file_lines} lines): {rel_path}")
                    formatted_code = original_code

                # Save formatted version
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_code)

                # Store results
                details[rel_path] = {
                    "before": original_code,
                    "after": highlight_code_diff(original_code, formatted_code),
                    "metrics": metrics_dict
                }

                summary["files_analyzed"] += 1
                summary["files_formatted"] += 1
                summary["files_updated"] += 1

                # Track LOC
                total_loc += len(original_code.splitlines())

            except Exception as e:
                logger.error(f"Error processing {rel_path}: {e}")

    # Run multi-linter analysis
    logger.info("Running static analysis tools...")
    linter_results = analyzer.multi_linter.run_all(input_path)
    aggregated = analyzer.multi_linter.get_aggregated_results()

    summary["security_issues"] = aggregated.get(
        'by_severity', {}).get('high', 0)
    summary["code_quality_issues"] = aggregated.get('total_issues', 0)

    # Save linter results
    linter_output_path = os.path.join(output_path, "linter_results.json")
    with open(linter_output_path, "w", encoding="utf-8") as f:
        json.dump({
            'summary': aggregated,
            'details': {name: res.to_dict() for name, res in linter_results.items()}
        }, f, indent=2)

    # Phase 4: CVE Detection
    cve_results = {}
    dependencies = []
    all_vulnerabilities = []

    if CVE_DETECTION_AVAILABLE and getattr(config, 'ENABLE_CVE_DETECTION', True):
        try:
            logger.info("Phase 4: Scanning dependencies for CVEs...")
            dependency_analyzer = DependencyAnalyzer()
            dependencies = dependency_analyzer.scan_directory(input_path)

            if dependencies:
                logger.info(f"Found {len(dependencies)} dependencies")
                cve_tracker = CVETracker()
                dep_dicts = [dep.to_dict() for dep in dependencies]
                cve_results = cve_tracker.batch_query_osv(dep_dicts)

                # Enrich with OWASP mapping
                mapper = OWASPMapper()
                for pkg_id, vulns in cve_results.items():
                    for vuln in vulns:
                        vuln_dict = vuln.to_dict()
                        vuln_dict = mapper.add_owasp_context(vuln_dict)
                        all_vulnerabilities.append(vuln_dict)

                logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in dependencies")

                # Save CVE results
                cve_output_path = os.path.join(output_path, "cve_results.json")
                with open(cve_output_path, "w", encoding="utf-8") as f:
                    json.dump({
                        'dependencies': [dep.to_dict() for dep in dependencies],
                        'vulnerabilities': all_vulnerabilities
                    }, f, indent=2)
            else:
                logger.info("No dependencies found for CVE scanning")
        except Exception as e:
            logger.error(f"Error in CVE detection: {e}")

    # Scan for hardcoded secrets
    security_findings = []
    if CVE_DETECTION_AVAILABLE:
        try:
            logger.info("Scanning for hardcoded secrets...")
            secret_detector = SecretDetector()
            for root, dirs, files in os.walk(input_path):
                # Filter out ignored directories
                dirs[:] = [d for d in dirs if not should_ignore_directory(os.path.join(root, d))]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip ignored files
                    if should_ignore_file(file_path):
                        continue
                    
                    # Only scan code files and environment files (but not JSON, MD, etc.)
                    if file.endswith(('.py', '.java', '.js', '.go', '.rb', '.php', '.env')):
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                code = f.read()
                            secrets = secret_detector.scan_code(
                                code, file_path)

                            # Convert to security findings format
                            for secret in secrets:
                                security_findings.append({
                                    'id': f"SECRET-{len(security_findings)+1}",
                                    'type': 'secret',
                                    'severity': secret.get('severity', 'HIGH').upper(),
                                    'risk_score': 85,
                                    'title': f"Hardcoded {secret['type']} Detected",
                                    'description': _generate_secret_description(secret.get('type', 'generic'), secret.get('context')),
                                    'file_path': secret['file'],
                                    'line_number': secret.get('line', 0),
                                    'owasp_category': 'A02:2021',
                                    'owasp_name': 'Cryptographic Failures',
                                    'cwe_ids': ['CWE-798'],
                                    'remediation': 'Move sensitive data to environment variables or secure vault',
                                    'confidence': 0.9
                                })
                        except Exception as e:
                            logger.debug(f"Error scanning {file_path} for secrets: {e}")

            if security_findings:
                logger.info(
                    f"Found {len(security_findings)} hardcoded secrets")
        except Exception as e:
            logger.error(f"Error in secret detection: {e}")

    # Generate comprehensive report with meta-reasoner
    comprehensive_report = None
    if META_REASONER_AVAILABLE:
        try:
            logger.info(
                "Generating comprehensive report with meta-reasoner...")
            comprehensive_report = generate_comprehensive_report(
                linter_results=aggregated,
                llm_insights=None,  # Add LLM insights if available
                summary=summary
            )

            # Save comprehensive report
            report_path = os.path.join(
                output_path, "comprehensive_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(comprehensive_report, f, indent=2)

            logger.info(f"Comprehensive report saved to {report_path}")
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {e}")

    # Phase 5: Security Reporting
    security_report_data = None
    fix_suggestions = []
    dashboard_data = None

    if SECURITY_REPORTING_AVAILABLE and getattr(config, 'ENABLE_SECURITY_REPORTING', True):
        try:
            logger.info(
                "Phase 5: Generating security reports and recommendations...")

            # Generate comprehensive security report
            report_generator = SecurityReportGenerator()
            security_report_data = report_generator.generate_comprehensive_report(
                security_findings=security_findings,
                cve_results=cve_results,
                dependencies=[dep.to_dict() for dep in dependencies],
                metadata={
                    'project': os.path.basename(input_path),
                    'scan_type': 'full',
                    'total_files': summary['files_analyzed']
                }
            )

            # Save JSON report
            json_report_path = os.path.join(
                output_path, "security_report.json")
            report_generator.save_report(
                security_report_data, json_report_path, format='json')
            logger.info(f"Security report (JSON) saved to {json_report_path}")

            # Save Markdown report
            md_report_path = os.path.join(output_path, "security_report.md")
            report_generator.save_report(
                security_report_data, md_report_path, format='markdown')
            logger.info(f"Security report (Markdown) saved to {md_report_path}")

            # Generate fix suggestions for top findings
            fix_generator = FixGenerator()
            for finding in security_findings[:5]:  # Top 5 findings
                try:
                    fix = fix_generator.generate_fix_suggestion(
                        finding, context={'language': 'python'})
                    fix_suggestions.append(fix)
                except Exception as e:
                    logger.debug(f"Could not generate fix for {finding.get('id')}: {e}")

            # Save fix suggestions
            if fix_suggestions:
                fix_output_path = os.path.join(
                    output_path, "fix_suggestions.json")
                with open(fix_output_path, "w", encoding="utf-8") as f:
                    json.dump(fix_suggestions, f, indent=2)
                logger.info(f"Fix suggestions saved to {fix_output_path}")

            # Export dashboard data
            exporter = DashboardExporter()
            dashboard_data = exporter.export_all(
                security_findings=security_findings,
                cve_results=all_vulnerabilities,
                dependencies=[dep.to_dict() for dep in dependencies]
            )

            dashboard_output_path = os.path.join(
                output_path, "dashboard_data.json")
            with open(dashboard_output_path, "w", encoding="utf-8") as f:
                json.dump(dashboard_data, f, indent=2)
            logger.info(f"Dashboard data exported to {dashboard_output_path}")

        except Exception as e:
            logger.error(f"Error in security reporting: {e}")

    # ── Generate security report ──────────────────────────────────────────────
    security_report = _generate_security_report(aggregated)

    # Enhanced summary with Phase 4 & 5 data
    summary['cve_vulnerabilities'] = len(all_vulnerabilities)
    summary['hardcoded_secrets'] = len(security_findings)
    summary['total_dependencies'] = len(dependencies)
    summary['vulnerable_packages'] = len(cve_results)
    summary['total_loc'] = total_loc

    # ── Phase 6a: LLM Metrics Extraction ────────────────────────────────────
    llm_metrics = {}
    if METRICS_EXTRACTOR_AVAILABLE and getattr(config, 'ENABLE_LLM_AGENTS', True):
        try:
            logger.info("Phase 6a: Extracting comprehensive metrics via LLM...")
            extractor = MetricsExtractor()
            llm_metrics = extractor.extract(
                linter_results=aggregated,
                security_findings=security_findings,
                cve_count=len(all_vulnerabilities),
                file_count=summary['files_analyzed'],
                total_loc=total_loc,
                file_details=details,
            )
            # Save to output
            metrics_path = os.path.join(output_path, "metrics.json")
            with open(metrics_path, 'w', encoding='utf-8') as f:
                json.dump(llm_metrics, f, indent=2)
            logger.info(f"Metrics JSON saved to {metrics_path}")
        except Exception as e:
            logger.error(f"Error in LLM metrics extraction: {e}")
    else:
        # Rule-based fallback even without LLM flag
        try:
            from llm_agents.metrics_extractor import MetricsExtractor as _ME
            extractor = _ME()
            llm_metrics = extractor._rule_based_extract(
                linter_results=aggregated,
                security_findings=security_findings,
                cve_count=len(all_vulnerabilities),
                file_count=summary['files_analyzed'],
                total_loc=total_loc,
                file_details=details,
            )
            metrics_path = os.path.join(output_path, "metrics.json")
            with open(metrics_path, 'w', encoding='utf-8') as f:
                json.dump(llm_metrics, f, indent=2)
        except Exception as e:
            logger.warning(f"Rule-based metrics fallback also failed: {e}")

    # ── Phase 6b: Git Commit History Extraction ──────────────────────────────
    git_data = {}
    if GIT_ANALYZER_AVAILABLE:
        try:
            logger.info("Phase 6b: Extracting git commit history...")
            total_issues_count = llm_metrics.get('total_issues', aggregated.get('total_issues', 0))
            git_data = analyze_repo_git(
                repo_path=input_path,
                total_issues=total_issues_count,
                timeline_days=30,
            )
            # Save git timeline
            timeline_path = os.path.join(output_path, "git_timeline.json")
            with open(timeline_path, 'w', encoding='utf-8') as f:
                json.dump(git_data['timeline'], f, indent=2)
            logger.info(
                f"Git timeline saved: {git_data['total_commits']} commits, "
                f"has_git={git_data['has_git']}"
            )
        except Exception as e:
            logger.error(f"Error in git analysis: {e}")

    return {
        "summary": summary,
        "details": details,
        "security": security_report,
        "linter_results": aggregated,
        "comprehensive_report": comprehensive_report,
        "cve_results": all_vulnerabilities,
        "dependencies": [dep.to_dict() for dep in dependencies],
        "security_findings": security_findings,
        "security_report": security_report_data,
        "fix_suggestions": fix_suggestions,
        "dashboard_data": dashboard_data,
        "llm_metrics": llm_metrics,
        "git_data": git_data,
    }


def _generate_security_report(aggregated_results: Dict[str, Any]) -> str:
    """Generate human-readable security report"""
    issues = aggregated_results.get('issues', [])

    if not issues:
        return "✅ No major security or quality issues found!"

    high_severity = [i for i in issues if i.get(
        'severity') in ['high', 'critical', 'error']]

    report = f"⚠️ Found {len(issues)} potential issues:\n\n"
    report += f"🔴 High severity: {len(high_severity)}\n"
    report += f"🟡 Total issues: {len(issues)}\n\n"

    if high_severity:
        report += "**Top Critical Issues:**\n\n"
        for issue in high_severity[:5]:
            tool = issue.get('tool', 'unknown')
            file = issue.get('file', 'N/A')
            line = issue.get('line', 'N/A')
            message = issue.get('issue_text') or issue.get(
                'message', 'Unknown issue')

            report += f"🔍 [{tool.upper()}] {message}\n"
            report += f"   📁 {file}:{line}\n\n"

        if len(high_severity) > 5:
            remaining = len(high_severity) - 5
            report += f"...and {remaining} more high-severity issues.\n"

    return report
