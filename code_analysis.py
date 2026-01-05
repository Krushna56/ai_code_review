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
from pathlib import Path
from typing import Dict, List, Any, Optional
from autopep8 import fix_code
import difflib

import config
from static_analysis.ast_parser import ASTParser
from static_analysis.multi_linter import MultiLinter

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
            result['formatted_code'] = highlight_code_diff(original_code, formatted_code)
            
            # 3. LLM Analysis (if enabled and code is not too long)
            if config.ENABLE_LLM_AGENTS and len(original_code) < 5000:
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
        insights = {}
        
        context = {
            'metrics': metrics,
            'static_analysis': static_issues
        }
        
        try:
            # Security review
            security_result = self.security_agent.analyze(code, context)
            insights['security'] = security_result
            
            # Refactoring suggestions
            refactor_result = self.refactor_agent.analyze(code, context)
            insights['refactoring'] = refactor_result
            
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            insights['error'] = str(e)
        
        return insights


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
        "bugs_fixed": 0,
        "security_issues": 0,
        "code_quality_issues": 0,
        "files_updated": 0
    }
    details = {}
    
    analyzer = CodeAnalyzer()
    
    # Analyze Python files
    for root, _, files in os.walk(input_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, input_path)
                
                logger.info(f"Analyzing {rel_path}")
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        original_code = f.read()
                    
                    # Get AST metrics
                    metrics = analyzer.ast_parser.parse_code(original_code, file_path)
                    metrics_dict = analyzer.ast_parser.get_metrics_dict() if metrics else {}
                    
                    # Format code
                    formatted_code = fix_code(original_code)
                    
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
                    summary["bugs_fixed"] += 1
                    summary["files_updated"] += 1
                    
                except Exception as e:
                    logger.error(f"Error processing {rel_path}: {e}")
    
    # Run multi-linter analysis
    logger.info("Running static analysis tools...")
    linter_results = analyzer.multi_linter.run_all(input_path)
    aggregated = analyzer.multi_linter.get_aggregated_results()
    
    summary["security_issues"] = aggregated.get('by_severity', {}).get('high', 0)
    summary["code_quality_issues"] = aggregated.get('total_issues', 0)
    
    # Save linter results
    linter_output_path = os.path.join(output_path, "linter_results.json")
    with open(linter_output_path, "w", encoding="utf-8") as f:
        json.dump({
            'summary': aggregated,
            'details': {name: res.to_dict() for name, res in linter_results.items()}
        }, f, indent=2)
    
    # Generate comprehensive report with meta-reasoner
    comprehensive_report = None
    if META_REASONER_AVAILABLE:
        try:
            logger.info("Generating comprehensive report with meta-reasoner...")
            comprehensive_report = generate_comprehensive_report(
                linter_results=aggregated,
                llm_insights=None,  # Add LLM insights if available
                summary=summary
            )
            
            # Save comprehensive report
            report_path = os.path.join(output_path, "comprehensive_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(comprehensive_report, f, indent=2)
            
            logger.info(f"Comprehensive report saved to {report_path}")
        except Exception as e:
            logger.error(f"Error generating comprehensive report: {e}")
    
    # Generate security report
    security_report = _generate_security_report(aggregated)
    
    return {
        "summary": summary,
        "details": details,
        "security": security_report,
        "linter_results": aggregated,
        "comprehensive_report": comprehensive_report
    }


def _generate_security_report(aggregated_results: Dict[str, Any]) -> str:
    """Generate human-readable security report"""
    issues = aggregated_results.get('issues', [])
    
    if not issues:
        return "✅ No major security or quality issues found!"
    
    high_severity = [i for i in issues if i.get('severity') in ['high', 'critical', 'error']]
    
    report = f"⚠️ Found {len(issues)} potential issues:\n\n"
    report += f"🔴 High severity: {len(high_severity)}\n"
    report += f"🟡 Total issues: {len(issues)}\n\n"
    
    if high_severity:
        report += "**Top Critical Issues:**\n\n"
        for issue in high_severity[:5]:
            tool = issue.get('tool', 'unknown')
            file = issue.get('file', 'N/A')
            line = issue.get('line', 'N/A')
            message = issue.get('issue_text') or issue.get('message', 'Unknown issue')
            
            report += f"🔍 [{tool.upper()}] {message}\n"
            report += f"   📁 {file}:{line}\n\n"
        
        if len(high_severity) > 5:
            report += f"...and {len(high_severity) - 5} more high-severity issues.\n"
    
    return report
