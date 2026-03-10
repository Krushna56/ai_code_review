"""
Modular code analysis pipeline architecture.

Separates the 6-phase analysis into independent, composable components
for better maintainability, testability, and extensibility.

Phases:
1. Static Analysis - AST parsing, linting
2. Semantic Embeddings - Vector embeddings, semantic search
3. LLM Intelligence - Security & refactoring recommendations
4. CVE Detection - Dependency and vulnerability scanning
5. Security Reporting - Unified findings aggregation
6. Dashboard Export - Visualization-ready data
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AnalysisPhaseResult:
    """Result of a single analysis phase"""
    phase_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def merge(self, other: 'AnalysisPhaseResult') -> 'AnalysisPhaseResult':
        """Merge two phase results"""
        if not self.success or not other.success:
            return AnalysisPhaseResult(
                phase_name=f"{self.phase_name}+{other.phase_name}",
                success=self.success and other.success,
                data={**self.data, **other.data},
                error=self.error or other.error
            )
        return AnalysisPhaseResult(
            phase_name=f"{self.phase_name}+{other.phase_name}",
            success=True,
            data={**self.data, **other.data}
        )


class AnalysisPhase(ABC):
    """Base class for analysis phases"""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")

    @abstractmethod
    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """
        Execute the analysis phase.

        Args:
            codebase_data: Data from previous phases

        Returns:
            AnalysisPhaseResult with phase output
        """
        pass

    def validate_input(self, codebase_data: Dict[str, Any], required_keys: List[str]) -> bool:
        """Validate that required data is present"""
        missing_keys = [key for key in required_keys if key not in codebase_data]
        if missing_keys:
            self.logger.warning(f"Missing required data: {missing_keys}")
            return False
        return True


class StaticAnalysisPhase(AnalysisPhase):
    """Phase 1: Static Analysis (AST parsing, linting)"""

    def __init__(self):
        super().__init__("StaticAnalysis")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Run static analysis on codebase"""
        import time
        start = time.time()

        try:
            if not self.validate_input(codebase_data, ['files', 'code_paths']):
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=False,
                    error="Missing required input data"
                )

            # Import here to avoid circular dependencies
            from static_analysis.multi_linter import MultiLinter
            from static_analysis.ast_parser import ASTParser

            linter = MultiLinter()
            ast_parser = ASTParser()

            # Run linting
            lint_issues = []
            for file_path in codebase_data.get('code_paths', []):
                try:
                    issues = linter.lint_file(file_path)
                    lint_issues.extend(issues)
                except Exception as e:
                    self.logger.warning(f"Linting failed for {file_path}: {e}")

            # Run AST analysis
            ast_metrics = {}
            for file_path in codebase_data.get('code_paths', []):
                try:
                    with open(file_path, 'r') as f:
                        code = f.read()
                    metrics = ast_parser.analyze(code)
                    ast_metrics[file_path] = metrics
                except Exception as e:
                    self.logger.warning(f"AST analysis failed for {file_path}: {e}")

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data={
                    'lint_issues': lint_issues,
                    'ast_metrics': ast_metrics,
                    'total_issues': len(lint_issues)
                },
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class EmbeddingPhase(AnalysisPhase):
    """Phase 2: Semantic Embeddings (vector embeddings, semantic search)"""

    def __init__(self):
        super().__init__("Embeddings")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Generate code embeddings"""
        import time
        start = time.time()

        try:
            if not self.validate_input(codebase_data, ['files']):
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=False,
                    error="Missing required input data"
                )

            import config
            if not config.ENABLE_SEMANTIC_SEARCH:
                self.logger.info("Embeddings disabled in config")
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=True,
                    data={'embeddings': [], 'chunks': 0}
                )

            from embeddings.code_embedder import CodeEmbedder

            embedder = CodeEmbedder()
            all_embeddings = []

            # Embed all files
            for file_path, file_content in codebase_data['files'].items():
                try:
                    embeddings = embedder.embed_code_chunked(file_content)
                    all_embeddings.extend(embeddings)
                    self.logger.debug(f"Embedded {len(embeddings)} chunks from {file_path}")
                except Exception as e:
                    self.logger.warning(f"Embedding failed for {file_path}: {e}")

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data={
                    'embeddings': all_embeddings,
                    'chunks': len(all_embeddings),
                    'embedding_model': embedder.provider
                },
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"Embedding phase failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class LLMIntelligencePhase(AnalysisPhase):
    """Phase 3: LLM Intelligence (security & refactoring recommendations)"""

    def __init__(self):
        super().__init__("LLMIntelligence")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Run LLM analysis"""
        import time
        import config
        start = time.time()

        try:
            if not config.ENABLE_LLM_AGENTS:
                self.logger.info("LLM agents disabled in config")
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=True,
                    data={'security_issues': [], 'refactoring_suggestions': []}
                )

            from llm_agents.security_reviewer import SecurityReviewer
            from llm_agents.refactor_agent import RefactorAgent
            from utils.parallel_executor import run_parallel_lm_agents

            if not self.validate_input(codebase_data, ['files']):
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=False,
                    error="Missing required input data"
                )

            security_agent = SecurityReviewer()
            refactor_agent = RefactorAgent()

            all_security = []
            all_refactoring = []

            # Analyze each file with LLM agents in parallel
            for file_path, file_content in codebase_data['files'].items():
                try:
                    context = {
                        'file_path': file_path,
                        'lint_issues': codebase_data.get('lint_issues', []),
                        'ast_metrics': codebase_data.get('ast_metrics', {}).get(file_path)
                    }

                    security_result, refactor_result = run_parallel_lm_agents(
                        code=file_content,
                        context=context,
                        security_agent=security_agent,
                        refactor_agent=refactor_agent
                    )

                    all_security.extend(security_result.get('issues', []))
                    all_refactoring.extend(refactor_result.get('suggestions', []))

                except Exception as e:
                    self.logger.warning(f"LLM analysis failed for {file_path}: {e}")

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data={
                    'security_issues': all_security,
                    'refactoring_suggestions': all_refactoring,
                    'total_security_issues': len(all_security),
                    'total_suggestions': len(all_refactoring)
                },
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"LLM intelligence phase failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class CVEDetectionPhase(AnalysisPhase):
    """Phase 4: CVE Detection (dependency scanning)"""

    def __init__(self):
        super().__init__("CVEDetection")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Detect CVEs in dependencies"""
        import time
        import config
        start = time.time()

        try:
            if not config.ENABLE_CVE_DETECTION:
                self.logger.info("CVE detection disabled in config")
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=True,
                    data={'cve_findings': [], 'dependencies': []}
                )

            from security.cve_tracker import CVETracker
            from security.dependency_analyzer import DependencyAnalyzer

            if not self.validate_input(codebase_data, ['files']):
                return AnalysisPhaseResult(
                    phase_name=self.name,
                    success=False,
                    error="Missing required input data"
                )

            cve_tracker = CVETracker()
            dep_analyzer = DependencyAnalyzer()

            # Analyze dependencies
            dependencies = dep_analyzer.extract_dependencies(codebase_data['files'])

            # Query CVE database
            cve_findings = []
            for dep_file, deps in dependencies.items():
                for dep in deps:
                    try:
                        cves = cve_tracker.query(dep['name'], dep.get('version'))
                        cve_findings.extend(cves)
                    except Exception as e:
                        self.logger.warning(f"CVE lookup failed for {dep['name']}: {e}")

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data={
                    'cve_findings': cve_findings,
                    'dependencies': list(dependencies.keys()),
                    'total_cves': len(cve_findings)
                },
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"CVE detection phase failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class ReportingPhase(AnalysisPhase):
    """Phase 5: Security Reporting (unified findings aggregation)"""

    def __init__(self):
        super().__init__("Reporting")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Generate security report"""
        import time
        start = time.time()

        try:
            from reporting.security_report_generator import SecurityReportGenerator

            # Aggregate all findings
            all_findings = []
            all_findings.extend(codebase_data.get('lint_issues', []))
            all_findings.extend(codebase_data.get('security_issues', []))
            all_findings.extend(codebase_data.get('cve_findings', []))

            # Generate reports
            report_gen = SecurityReportGenerator()
            json_report = report_gen.generate_json_report(
                findings=all_findings,
                metadata=codebase_data.get('metadata', {})
            )
            markdown_report = report_gen.generate_markdown_report(
                findings=all_findings,
                metadata=codebase_data.get('metadata', {})
            )

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data={
                    'json_report': json_report,
                    'markdown_report': markdown_report,
                    'total_findings': len(all_findings)
                },
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"Reporting phase failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class DashboardExportPhase(AnalysisPhase):
    """Phase 6: Dashboard Export (visualization-ready data)"""

    def __init__(self):
        super().__init__("DashboardExport")

    def execute(self, codebase_data: Dict[str, Any]) -> AnalysisPhaseResult:
        """Export data for dashboard"""
        import time
        start = time.time()

        try:
            from reporting.dashboard_exporter import DashboardExporter

            exporter = DashboardExporter()
            dashboard_data = exporter.export(codebase_data)

            duration = time.time() - start

            return AnalysisPhaseResult(
                phase_name=self.name,
                success=True,
                data=dashboard_data,
                duration_seconds=duration
            )

        except Exception as e:
            self.logger.error(f"Dashboard export phase failed: {e}", exc_info=True)
            return AnalysisPhaseResult(
                phase_name=self.name,
                success=False,
                error=str(e)
            )


class AnalysisPipeline:
    """Orchestrates the 6-phase analysis pipeline"""

    def __init__(self):
        self.phases = [
            StaticAnalysisPhase(),
            EmbeddingPhase(),
            LLMIntelligencePhase(),
            CVEDetectionPhase(),
            ReportingPhase(),
            DashboardExportPhase()
        ]
        self.logger = logging.getLogger(__name__)

    def execute(self, codebase_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the complete analysis pipeline.

        Args:
            codebase_data: Initial codebase data (files, metadata, etc.)

        Returns:
            Complete analysis results
        """
        results = {}
        accumulated_data = dict(codebase_data)

        self.logger.info(f"Starting {len(self.phases)}-phase analysis pipeline")

        for phase in self.phases:
            self.logger.info(f"Executing {phase.name}...")

            try:
                phase_result = phase.execute(accumulated_data)
                results[phase.name] = phase_result

                if phase_result.success:
                    accumulated_data.update(phase_result.data)
                    self.logger.info(
                        f"{phase.name} completed in {phase_result.duration_seconds:.2f}s"
                    )
                else:
                    self.logger.error(f"{phase.name} failed: {phase_result.error}")
                    # Continue pipeline even if phase fails

            except Exception as e:
                self.logger.error(f"Unexpected error in {phase.name}: {e}", exc_info=True)
                results[phase.name] = AnalysisPhaseResult(
                    phase_name=phase.name,
                    success=False,
                    error=str(e)
                )

        self.logger.info("Analysis pipeline complete")
        return {
            'phases': results,
            'final_data': accumulated_data
        }
