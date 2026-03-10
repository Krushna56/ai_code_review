"""
Modular code analysis pipeline.

The analysis process is decomposed into 6 independent phases:
1. Static Analysis - AST parsing, linting (Bandit, Semgrep, Ruff)
2. Semantic Embeddings - Code embeddings for semantic search
3. LLM Intelligence - AI-powered security & refactoring recommendations
4. CVE Detection - Dependency vulnerability scanning
5. Security Reporting - Unified findings aggregation
6. Dashboard Export - Visualization-ready data export

Each phase is independently testable and replaceable.
"""

from .pipeline import (
    AnalysisPipeline,
    AnalysisPhase,
    AnalysisPhaseResult,
    StaticAnalysisPhase,
    EmbeddingPhase,
    LLMIntelligencePhase,
    CVEDetectionPhase,
    ReportingPhase,
    DashboardExportPhase
)

__all__ = [
    'AnalysisPipeline',
    'AnalysisPhase',
    'AnalysisPhaseResult',
    'StaticAnalysisPhase',
    'EmbeddingPhase',
    'LLMIntelligencePhase',
    'CVEDetectionPhase',
    'ReportingPhase',
    'DashboardExportPhase'
]
