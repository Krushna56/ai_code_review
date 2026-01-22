"""
AST Parser and Code Metrics Extraction

This module provides functionality to parse Python code using AST,
extract various code metrics, and analyze code structure.
"""

import ast
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CodeMetrics:
    """Container for code metrics"""

    def __init__(self):
        self.loc = 0  # Lines of Code
        self.sloc = 0  # Source Lines of Code (excluding comments/blanks)
        self.comments = 0
        self.blank_lines = 0
        self.functions = 0
        self.classes = 0
        self.complexity = 0  # Cyclomatic Complexity
        self.wmc = 0  # Weighted Methods per Class
        self.dit = 0  # Depth of Inheritance Tree
        self.lcom = 0  # Lack of Cohesion of Methods
        self.fan_in = 0
        self.fan_out = 0
        self.imports = []
        self.function_names = []
        self.class_names = []


class ASTParser:
    """Parse Python code and extract metrics"""

    def __init__(self):
        self.metrics = CodeMetrics()
        self.tree = None

    def parse_file(self, file_path: str) -> Optional[CodeMetrics]:
        """Parse a Python file and extract metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.parse_code(code, file_path)
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            return None

    def parse_code(self, code: str, file_path: str = "<string>") -> CodeMetrics:
        """Parse Python code string and extract metrics"""
        self.metrics = CodeMetrics()

        try:
            self.tree = ast.parse(code)

            # Calculate basic metrics
            self._calculate_loc(code)
            self._extract_structure()
            self._calculate_complexity()
            self._calculate_oo_metrics()

            return self.metrics

        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return self.metrics
        except Exception as e:
            logger.error(f"Error parsing code in {file_path}: {e}")
            return self.metrics

    def _calculate_loc(self, code: str):
        """Calculate lines of code metrics"""
        lines = code.split('\n')
        self.metrics.loc = len(lines)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                self.metrics.blank_lines += 1
            elif stripped.startswith('#'):
                self.metrics.comments += 1
            else:
                self.metrics.sloc += 1

    def _extract_structure(self):
        """Extract structural information from AST"""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self.metrics.functions += 1
                self.metrics.function_names.append(node.name)
            elif isinstance(node, ast.ClassDef):
                self.metrics.classes += 1
                self.metrics.class_names.append(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self._extract_imports(node)

    def _extract_imports(self, node):
        """Extract import information"""
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.metrics.imports.append(alias.name)
                self.metrics.fan_out += 1
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                self.metrics.imports.append(node.module)
                self.metrics.fan_out += 1

    def _calculate_complexity(self):
        """Calculate cyclomatic complexity"""
        complexity = 0

        for node in ast.walk(self.tree):
            # Each decision point adds to complexity
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        self.metrics.complexity = complexity

    def _calculate_oo_metrics(self):
        """Calculate object-oriented metrics"""
        classes = [node for node in ast.walk(
            self.tree) if isinstance(node, ast.ClassDef)]

        for cls in classes:
            # Calculate WMC (Weighted Methods per Class)
            methods = [n for n in cls.body if isinstance(n, ast.FunctionDef)]
            self.metrics.wmc += len(methods)

            # Calculate DIT (Depth of Inheritance Tree)
            if cls.bases:
                self.metrics.dit = max(self.metrics.dit, len(cls.bases))

            # Calculate LCOM (simplified version)
            if methods:
                self.metrics.lcom += self._calculate_lcom(cls, methods)

    def _calculate_lcom(self, cls: ast.ClassDef, methods: List[ast.FunctionDef]) -> int:
        """
        Calculate Lack of Cohesion of Methods (simplified)
        Higher values indicate lower cohesion
        """
        if len(methods) <= 1:
            return 0

        # Get instance variables used by each method
        method_vars = []
        for method in methods:
            vars_used = set()
            for node in ast.walk(method):
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == 'self':
                        vars_used.add(node.attr)
            method_vars.append(vars_used)

        # Count pairs of methods with no shared variables
        no_shared = 0
        shared = 0

        for i in range(len(method_vars)):
            for j in range(i + 1, len(method_vars)):
                if method_vars[i] & method_vars[j]:
                    shared += 1
                else:
                    no_shared += 1

        return max(0, no_shared - shared)

    def get_metrics_dict(self) -> Dict[str, Any]:
        """Return metrics as dictionary"""
        return {
            'loc': self.metrics.loc,
            'sloc': self.metrics.sloc,
            'comments': self.metrics.comments,
            'blank_lines': self.metrics.blank_lines,
            'functions': self.metrics.functions,
            'classes': self.metrics.classes,
            'complexity': self.metrics.complexity,
            'wmc': self.metrics.wmc,
            'dit': self.metrics.dit,
            'lcom': self.metrics.lcom,
            'fan_in': self.metrics.fan_in,
            'fan_out': self.metrics.fan_out,
            'imports': self.metrics.imports,
            'function_names': self.metrics.function_names,
            'class_names': self.metrics.class_names
        }


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze a Python file and return metrics

    Args:
        file_path: Path to Python file

    Returns:
        Dictionary containing code metrics
    """
    parser = ASTParser()
    metrics = parser.parse_file(file_path)

    if metrics:
        return parser.get_metrics_dict()
    else:
        return {}


def analyze_directory(directory: str, extensions: List[str] = ['.py']) -> Dict[str, Dict[str, Any]]:
    """
    Analyze all files in a directory

    Args:
        directory: Path to directory
        extensions: List of file extensions to analyze

    Returns:
        Dictionary mapping file paths to their metrics
    """
    results = {}
    dir_path = Path(directory)

    for ext in extensions:
        for file_path in dir_path.rglob(f'*{ext}'):
            try:
                metrics = analyze_file(str(file_path))
                if metrics:
                    results[str(file_path)] = metrics
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")

    return results
