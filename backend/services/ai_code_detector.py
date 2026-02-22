"""
AI Code Detector

Detects AI-generated code by analyzing patterns, comments, and code style.
"""

import re
import logging
from typing import Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class AICodeDetector:
    """Detects AI-generated code in source files"""
    
    # Common AI code patterns
    AI_PATTERNS = [
        # Common AI comments
        r'#\s*(AI|ChatGPT|Copilot|Generated|Auto-generated)',
        r'//\s*(AI|ChatGPT|Copilot|Generated|Auto-generated)',
        r'/\*.*?(AI|ChatGPT|Copilot|Generated|Auto-generated).*?\*/',
        
        # Common AI function naming patterns
        r'def\s+helper_\w+\(',
        r'function\s+helper\w+\(',
        
        # Overly generic variable names (AI tendency)
        r'\b(temp|tmp|data|result|output|input|value)\d*\b',
        
        # Perfect formatting (unusual in human code)
        r'^\s{4}',  # Consistent 4-space indentation
    ]
    
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.AI_PATTERNS]
    
    def detect_in_file(self, file_path: str) -> Dict[str, Any]:
        """
        Detect AI-generated code in a single file
        
        Args:
            file_path: Path to source file
            
        Returns:
            Detection results with confidence score
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            total_lines = len(content.split('\n'))
            if total_lines == 0:
                return {'ai_score': 0, 'confidence': 0, 'total_lines': 0}
            
            # Count pattern matches
            matches = 0
            for pattern in self.patterns:
                matches += len(pattern.findall(content))
            
            # Calculate AI score (0-100)
            # More matches = higher AI probability
            ai_score = min(100, (matches / total_lines) * 100)
            
            # Confidence based on number of different patterns matched
            patterns_matched = sum(1 for p in self.patterns if p.search(content))
            confidence = min(100, (patterns_matched / len(self.patterns)) * 100)
            
            return {
                'ai_score': round(ai_score, 2),
                'confidence': round(confidence, 2),
                'total_lines': total_lines,
                'matches': matches
            }
            
        except Exception as e:
            logger.error(f"Error detecting AI code in {file_path}: {e}")
            return {'ai_score': 0, 'confidence': 0, 'total_lines': 0}
    
    def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """
        Analyze entire project for AI-generated code
        
        Args:
            project_path: Path to project directory
            
        Returns:
            Overall AI code percentage and details
        """
        project_dir = Path(project_path)
        if not project_dir.exists():
            logger.warning(f"Project path does not exist: {project_path}")
            return {'ai_percentage': 0, 'total_files': 0}
        
        # Supported file extensions
        extensions = ['.py', '.js', '.java', '.cpp', '.c', '.go', '.rs', '.ts', '.jsx', '.tsx']
        
        total_lines = 0
        ai_lines = 0
        files_analyzed = 0
        
        # Analyze all source files
        for ext in extensions:
            for file_path in project_dir.rglob(f'*{ext}'):
                if self._should_skip(file_path):
                    continue
                
                result = self.detect_in_file(str(file_path))
                files_analyzed += 1
                total_lines += result['total_lines']
                
                # Estimate AI lines based on score
                ai_lines += (result['ai_score'] / 100) * result['total_lines']
        
        # Calculate overall percentage
        if total_lines == 0:
            ai_percentage = 0
        else:
            ai_percentage = (ai_lines / total_lines) * 100
        
        return {
            'ai_percentage': round(ai_percentage, 1),
            'total_files': files_analyzed,
            'total_lines': total_lines,
            'estimated_ai_lines': round(ai_lines)
        }
    
    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        skip_dirs = {'node_modules', 'venv', '__pycache__', '.git', 'dist', 'build'}
        return any(part in skip_dirs for part in file_path.parts)


# Singleton instance
_ai_detector = None


def get_ai_detector() -> AICodeDetector:
    """Get or create AI detector singleton"""
    global _ai_detector
    if _ai_detector is None:
        _ai_detector = AICodeDetector()
    return _ai_detector
