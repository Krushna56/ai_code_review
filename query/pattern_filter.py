"""
Pattern Filters

Regex and AST-based pattern matching for security vulnerabilities.
"""

import re
import ast
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityPatternFilter:
    """Detect security patterns using regex and AST analysis"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r'["\'].*\+.*["\'].*execute',  # String concatenation in SQL
        r'execute\s*\(\s*["\'].*(SELECT|INSERT|UPDATE|DELETE).*\+',
        r'executeQuery\s*\([^)]*\+',  # Java JDBC
        r'cursor\.execute\s*\([^)]*%',  # Python string formatting in SQL
        r'Statement\.executeQuery\([^)]*\+',
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r'innerHTML\s*=',
        r'document\.write\s*\(',
        r'eval\s*\(',
        r'dangerouslySetInnerHTML',
        r'\.html\s*\([^)]*\+',  # jQuery .html() with concatenation
    ]
    
    # Insecure crypto patterns
    CRYPTO_PATTERNS = [
        r'MD5|md5',
        r'SHA1|sha1(?!224|256|384|512)',  # SHA1 but not SHA2 family
        r'DES(?!ede)',  # DES but not 3DES
        r'RC4|rc4',
        r'ECB',  # ECB mode
    ]
    
    # SSL/TLS issues
    SSL_PATTERNS = [
        r'setSSL\s*\(\s*false',
        r'verify\s*=\s*False',
        r'VERIFY_NONE',
        r'TrustAllCertificates',
        r'checkServerTrusted.*\{\s*\}',  # Empty implementation
    ]
    
    # Deserialization issues
    DESERIALIZATION_PATTERNS = [
        r'pickle\.loads',
        r'yaml\.load\s*\(',  # Should use safe_load
        r'ObjectInputStream',
        r'unserialize\s*\(',  # PHP
    ]
    
    # Path traversal
    PATH_TRAVERSAL_PATTERNS = [
        r'open\s*\([^)]*\+',  # File open with concatenation
        r'File\s*\([^)]*\+',  # Java File with concatenation
        r'\.\./|\.\.\\'  # Directory traversal attempts
    ]
    
    # Command injection
    COMMAND_INJECTION_PATTERNS = [
        r'exec\s*\(',
        r'eval\s*\(',
        r'os\.system\s*\(',
        r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
        r'Runtime\.getRuntime\(\)\.exec',
    ]
    
    def __init__(self):
        """Initialize pattern filter"""
        self.pattern_categories = {
            'sql_injection': self.SQL_INJECTION_PATTERNS,
            'xss': self.XSS_PATTERNS,
            'weak_crypto': self.CRYPTO_PATTERNS,
            'ssl_issues': self.SSL_PATTERNS,
            'deserialization': self.DESERIALIZATION_PATTERNS,
            'path_traversal': self.PATH_TRAVERSAL_PATTERNS,
            'command_injection': self.COMMAND_INJECTION_PATTERNS,
        }
        logger.info("Initialized SecurityPatternFilter")
    
    def scan_code(self, code: str, file_path: str = None, 
                  language: str = None) -> List[Dict[str, Any]]:
        """
        Scan code for security patterns
        
        Args:
            code: Source code to scan
            file_path: Optional file path
            language: Programming language
            
        Returns:
            List of pattern matches
        """
        matches = []
        
        # Regex-based scanning
        regex_matches = self._scan_with_regex(code, file_path)
        matches.extend(regex_matches)
        
        # AST-based scanning for Python
        if language == 'python' or (file_path and file_path.endswith('.py')):
            ast_matches = self._scan_python_ast(code, file_path)
            matches.extend(ast_matches)
        
        return matches
    
    def _scan_with_regex(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan code using regex patterns"""
        matches = []
        lines = code.split('\n')
        
        for category, patterns in self.pattern_categories.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({
                            'type': 'pattern_match',
                            'category': category,
                            'pattern': pattern,
                            'line': line_num,
                            'file': file_path,
                            'context': line.strip(),
                            'severity': self._get_severity(category),
                            'detector': 'regex'
                        })
        
        return matches
    
    def _scan_python_ast(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan Python code using AST analysis"""
        matches = []
        
        try:
            tree = ast.parse(code)
            
            # Find dangerous function calls
            for node in ast.walk(tree):
                # SQL injection via string formatting
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        method_name = node.func.attr
                        
                        # Check for execute() with % formatting
                        if method_name == 'execute' and node.args:
                            if self._has_string_formatting(node.args[0]):
                                matches.append({
                                    'type': 'ast_pattern',
                                    'category': 'sql_injection',
                                    'line': node.lineno,
                                    'file': file_path,
                                    'context': ast.unparse(node) if hasattr(ast, 'unparse') else 'execute(...)',
                                    'severity': 'critical',
                                    'detector': 'ast',
                                    'description': 'SQL query using string formatting'
                                })
                        
                        # Check for eval()
                        if method_name in ['eval', 'exec']:
                            matches.append({
                                'type': 'ast_pattern',
                                'category': 'command_injection',
                                'line': node.lineno,
                                'file': file_path,
                                'context': ast.unparse(node) if hasattr(ast, 'unparse') else f'{method_name}(...)',
                                'severity': 'critical',
                                'detector': 'ast',
                                'description': f'Use of {method_name}()'
                            })
                
                # Check for pickle usage
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if 'pickle' in alias.name:
                            matches.append({
                                'type': 'ast_pattern',
                                'category': 'deserialization',
                                'line': node.lineno,
                                'file': file_path,
                                'context': f'import {alias.name}',
                                'severity': 'high',
                                'detector': 'ast',
                                'description': 'Pickle usage detected (deserialization risk)'
                            })
        
        except SyntaxError as e:
            logger.warning(f"Failed to parse Python code: {e}")
        
        return matches
    
    def _has_string_formatting(self, node) -> bool:
        """Check if node uses string formatting"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        if isinstance(node, ast.JoinedStr):  # f-strings
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
                return True
        return False
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for pattern category"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'path_traversal': 'high',
            'xss': 'high',
            'deserialization': 'high',
            'ssl_issues': 'high',
            'weak_crypto': 'medium',
        }
        return severity_map.get(category, 'medium')
    
    def filter_by_category(self, category: str) -> List[str]:
        """Get regex patterns for a specific category"""
        return self.pattern_categories.get(category, [])
    
    def get_all_categories(self) -> List[str]:
        """Get list of all pattern categories"""
        return list(self.pattern_categories.keys())


def scan_for_patterns(code: str, file_path: str = None, 
                     language: str = None) -> List[Dict[str, Any]]:
    """
    Convenience function to scan code for security patterns
    
    Args:
        code: Source code
        file_path: Optional file path
        language: Programming language
        
    Returns:
        List of pattern matches
    """
    scanner = SecurityPatternFilter()
    return scanner.scan_code(code, file_path, language)
