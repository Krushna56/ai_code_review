"""
Universal Code Chunker

Routes to appropriate parser based on file type and generates
code chunks with rich metadata for indexing.
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

import config

logger = logging.getLogger(__name__)

# Import parsers
try:
    from .java_parser import JavaParser
    JAVA_AVAILABLE = True
except ImportError:
    JAVA_AVAILABLE = False
    logger.warning("Java parser not available")

try:
    from static_analysis.ast_parser import ASTParser
    PYTHON_AVAILABLE = True
except ImportError:
    PYTHON_AVAILABLE = False
    logger.warning("Python AST parser not available")


class CodeChunker:
    """Universal code chunker that routes to language-specific parsers"""
    
    def __init__(self, chunk_strategy: str = None):
        """
        Initialize code chunker
        
        Args:
            chunk_strategy: 'function', 'class', or 'file' (from config if not provided)
        """
        self.chunk_strategy = chunk_strategy or config.CHUNK_STRATEGY
        self.max_chunk_size = config.MAX_CHUNK_SIZE
        
        # Initialize parsers
        self.java_parser = JavaParser() if JAVA_AVAILABLE else None
        self.python_parser = ASTParser() if PYTHON_AVAILABLE else None
        
        logger.info(f"Initialized CodeChunker with strategy: {self.chunk_strategy}")
    
    def chunk_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Chunk a code file based on its language
        
        Args:
            file_path: Path to source code file
            
        Returns:
            List of code chunks with metadata
        """
        file_path_obj = Path(file_path)
        extension = file_path_obj.suffix.lower()
        
        try:
            if extension == '.java':
                return self._chunk_java(file_path)
            elif extension == '.py':
                return self._chunk_python(file_path)
            elif extension in ['.js', '.jsx', '.ts', '.tsx']:
                return self._chunk_javascript(file_path)
            elif extension in ['.go']:
                return self._chunk_generic(file_path, 'go')
            elif extension in ['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp']:
                return self._chunk_generic(file_path, 'cpp')
            elif extension in ['.rb']:
                return self._chunk_generic(file_path, 'ruby')
            elif extension in ['.php']:
                return self._chunk_generic(file_path, 'php')
            else:
                logger.warning(f"Unsupported file type: {extension}")
                return []
                
        except Exception as e:
            logger.error(f"Error chunking {file_path}: {e}")
            return []
    
    def _chunk_java(self, file_path: str) -> List[Dict[str, Any]]:
        """Chunk Java file using tree-sitter"""
        if not self.java_parser:
            return self._chunk_generic(file_path, 'java')
        
        chunks = self.java_parser.parse_file(file_path)
        
        # Apply chunking strategy
        if self.chunk_strategy == 'function':
            # Return only methods/functions, exclude classes
            return [c for c in chunks if c['type'] in ['method', 'constructor']]
        elif self.chunk_strategy == 'class':
            # Return class-level chunks (includes methods within context)
            return chunks
        else:  # file
            # Combine all chunks into file-level
            return self._combine_to_file_level(chunks, file_path, 'java')
    
    def _chunk_python(self, file_path: str) -> List[Dict[str, Any]]:
        """Chunk Python file using AST parser"""
        if not self.python_parser:
            return self._chunk_generic(file_path, 'python')
        
        # Parse file
        metrics = self.python_parser.parse_file(file_path)
        
        if not metrics:
            return []
        
        # Convert AST metrics to chunk format
        chunks = []
        
        # Add file-level chunk with imports
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
            source_lines = source_code.split('\n')
        
        # Extract functions
        for func_name, func_metrics in metrics.get('functions', {}).items():
            chunks.append({
                'type': 'function',
                'name': func_name,
                'file': file_path,
                'language': 'python',
                'code': self._extract_function_code(source_lines, func_name),
                'start_line': func_metrics.get('start_line', 0),
                'end_line': func_metrics.get('end_line', 0),
                'metadata': {
                    'complexity': func_metrics.get('complexity', 0),
                    'lines_of_code': func_metrics.get('loc', 0),
                    'parameters': func_metrics.get('args', [])
                }
            })
        
        # Extract classes
        for class_name, class_metrics in metrics.get('classes', {}).items():
            # Class-level chunk
            chunks.append({
                'type': 'class',
                'name': class_name,
                'file': file_path,
                'language': 'python',
                'code': self._extract_class_code(source_lines, class_name),
                'start_line': class_metrics.get('start_line', 0),
                'end_line': class_metrics.get('end_line', 0),
                'metadata': {
                    'method_count': len(class_metrics.get('methods', {})),
                    'lines_of_code': class_metrics.get('loc', 0)
                }
            })
            
            # Methods within class
            for method_name, method_metrics in class_metrics.get('methods', {}).items():
                chunks.append({
                    'type': 'method',
                    'name': method_name,
                    'class': class_name,
                    'file': file_path,
                    'language': 'python',
                    'code': self._extract_function_code(source_lines, method_name),
                    'start_line': method_metrics.get('start_line', 0),
                    'end_line': method_metrics.get('end_line', 0),
                    'metadata': {
                        'complexity': method_metrics.get('complexity', 0),
                        'lines_of_code': method_metrics.get('loc', 0)
                    }
                })
        
        # Apply chunking strategy
        if self.chunk_strategy == 'function':
            return [c for c in chunks if c['type'] in ['function', 'method']]
        elif self.chunk_strategy == 'class':
            return chunks
        else:  # file
            return self._combine_to_file_level(chunks, file_path, 'python')
    
    def _chunk_javascript(self, file_path: str) -> List[Dict[str, Any]]:
        """Chunk JavaScript/TypeScript file (placeholder - can add tree-sitter later)"""
        return self._chunk_generic(file_path, 'javascript')
    
    def _chunk_generic(self, file_path: str, language: str) -> List[Dict[str, Any]]:
        """
        Generic chunker for languages without specific parser.
        Chunks by file or simple line-based splitting.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            source_lines = source_code.split('\n')
            total_lines = len(source_lines)
            
            # If file is small enough, return as single chunk
            if total_lines <= self.max_chunk_size:
                return [{
                    'type': 'file',
                    'name': Path(file_path).name,
                    'file': file_path,
                    'language': language,
                    'code': source_code,
                    'start_line': 1,
                    'end_line': total_lines,
                    'metadata': {
                        'lines_of_code': total_lines
                    }
                }]
            
            # Split into multiple chunks
            chunks = []
            for i in range(0, total_lines, self.max_chunk_size):
                end = min(i + self.max_chunk_size, total_lines)
                chunk_code = '\n'.join(source_lines[i:end])
                
                chunks.append({
                    'type': 'file_chunk',
                    'name': f"{Path(file_path).name}_chunk_{i // self.max_chunk_size}",
                    'file': file_path,
                    'language': language,
                    'code': chunk_code,
                    'start_line': i + 1,
                    'end_line': end,
                    'metadata': {
                        'lines_of_code': end - i,
                        'chunk_index': i // self.max_chunk_size
                    }
                })
            
            return chunks
            
        except Exception as e:
            logger.error(f"Error in generic chunker for {file_path}: {e}")
            return []
    
    def _combine_to_file_level(self, chunks: List[Dict[str, Any]], 
                               file_path: str, language: str) -> List[Dict[str, Any]]:
        """Combine all chunks into a single file-level chunk"""
        if not chunks:
            return []
        
        # Combine all code
        combined_code = '\n\n'.join([c['code'] for c in chunks])
        
        return [{
            'type': 'file',
            'name': Path(file_path).name,
            'file': file_path,
            'language': language,
            'code': combined_code,
            'start_line': min(c['start_line'] for c in chunks),
            'end_line': max(c['end_line'] for c in chunks),
            'metadata': {
                'chunk_count': len(chunks),
                'languages': language,
                'total_functions': len([c for c in chunks if c['type'] in ['function', 'method']]),
                'total_classes': len([c for c in chunks if c['type'] == 'class'])
            }
        }]
    
    def _extract_function_code(self, source_lines: List[str], func_name: str) -> str:
        """Extract function code from source lines (basic implementation)"""
        # This is a simple implementation - can be enhanced
        for i, line in enumerate(source_lines):
            if f'def {func_name}' in line:
                # Find function end (simple indentation-based)
                func_lines = [line]
                indent = len(line) - len(line.lstrip())
                
                for j in range(i + 1, len(source_lines)):
                    next_line = source_lines[j]
                    if next_line.strip() and not next_line.startswith(' ' * (indent + 1)):
                        break
                    func_lines.append(next_line)
                
                return '\n'.join(func_lines)
        
        return f"# Function {func_name} not found"
    
    def _extract_class_code(self, source_lines: List[str], class_name: str) -> str:
        """Extract class code from source lines (basic implementation)"""
        for i, line in enumerate(source_lines):
            if f'class {class_name}' in line:
                # Find class end
                class_lines = [line]
                indent = len(line) - len(line.lstrip())
                
                for j in range(i + 1, len(source_lines)):
                    next_line = source_lines[j]
                    if next_line.strip() and not next_line.startswith(' ' * (indent + 1)):
                        break
                    class_lines.append(next_line)
                
                return '\n'.join(class_lines)
        
        return f"# Class {class_name} not found"
    
    def get_supported_extensions(self) -> List[str]:
        """Get list of supported file extensions"""
        return ['.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.go', '.cpp', '.c', '.h', '.rb', '.php']


def chunk_file(file_path: str, strategy: str = None) -> List[Dict[str, Any]]:
    """
    Convenience function to chunk a single file
    
    Args:
        file_path: Path to source file
        strategy: Optional chunking strategy override
        
    Returns:
        List of code chunks
    """
    chunker = CodeChunker(chunk_strategy=strategy)
    return chunker.chunk_file(file_path)
