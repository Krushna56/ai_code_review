"""
Java Code Parser using tree-sitter

Extracts methods, classes, and other code structures from Java source files.
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from tree_sitter_languages import get_language, get_parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("tree-sitter-languages not available")

logger = logging.getLogger(__name__)


class JavaParser:
    """Parse Java code into structured chunks using tree-sitter"""

    def __init__(self):
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter-languages required. Install with: pip install tree-sitter-languages")

        self.language = get_language('java')
        self.parser = get_parser('java')
        logger.info("Initialized Java parser with tree-sitter")

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Java file and extract code chunks

        Args:
            file_path: Path to Java source file

        Returns:
            List of code chunks with metadata
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            return self.parse_source(source_code, file_path)

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return []

    def parse_source(self, source_code: str, file_path: str = None) -> List[Dict[str, Any]]:
        """
        Parse Java source code and extract chunks

        Args:
            source_code: Java source code string
            file_path: Optional file path for metadata

        Returns:
            List of code chunks with metadata
        """
        tree = self.parser.parse(bytes(source_code, 'utf-8'))
        root_node = tree.root_node

        chunks = []
        source_lines = source_code.split('\n')

        # Extract package and imports
        package_name = self._extract_package(root_node, source_code)
        imports = self._extract_imports(root_node, source_code)

        # Extract classes and interfaces
        for node in root_node.children:
            if node.type in ['class_declaration', 'interface_declaration', 'enum_declaration']:
                class_chunks = self._extract_class(
                    node, source_code, source_lines, file_path, package_name)
                chunks.extend(class_chunks)
            elif node.type == 'method_declaration':
                # Top-level methods (rare in Java but possible)
                method_chunk = self._extract_method(
                    node, source_code, source_lines, file_path)
                if method_chunk:
                    chunks.append(method_chunk)

        # Add a file-level chunk with imports and package info
        if package_name or imports:
            chunks.insert(0, {
                'type': 'file_header',
                'file': file_path,
                'language': 'java',
                'package': package_name,
                'imports': imports,
                'code': self._extract_header(source_lines, len(imports)),
                'start_line': 1,
                'end_line': len(imports) + (1 if package_name else 0),
                'metadata': {
                    'has_package': bool(package_name),
                    'import_count': len(imports)
                }
            })

        return chunks

    def _extract_package(self, root_node, source_code: str) -> Optional[str]:
        """Extract package declaration"""
        for node in root_node.children:
            if node.type == 'package_declaration':
                return source_code[node.start_byte:node.end_byte].replace('package', '').replace(';', '').strip()
        return None

    def _extract_imports(self, root_node, source_code: str) -> List[str]:
        """Extract import statements"""
        imports = []
        for node in root_node.children:
            if node.type == 'import_declaration':
                import_stmt = source_code[node.start_byte:node.end_byte].strip(
                )
                imports.append(import_stmt)
        return imports

    def _extract_header(self, source_lines: List[str], import_count: int) -> str:
        """Extract file header (package + imports)"""
        return '\n'.join(source_lines[:import_count + 2])

    def _extract_class(self, class_node, source_code: str, source_lines: List[str],
                       file_path: str, package: Optional[str]) -> List[Dict[str, Any]]:
        """Extract class and its methods"""
        chunks = []

        # Get class name
        class_name = None
        for child in class_node.children:
            if child.type == 'identifier':
                class_name = source_code[child.start_byte:child.end_byte]
                break

        if not class_name:
            return chunks

        start_line = class_node.start_point[0] + 1
        end_line = class_node.end_point[0] + 1

        # Extract class-level chunk (signature + fields)
        class_body = class_node.child_by_field_name('body')
        if class_body:
            # Get class signature and fields (not methods)
            fields = []
            for node in class_body.children:
                if node.type == 'field_declaration':
                    field_code = source_code[node.start_byte:node.end_byte]
                    fields.append(field_code.strip())

            class_signature = self._get_class_signature(
                class_node, source_code)
            class_chunk = {
                'type': 'class',
                'name': class_name,
                'file': file_path,
                'language': 'java',
                'package': package,
                'code': class_signature + '\n' + '\n'.join(fields),
                'start_line': start_line,
                'end_line': end_line,
                'metadata': {
                    'field_count': len(fields),
                    'is_interface': class_node.type == 'interface_declaration',
                    'is_enum': class_node.type == 'enum_declaration'
                }
            }
            chunks.append(class_chunk)

            # Extract methods
            for node in class_body.children:
                if node.type in ['method_declaration', 'constructor_declaration']:
                    method_chunk = self._extract_method(node, source_code, source_lines,
                                                        file_path, class_name, package)
                    if method_chunk:
                        chunks.append(method_chunk)

        return chunks

    def _get_class_signature(self, class_node, source_code: str) -> str:
        """Extract class signature (modifiers + declaration)"""
        # Find the opening brace
        for child in class_node.children:
            if child.type == 'class_body':
                return source_code[class_node.start_byte:child.start_byte].strip()
        # Fallback
        return source_code[class_node.start_byte:class_node.end_byte][:200]

    def _extract_method(self, method_node, source_code: str, source_lines: List[str],
                        file_path: str, class_name: str = None, package: str = None) -> Optional[Dict[str, Any]]:
        """Extract method chunk"""
        # Get method name
        method_name = None
        for child in method_node.children:
            if child.type == 'identifier':
                method_name = source_code[child.start_byte:child.end_byte]
                break

        if not method_name:
            return None

        start_line = method_node.start_point[0] + 1
        end_line = method_node.end_point[0] + 1
        method_code = source_code[method_node.start_byte:method_node.end_byte]

        # Extract parameters
        params = []
        param_list = method_node.child_by_field_name('parameters')
        if param_list:
            for param in param_list.children:
                if param.type == 'formal_parameter':
                    param_code = source_code[param.start_byte:param.end_byte]
                    params.append(param_code.strip())

        # Extract return type (if not constructor)
        return_type = None
        if method_node.type == 'method_declaration':
            type_node = method_node.child_by_field_name('type')
            if type_node:
                return_type = source_code[type_node.start_byte:type_node.end_byte]

        return {
            'type': 'method' if method_node.type == 'method_declaration' else 'constructor',
            'name': method_name,
            'class': class_name,
            'file': file_path,
            'language': 'java',
            'package': package,
            'code': method_code,
            'start_line': start_line,
            'end_line': end_line,
            'metadata': {
                'parameters': params,
                'param_count': len(params),
                'return_type': return_type,
                'lines_of_code': end_line - start_line + 1
            }
        }


def parse_java_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to parse a Java file

    Args:
        file_path: Path to Java file

    Returns:
        List of code chunks
    """
    parser = JavaParser()
    return parser.parse_file(file_path)
