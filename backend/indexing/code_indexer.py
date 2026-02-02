"""
Indexing Package

Code indexing pipeline for the security Q&A system.
"""

from .code_indexer import CodeIndexer, index_codebase

__all__ = ['CodeIndexer', 'index_codebase']
