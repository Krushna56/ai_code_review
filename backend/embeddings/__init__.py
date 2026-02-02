"""Embeddings package initialization"""

from .code_embedder import CodeEmbedder, embed_code
from .vector_store import VectorStore

__all__ = ['CodeEmbedder', 'embed_code', 'VectorStore']
