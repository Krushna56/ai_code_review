"""
Code Embedding Generation

Supports multiple embedding providers:
- OpenAI embeddings (API-based, high quality)
- Local embeddings using sentence-transformers (free, CPU-friendly)
"""

import hashlib
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import numpy as np

import config

logger = logging.getLogger(__name__)


class CodeEmbedder:
    """Generate embeddings for code snippets"""

    def __init__(self, provider: str = None):
        self.provider = provider or config.EMBEDDING_PROVIDER
        self.cache_dir = config.EMBEDDING_CACHE_DIR
        self.cache_enabled = config.CACHE_EMBEDDINGS

        if self.provider == 'openai':
            self._init_openai()
        elif self.provider == 'local':
            self._init_local()
        elif self.provider == 'codestral':
            self._init_codestral()
        else:
            raise ValueError(f"Unknown embedding provider: {self.provider}")

    def _init_openai(self):
        """Initialize OpenAI embeddings"""
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=config.OPENAI_API_KEY)
            self.model = config.OPENAI_EMBEDDING_MODEL
            logger.info(
                f"Initialized OpenAI embeddings with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI: {e}")
            raise

    def _init_local(self):
        """Initialize local sentence-transformers embeddings"""
        try:
            from sentence_transformers import SentenceTransformer
            self.model_name = config.LOCAL_EMBEDDING_MODEL
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Initialized local embeddings with model: {
                        self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize sentence-transformers: {e}")
            raise

    def _init_codestral(self):
        """Initialize Codestral (Mistral) embeddings"""
        try:
            from mistralai.client import MistralClient
            self.client = MistralClient(api_key=config.MISTRAL_API_KEY)
            self.model = config.CODESTRAL_EMBED_MODEL
            logger.info(
                f"Initialized Codestral embeddings with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Codestral: {e}")
            raise

    def embed(self, text: str) -> Optional[np.ndarray]:
        """
        Generate embedding for a single text

        Args:
            text: Code snippet or text to embed

        Returns:
            Embedding vector as numpy array
        """
        # Check cache first
        if self.cache_enabled:
            cached = self._get_from_cache(text)
            if cached is not None:
                return cached

        try:
            if self.provider == 'openai':
                embedding = self._embed_openai(text)
            elif self.provider == 'codestral':
                embedding = self._embed_codestral(text)
            else:  # local
                embedding = self._embed_local(text)

            # Cache the result
            if self.cache_enabled and embedding is not None:
                self._save_to_cache(text, embedding)

            return embedding

        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return None

    def embed_batch(self, texts: List[str]) -> List[Optional[np.ndarray]]:
        """
        Generate embeddings for multiple texts

        Args:
            texts: List of code snippets or texts

        Returns:
            List of embedding vectors
        """
        embeddings = []

        # Check which texts are already cached
        uncached_indices = []
        uncached_texts = []

        for i, text in enumerate(texts):
            if self.cache_enabled:
                cached = self._get_from_cache(text)
                if cached is not None:
                    embeddings.append(cached)
                    continue

            uncached_indices.append(i)
            uncached_texts.append(text)
            embeddings.append(None)  # Placeholder

        # Generate embeddings for uncached texts
        if uncached_texts:
            try:
                if self.provider == 'openai':
                    new_embeddings = self._embed_openai_batch(uncached_texts)
                elif self.provider == 'codestral':
                    new_embeddings = self._embed_codestral_batch(
                        uncached_texts)
                else:  # local
                    new_embeddings = self._embed_local_batch(uncached_texts)

                # Fill in the embeddings and cache them
                for idx, embedding in zip(uncached_indices, new_embeddings):
                    embeddings[idx] = embedding
                    if self.cache_enabled and embedding is not None:
                        self._save_to_cache(texts[idx], embedding)

            except Exception as e:
                logger.error(f"Error in batch embedding: {e}")

        return embeddings

    def _embed_openai(self, text: str) -> np.ndarray:
        """Generate embedding using OpenAI API"""
        response = self.client.embeddings.create(
            model=self.model,
            input=text
        )
        return np.array(response.data[0].embedding, dtype=np.float32)

    def _embed_openai_batch(self, texts: List[str]) -> List[np.ndarray]:
        """Generate embeddings for batch using OpenAI API"""
        response = self.client.embeddings.create(
            model=self.model,
            input=texts
        )
        return [np.array(item.embedding, dtype=np.float32) for item in response.data]

    def _embed_local(self, text: str) -> np.ndarray:
        """Generate embedding using local model"""
        return self.model.encode(text, convert_to_numpy=True).astype(np.float32)

    def _embed_local_batch(self, texts: List[str]) -> List[np.ndarray]:
        """Generate embeddings for batch using local model"""
        embeddings = self.model.encode(
            texts, convert_to_numpy=True, show_progress_bar=True)
        return [emb.astype(np.float32) for emb in embeddings]

    def _embed_codestral(self, text: str) -> np.ndarray:
        """Generate embedding using Codestral API"""
        response = self.client.embeddings(
            model=self.model,
            input=[text]
        )
        return np.array(response.data[0].embedding, dtype=np.float32)

    def _embed_codestral_batch(self, texts: List[str]) -> List[np.ndarray]:
        """Generate embeddings for batch using Codestral API"""
        response = self.client.embeddings(
            model=self.model,
            input=texts
        )
        return [np.array(item.embedding, dtype=np.float32) for item in response.data]

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text"""
        model_name = self.model if self.provider in [
            'openai', 'codestral'] else self.model_name
        content = f"{self.provider}:{model_name}:{text}"
        return hashlib.md5(content.encode()).hexdigest()

    def _get_from_cache(self, text: str) -> Optional[np.ndarray]:
        """Retrieve embedding from cache"""
        cache_key = self._get_cache_key(text)
        cache_file = self.cache_dir / f"{cache_key}.npy"

        if cache_file.exists():
            try:
                return np.load(cache_file)
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        return None

    def _save_to_cache(self, text: str, embedding: np.ndarray):
        """Save embedding to cache"""
        cache_key = self._get_cache_key(text)
        cache_file = self.cache_dir / f"{cache_key}.npy"

        try:
            np.save(cache_file, embedding)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def get_dimension(self) -> int:
        """Get embedding dimension"""
        if self.provider == 'openai':
            # text-embedding-3-small: 1536, text-embedding-3-large: 3072
            return 1536 if 'small' in self.model else 3072
        elif self.provider == 'codestral':
            # Codestral Embed: 1024 dimensions
            return 1024
        else:
            # all-MiniLM-L6-v2: 384, all-mpnet-base-v2: 768
            return self.model.get_sentence_embedding_dimension()


def embed_code(code: str, provider: str = None) -> Optional[np.ndarray]:
    """
    Convenience function to embed a single code snippet

    Args:
        code: Code snippet to embed
        provider: 'openai' or 'local'

    Returns:
        Embedding vector
    """
    embedder = CodeEmbedder(provider)
    return embedder.embed(code)
