"""
Vector Store using FAISS

Local vector database for semantic code search
"""

import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import numpy as np

try:
    import faiss
except ImportError:
    faiss = None
    logging.warning("FAISS not installed. Install with: pip install faiss-cpu")

import config

logger = logging.getLogger(__name__)


class VectorStore:
    """FAISS-based vector store for code snippets"""
    
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.index = None
        self.metadata = []
        self.index_path = config.FAISS_INDEX_PATH
        self.metadata_path = config.FAISS_METADATA_PATH
        
        if faiss is None:
            raise ImportError("FAISS is required. Install with: pip install faiss-cpu")
        
        self._initialize_index()
    
    def _initialize_index(self):
        """Initialize or load FAISS index"""
        if self.index_path.exists():
            self.load()
        else:
            # Create new index (L2 distance)
            self.index = faiss.IndexFlatL2(self.dimension)
            logger.info(f"Created new FAISS index with dimension {self.dimension}")
    
    def add(self, embeddings: np.ndarray, metadata: List[Dict[str, Any]]):
        """
        Add embeddings to the index
        
        Args:
            embeddings: numpy array of shape (n, dimension)
            metadata: List of metadata dicts for each embedding
        """
        if embeddings.shape[1] != self.dimension:
            raise ValueError(f"Embedding dimension {embeddings.shape[1]} doesn't match index dimension {self.dimension}")
        
        # Ensure float32
        embeddings = embeddings.astype(np.float32)
        
        # Add to index
        self.index.add(embeddings)
        self.metadata.extend(metadata)
        
        logger.info(f"Added {len(embeddings)} embeddings to index. Total: {self.index.ntotal}")
    
    def search(self, query_embedding: np.ndarray, k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar code snippets
        
        Args:
            query_embedding: Query vector
            k: Number of results to return
            
        Returns:
            List of results with metadata and distances
        """
        if self.index is None or self.index.ntotal == 0:
            logger.warning("Index is empty")
            return []
        
        # Ensure correct shape and type
        query_embedding = query_embedding.astype(np.float32).reshape(1, -1)
        
        # Search
        distances, indices = self.index.search(query_embedding, min(k, self.index.ntotal))
        
        # Prepare results
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < len(self.metadata):
                result = self.metadata[idx].copy()
                result['distance'] = float(dist)
                result['similarity'] = float(1 / (1 + dist))  # Convert distance to similarity
                results.append(result)
        
        return results
    
    def save(self):
        """Save index and metadata to disk"""
        try:
            # Save FAISS index
            faiss.write_index(self.index, str(self.index_path))
            
            # Save metadata
            with open(self.metadata_path, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2)
            
            logger.info(f"Saved index with {self.index.ntotal} vectors to {self.index_path}")
            
        except Exception as e:
            logger.error(f"Error saving index: {e}")
    
    def load(self):
        """Load index and metadata from disk"""
        try:
            # Load FAISS index
            self.index = faiss.read_index(str(self.index_path))
            self.dimension = self.index.d
            
            # Load metadata
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r', encoding='utf-8') as f:
                    self.metadata = json.load(f)
            
            logger.info(f"Loaded index with {self.index.ntotal} vectors from {self.index_path}")
            
        except Exception as e:
            logger.error(f"Error loading index: {e}")
            self._initialize_index()
    
    def clear(self):
        """Clear the index"""
        self.index = faiss.IndexFlatL2(self.dimension)
        self.metadata = []
        logger.info("Cleared index")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics"""
        return {
            'total_vectors': self.index.ntotal if self.index else 0,
            'dimension': self.dimension,
            'index_type': type(self.index).__name__ if self.index else None
        }
