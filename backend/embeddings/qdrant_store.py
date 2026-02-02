"""
Qdrant Vector Store

High-performance vector database for semantic code search with metadata filtering.
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import uuid

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import (
        Distance, VectorParams, PointStruct,
        Filter, FieldCondition, MatchValue
    )
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    logging.warning(
        "Qdrant not installed. Install with: pip install qdrant-client")

import config

logger = logging.getLogger(__name__)


class QdrantStore:
    """Qdrant-based vector store for code chunks with rich metadata"""

    def __init__(self, collection_name: str = None, dimension: int = 384):
        """
        Initialize Qdrant vector store

        Args:
            collection_name: Name of the collection
            dimension: Embedding dimension
        """
        if not QDRANT_AVAILABLE:
            raise ImportError(
                "Qdrant required. Install with: pip install qdrant-client")

        self.collection_name = collection_name or config.QDRANT_COLLECTION
        self.dimension = dimension

        # Initialize client
        if config.QDRANT_USE_MEMORY:
            # In-memory mode for development
            self.client = QdrantClient(":memory:")
            logger.info("Initialized Qdrant in-memory mode")
        else:
            # Connect to Qdrant server
            self.client = QdrantClient(
                host=config.QDRANT_HOST,
                port=config.QDRANT_PORT
            )
            logger.info(f"Connected to Qdrant at {
                        config.QDRANT_HOST}:{config.QDRANT_PORT}")

        # Create collection if it doesn't exist
        self._ensure_collection()

    def _ensure_collection(self):
        """Create collection if it doesn't exist"""
        try:
            collections = self.client.get_collections().collections
            collection_names = [c.name for c in collections]

            if self.collection_name not in collection_names:
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=self.dimension,
                        distance=Distance.COSINE
                    )
                )
                logger.info(f"Created Qdrant collection: {
                            self.collection_name}")
            else:
                logger.info(f"Using existing Qdrant collection: {
                            self.collection_name}")

        except Exception as e:
            logger.error(f"Error ensuring collection: {e}")
            raise

    def add(self, embeddings: List[List[float]], metadata: List[Dict[str, Any]]):
        """
        Add embeddings with metadata to the collection

        Args:
            embeddings: List of embedding vectors
            metadata: List of metadata dicts for each embedding
        """
        if len(embeddings) != len(metadata):
            raise ValueError(
                "Number of embeddings must match number of metadata entries")

        points = []
        for embedding, meta in zip(embeddings, metadata):
            point_id = str(uuid.uuid4())

            # Prepare payload with metadata
            payload = {
                'file': meta.get('file', ''),
                'language': meta.get('language', ''),
                'type': meta.get('type', ''),
                'name': meta.get('name', ''),
                'start_line': meta.get('start_line', 0),
                'end_line': meta.get('end_line', 0),
                'code': meta.get('code', ''),
                'class': meta.get('class'),
                'package': meta.get('package'),
                'metadata': meta.get('metadata', {})
            }

            points.append(PointStruct(
                id=point_id,
                vector=embedding,
                payload=payload
            ))

        # Upload points in batches
        batch_size = 100
        for i in range(0, len(points), batch_size):
            batch = points[i:i + batch_size]
            self.client.upsert(
                collection_name=self.collection_name,
                points=batch
            )

        logger.info(f"Added {len(points)} points to Qdrant collection")

    def search(self, query_embedding: List[float], k: int = 5,
               filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Search for similar code chunks

        Args:
            query_embedding: Query vector
            k: Number of results to return
            filters: Optional metadata filters (e.g., {'language': 'java', 'type': 'method'})

        Returns:
            List of results with metadata and scores
        """
        # Build filter conditions if provided
        qdrant_filter = None
        if filters:
            conditions = []
            for key, value in filters.items():
                conditions.append(
                    FieldCondition(
                        key=key,
                        match=MatchValue(value=value)
                    )
                )
            if conditions:
                qdrant_filter = Filter(must=conditions)

        # Perform search
        results = self.client.search(
            collection_name=self.collection_name,
            query_vector=query_embedding,
            limit=k,
            query_filter=qdrant_filter
        )

        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append({
                'id': result.id,
                'score': result.score,
                'file': result.payload.get('file'),
                'language': result.payload.get('language'),
                'type': result.payload.get('type'),
                'name': result.payload.get('name'),
                'class': result.payload.get('class'),
                'package': result.payload.get('package'),
                'start_line': result.payload.get('start_line'),
                'end_line': result.payload.get('end_line'),
                'code': result.payload.get('code'),
                'metadata': result.payload.get('metadata', {})
            })

        return formatted_results

    def delete_by_file(self, file_path: str):
        """
        Delete all chunks from a specific file

        Args:
            file_path: Path to file
        """
        filter_condition = Filter(
            must=[
                FieldCondition(
                    key='file',
                    match=MatchValue(value=file_path)
                )
            ]
        )

        self.client.delete(
            collection_name=self.collection_name,
            points_selector=filter_condition
        )

        logger.info(f"Deleted chunks for file: {file_path}")

    def clear(self):
        """Clear all data from the collection"""
        try:
            self.client.delete_collection(collection_name=self.collection_name)
            self._ensure_collection()
            logger.info("Cleared Qdrant collection")
        except Exception as e:
            logger.error(f"Error clearing collection: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        try:
            collection_info = self.client.get_collection(self.collection_name)
            return {
                'total_points': collection_info.points_count,
                'dimension': self.dimension,
                'collection_name': self.collection_name
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {
                'total_points': 0,
                'dimension': self.dimension,
                'collection_name': self.collection_name
            }

    def search_by_metadata(self, metadata_filters: Dict[str, Any],
                           limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search by metadata only (no vector similarity)

        Args:
            metadata_filters: Filters to apply (e.g., {'language': 'java', 'type': 'method'})
            limit: Maximum results to return

        Returns:
            List of matching chunks
        """
        conditions = []
        for key, value in metadata_filters.items():
            conditions.append(
                FieldCondition(
                    key=key,
                    match=MatchValue(value=value)
                )
            )

        filter_condition = Filter(must=conditions) if conditions else None

        # Scroll through all matching points
        results = self.client.scroll(
            collection_name=self.collection_name,
            scroll_filter=filter_condition,
            limit=limit
        )

        formatted_results = []
        for point in results[0]:  # results[0] contains the points
            formatted_results.append({
                'id': point.id,
                'file': point.payload.get('file'),
                'language': point.payload.get('language'),
                'type': point.payload.get('type'),
                'name': point.payload.get('name'),
                'class': point.payload.get('class'),
                'package': point.payload.get('package'),
                'start_line': point.payload.get('start_line'),
                'end_line': point.payload.get('end_line'),
                'code': point.payload.get('code'),
                'metadata': point.payload.get('metadata', {})
            })

        return formatted_results


def create_vector_store(dimension: int = 384) -> QdrantStore:
    """
    Convenience function to create a Qdrant store

    Args:
        dimension: Embedding dimension

    Returns:
        QdrantStore instance
    """
    return QdrantStore(dimension=dimension)
