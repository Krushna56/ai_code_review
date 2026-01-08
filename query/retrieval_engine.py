"""
Hybrid Retrieval Engine

Combines semantic search with pattern-based filtering and result re-ranking.
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from embeddings.qdrant_store import QdrantStore
from embeddings.code_embedder import CodeEmbedder
from query.pattern_filter import SecurityPatternFilter
import config

logger = logging.getLogger(__name__)


class HybridRetriever:
    """Hybrid retrieval combining vector search and pattern matching"""
    
    def __init__(self, vector_store: QdrantStore = None, embedder: CodeEmbedder = None):
        """
        Initialize hybrid retriever
        
        Args:
            vector_store: QdrantStore instance
            embedder: CodeEmbedder instance
        """
        self.vector_store = vector_store
        self.embedder = embedder
        self.pattern_filter = SecurityPatternFilter()
        logger.info("Initialized HybridRetriever")
    
    def retrieve(self, query: str, k: int = 10, 
                intent: str = 'general',
                filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Hybrid retrieval combining semantic and pattern-based search
        
        Args:
            query: Search query
            k: Number of results
            intent: Query intent for pattern selection
            filters: Metadata filters
            
        Returns:
            Ranked list of code chunks
        """
        # 1. Semantic search via vector store
        semantic_results = self._semantic_search(query, k, filters)
        
        # 2. Pattern-based filtering (if applicable)
        pattern_results = self._pattern_search(intent, filters)
        
        # 3. Combine results
        combined = self._combine_results(semantic_results, pattern_results)
        
        # 4. Re-rank based on multiple signals
        ranked = self._rerank_results(combined, query, intent)
        
        # 5. Return top K
        return ranked[:k]
    
    def _semantic_search(self, query: str, k: int, 
                        filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform semantic vector search"""
        if not self.vector_store or not self.embedder:
            logger.warning("Vector store or embedder not initialized")
            return []
        
        # Generate query embedding
        query_embedding = self.embedder.embed(query)
        if query_embedding is None:
            logger.error("Failed to generate query embedding")
            return []
        
        # Search
        results = self.vector_store.search(
            query_embedding=query_embedding.tolist(),
            k=k * 2,  # Get more for re-ranking
            filters=filters
        )
        
        # Add source tag
        for result in results:
            result['retrieval_source'] = 'semantic'
        
        logger.info(f"Semantic search found {len(results)} results")
        return results
    
    def _pattern_search(self, intent: str, 
                       filters: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Search using pattern matching"""
        if intent not in ['pattern', 'hardcoded_secrets', 'sql_injection', 'xss']:
            # Pattern search only relevant for certain intents
            return []
        
        # Map intent to pattern category
        category_map = {
            'hardcoded_secrets': None,  # Handled by secret detector
            'sql_injection': 'sql_injection',
            'xss': 'xss',
            'pattern': None  # Use all patterns
        }
        
        category = category_map.get(intent)
        if not category:
            return []
        
        # Search using metadata filter for pattern category
        if self.vector_store:
            # This would require indexing pattern matches first
            # For now, return empty; this can be enhanced later
            pass
        
        return []
    
    def _combine_results(self, semantic: List[Dict[str, Any]], 
                        pattern: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Combine semantic and pattern-based results"""
        # Use dict to deduplicate by (file, start_line, end_line)
        combined = {}
        
        for result in semantic:
            key = (result.get('file'), result.get('start_line'), result.get('end_line'))
            if key not in combined:
                combined[key] = result
        
        for result in pattern:
            key = (result.get('file'), result.get('start_line'), result.get('end_line'))
            if key not in combined:
                result['retrieval_source'] = 'pattern'
                combined[key] = result
            else:
                # Boost score if found by both methods
                combined[key]['score'] = combined[key].get('score', 0) * 1.2
                combined[key]['retrieval_source'] = 'hybrid'
        
        return list(combined.values())
    
    def _rerank_results(self, results: List[Dict[str, Any]], 
                       query: str, intent: str) -> List[Dict[str, Any]]:
        """
        Re-rank results using multiple signals
        
        Ranking factors:
        1. Semantic similarity score (from vector search)
        2. Pattern match boost
        3. Code complexity (higher = more likely to have bugs)
        4. File type relevance
        5. Recency (if available)
        """
        for result in results:
            # Base score from semantic search
            base_score = result.get('score', 0.5)
            
            # Boost for pattern matches
            pattern_boost = 0.2 if result.get('retrieval_source') == 'pattern' else 0
            if result.get('retrieval_source') == 'hybrid':
                pattern_boost = 0.3
            
            # Boost for method/function types (more likely to have logic bugs)
            type_boost = 0.1 if result.get('type') in ['method', 'function'] else 0
            
            # Boost based on code complexity (if available)
            complexity = result.get('metadata', {}).get('complexity', 0)
            complexity_boost = min(complexity / 10 * 0.1, 0.15)  # Cap at 0.15
            
            # Language relevance boost (if query mentions specific language)
            language_boost = 0
            query_lower = query.lower()
            result_lang = result.get('language', '').lower()
            if result_lang and result_lang in query_lower:
                language_boost = 0.1
            
            # Intent-specific boosts
            intent_boost = self._get_intent_boost(result, intent)
            
            # Calculate final score
            final_score = (
                base_score + 
                pattern_boost + 
                type_boost + 
                complexity_boost + 
                language_boost + 
                intent_boost
            )
            
            result['rerank_score'] = final_score
            result['ranking_factors'] = {
                'semantic': base_score,
                'pattern': pattern_boost,
                'type': type_boost,
                'complexity': complexity_boost,
                'language': language_boost,
                'intent': intent_boost
            }
        
        # Sort by rerank_score
        results.sort(key=lambda x: x.get('rerank_score', 0), reverse=True)
        
        logger.info(f"Re-ranked {len(results)} results")
        return results
    
    def _get_intent_boost(self, result: Dict[str, Any], intent: str) -> float:
        """Get intent-specific ranking boost"""
        boost = 0.0
        
        # Boost for hardcoded secrets intent if high-entropy strings present
        if intent == 'hardcoded_secrets':
            code = result.get('code', '')
            if any(kw in code.lower() for kw in ['key', 'password', 'token', 'secret']):
                boost += 0.15
        
        # Boost for SQL injection if database-related
        if intent == 'sql_injection':
            code = result.get('code', '')
            if any(kw in code.lower() for kw in ['execute', 'query', 'sql', 'database']):
                boost += 0.15
        
        # Boost for location queries if name matches
        if intent == 'location':
            # Already handled by semantic search
            pass
        
        return boost
    
    def explain_ranking(self, result: Dict[str, Any]) -> str:
        """Generate human-readable explanation of ranking"""
        factors = result.get('ranking_factors', {})
        
        explanation = f"**Ranking Score: {result.get('rerank_score', 0):.3f}**\n"
        explanation += "Factors:\n"
        explanation += f"- Semantic similarity: {factors.get('semantic', 0):.3f}\n"
        
        if factors.get('pattern', 0) > 0:
            explanation += f"- Pattern match boost: +{factors['pattern']:.3f}\n"
        if factors.get('complexity', 0) > 0:
            explanation += f"- Complexity boost: +{factors['complexity']:.3f}\n"
        if factors.get('language', 0) > 0:
            explanation += f"- Language relevance: +{factors['language']:.3f}\n"
        if factors.get('intent', 0) > 0:
            explanation += f"- Intent boost: +{factors['intent']:.3f}\n"
        
        return explanation


def hybrid_search(query: str, vector_store: QdrantStore, embedder: CodeEmbedder,
                 k: int = 5, intent: str = 'general') -> List[Dict[str, Any]]:
    """
    Convenience function for hybrid search
    
    Args:
        query: Search query
        vector_store: Vector store instance
        embedder: Embedder instance
        k: Number of results
        intent: Query intent
        
    Returns:
        Ranked results
    """
    retriever = HybridRetriever(vector_store, embedder)
    return retriever.retrieve(query, k, intent)
