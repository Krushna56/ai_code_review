"""
Query Handler

Main query processing engine for natural language security questions.
"""

import logging
import re
from typing import List, Dict, Any, Optional

from indexing.code_indexer import CodeIndexer
from llm_agents.security_reviewer import SecurityReviewer
from query.retrieval_engine import HybridRetriever
from query.rag_prompts import RAGPromptTemplates
import config

logger = logging.getLogger(__name__)


class QueryHandler:
    """Handle natural language security queries"""

    def __init__(self, indexer: CodeIndexer = None):
        """
        Initialize query handler

        Args:
            indexer: CodeIndexer instance (creates new if None)
        """
        self.indexer = indexer or CodeIndexer()
        self.security_reviewer = SecurityReviewer()
        self.hybrid_retriever = HybridRetriever(
            vector_store=self.indexer.vector_store,
            embedder=self.indexer.embedder
        )
        logger.info("Initialized QueryHandler with hybrid retrieval")

    def query(self, question: str, k: int = None,
              filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process a natural language security question

        Args:
            question: Natural language query
            k: Number of code chunks to retrieve
            filters: Optional metadata filters

        Returns:
            Query response with answer, sources, and metadata
        """
        k = k or config.QUERY_CONTEXT_CHUNKS

        logger.info(f"Processing query: {question}")

        # Detect query intent
        intent = self._detect_intent(question)
        logger.info(f"Detected intent: {intent}")

        # Apply intent-specific filters
        if not filters:
            filters = self._get_filters_for_intent(intent, question)

        # Use hybrid retrieval for better results
        results = self.hybrid_retriever.retrieve(
            query=question,
            k=k,
            intent=intent,
            filters=filters
        )

        if not results:
            return {
                'question': question,
                'answer': "No relevant code found for this query.",
                'sources': [],
                'intent': intent
            }

        # Use specialized RAG prompt based on intent
        prompt = RAGPromptTemplates.get_prompt_for_intent(
            intent, results, question)

        # Generate answer using security reviewer with RAG prompt
        answer = self.security_reviewer.generate(
            prompt=prompt,
            system_prompt=self.security_reviewer.system_prompt
        )

        # Format response
        response = {
            'question': question,
            'answer': answer if answer else 'Unable to generate answer',
            'sources': self._format_sources(results),
            'intent': intent,
            'chunks_found': len(results),
            'filters_applied': filters,
            'retrieval_method': 'hybrid',
            'ranking_explanation': self.hybrid_retriever.explain_ranking(results[0]) if results else None
        }

        return response

    def _detect_intent(self, question: str) -> str:
        """
        Detect the intent of the query

        Returns: 'hardcoded_secrets', 'sql_injection', 'xss', 'cve', 'pattern', 'location', 'general'
        """
        question_lower = question.lower()

        # Hardcoded secrets
        if any(kw in question_lower for kw in ['hardcoded', 'secret', 'api key', 'password', 'token', 'credential']):
            return 'hardcoded_secrets'

        # SQL Injection
        if any(kw in question_lower for kw in ['sql injection', 'sql query', 'parameterized', 'prepared statement']):
            return 'sql_injection'

        # XSS
        if any(kw in question_lower for kw in ['xss', 'cross-site scripting', 'innerhtml', 'sanitize']):
            return 'xss'

        # CVE/Vulnerabilities
        if any(kw in question_lower for kw in ['cve', 'vulnerability', 'vulnerable', 'outdated', 'dependency']):
            return 'cve'

        # Security patterns
        if any(kw in question_lower for kw in ['insecure', 'ssl', 'encryption', 'crypto', 'weak', 'md5', 'sha1']):
            return 'pattern'

        # Location queries
        if any(kw in question_lower for kw in ['where', 'which file', 'implemented', 'used', 'find']):
            return 'location'

        return 'general'

    def _get_filters_for_intent(self, intent: str, question: str) -> Optional[Dict[str, Any]]:
        """Get metadata filters based on intent"""
        filters = {}

        # Extract language if mentioned
        question_lower = question.lower()
        for lang in ['java', 'python', 'javascript', 'go', 'cpp', 'ruby']:
            if lang in question_lower:
                filters['language'] = lang
                break

        # For location queries, might want specific types
        if intent == 'location':
            # Check for class/method mentions
            if 'class' in question_lower:
                filters['type'] = 'class'
            elif any(kw in question_lower for kw in ['function', 'method']):
                filters['type'] = 'method'

        return filters if filters else None

    def _build_context(self, results: List[Dict[str, Any]], intent: str) -> Dict[str, Any]:
        """Build context for LLM from search results"""
        code_samples = []

        for i, result in enumerate(results[:config.QUERY_CONTEXT_CHUNKS]):
            file_info = f"{result['file']}:{
                result['start_line']}-{result['end_line']}"
            name_info = result.get('name', 'Unknown')

            sample = f"""
## Code Chunk {i+1} (Score: {result['score']:.3f})
**Location**: {file_info}
**Type**: {result['type']}
**Name**: {name_info}

```{result.get('language', 'text')}
{result['code']}
```
"""
            code_samples.append(sample)

        return {
            'code_samples': '\n'.join(code_samples),
            'num_chunks': len(results),
            'intent': intent
        }

    def _format_sources(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format search results as source citations"""
        sources = []

        for result in results:
            sources.append({
                'file': result['file'],
                'lines': f"{result['start_line']}-{result['end_line']}",
                'type': result['type'],
                'name': result.get('name'),
                'score': round(result['score'], 3),
                'code_preview': result['code'][:200] + '...' if len(result['code']) > 200 else result['code']
            })

        return sources


def ask_question(question: str, indexer: CodeIndexer = None) -> Dict[str, Any]:
    """
    Convenience function to ask a security question

    Args:
        question: Natural language query
        indexer: Optional CodeIndexer instance

    Returns:
        Query response
    """
    handler = QueryHandler(indexer=indexer)
    return handler.query(question)
