"""
Smart code chunking utilities for efficient code embedding.

Implements sliding window chunking with semantic boundary detection
to preserve code context and improve embedding quality.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re

logger = logging.getLogger(__name__)


class ChunkStrategy(Enum):
    """Chunking strategies"""
    FIXED_SIZE = "fixed"          # Simple fixed-size chunks
    SEMANTIC = "semantic"         # Function/class boundary aware
    SLIDING_WINDOW = "sliding"    # Overlapping window chunks
    HYBRID = "hybrid"             # Combination of semantic + sliding


@dataclass
class CodeChunk:
    """Represents a chunk of code with metadata"""
    content: str
    chunk_index: int
    start_line: int
    end_line: int
    language: str = "python"
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    @property
    def size(self) -> int:
        """Size of chunk in characters"""
        return len(self.content)

    @property
    def lines(self) -> int:
        """Number of lines in chunk"""
        return self.content.count('\n') + 1


class CodeChunker:
    """Smart code chunking with multiple strategies"""

    def __init__(self,
                 strategy: ChunkStrategy = ChunkStrategy.SLIDING_WINDOW,
                 chunk_size: int = 500,
                 overlap: int = 100,
                 language: str = "python"):
        """
        Initialize code chunker.

        Args:
            strategy: Chunking strategy to use
            chunk_size: Target chunk size in characters
            overlap: Overlap size for sliding window (characters)
            language: Code language for semantic detection
        """
        self.strategy = strategy
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.language = language
        logger.info(
            f"Initialized CodeChunker: strategy={strategy.value}, "
            f"chunk_size={chunk_size}, overlap={overlap}"
        )

    def chunk(self, code: str) -> List[CodeChunk]:
        """
        Split code into chunks using the configured strategy.

        Args:
            code: Source code to chunk

        Returns:
            List of CodeChunk objects
        """
        if self.strategy == ChunkStrategy.FIXED_SIZE:
            return self._chunk_fixed_size(code)
        elif self.strategy == ChunkStrategy.SEMANTIC:
            return self._chunk_semantic(code)
        elif self.strategy == ChunkStrategy.SLIDING_WINDOW:
            return self._chunk_sliding_window(code)
        else:  # HYBRID
            return self._chunk_hybrid(code)

    def _chunk_fixed_size(self, code: str) -> List[CodeChunk]:
        """
        Fixed-size chunking - simple splitting.

        Args:
            code: Source code to chunk

        Returns:
            List of fixed-size CodeChunk objects
        """
        chunks = []
        lines = code.split('\n')
        current_chunk = []
        current_size = 0
        start_line = 0

        for line_idx, line in enumerate(lines):
            line_with_newline = line + '\n'
            if current_size + len(line_with_newline) > self.chunk_size and current_chunk:
                # Save current chunk
                chunk_content = '\n'.join(current_chunk)
                chunks.append(CodeChunk(
                    content=chunk_content,
                    chunk_index=len(chunks),
                    start_line=start_line,
                    end_line=line_idx,
                    language=self.language
                ))

                # Start new chunk
                current_chunk = [line]
                current_size = len(line_with_newline)
                start_line = line_idx
            else:
                current_chunk.append(line)
                current_size += len(line_with_newline)

        # Add final chunk
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            chunks.append(CodeChunk(
                content=chunk_content,
                chunk_index=len(chunks),
                start_line=start_line,
                end_line=len(lines),
                language=self.language
            ))

        logger.info(f"Fixed-size chunking: {len(chunks)} chunks from {len(lines)} lines")
        return chunks

    def _chunk_semantic(self, code: str) -> List[CodeChunk]:
        """
        Semantic chunking - split at function/class boundaries.

        Args:
            code: Source code to chunk

        Returns:
            List of semantically meaningful CodeChunk objects
        """
        chunks = []
        lines = code.split('\n')

        # Regex patterns for semantic boundaries
        if self.language == "python":
            func_pattern = r'^(def |class |async def )'
            indent_pattern = r'^(\s*)'
        else:  # java, js, etc.
            func_pattern = r'^(public |private |protected |function |class )'
            indent_pattern = r'^(\s*)'

        current_chunk = []
        current_size = 0
        start_line = 0
        base_indent = None

        for line_idx, line in enumerate(lines):
            line_with_newline = line + '\n'

            # Check if this is a definition
            is_definition = re.match(func_pattern, line.strip())

            # Get indentation level
            indent_match = re.match(indent_pattern, line)
            current_indent = len(indent_match.group(1)) if indent_match else 0

            # If we hit a new top-level definition and have content, save chunk
            if (is_definition and current_indent == 0 and
                current_chunk and current_size > 50):
                chunk_content = '\n'.join(current_chunk)
                chunks.append(CodeChunk(
                    content=chunk_content,
                    chunk_index=len(chunks),
                    start_line=start_line,
                    end_line=line_idx - 1,
                    language=self.language,
                    metadata={'is_semantic': True}
                ))

                current_chunk = []
                current_size = 0
                start_line = line_idx
                base_indent = None

            current_chunk.append(line)
            current_size += len(line_with_newline)

        # Add final chunk
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            chunks.append(CodeChunk(
                content=chunk_content,
                chunk_index=len(chunks),
                start_line=start_line,
                end_line=len(lines),
                language=self.language,
                metadata={'is_semantic': True}
            ))

        logger.info(f"Semantic chunking: {len(chunks)} semantic chunks from {len(lines)} lines")
        return chunks

    def _chunk_sliding_window(self, code: str) -> List[CodeChunk]:
        """
        Sliding window chunking with overlap.

        Args:
            code: Source code to chunk

        Returns:
            List of overlapping CodeChunk objects
        """
        chunks = []
        step = self.chunk_size - self.overlap

        # Chunk by characters for precise control
        for i in range(0, len(code), step):
            end = min(i + self.chunk_size, len(code))
            chunk_content = code[i:end]

            # Convert character positions to line numbers
            start_line = code[:i].count('\n')
            end_line = code[:end].count('\n')

            chunks.append(CodeChunk(
                content=chunk_content,
                chunk_index=len(chunks),
                start_line=start_line,
                end_line=end_line,
                language=self.language,
                metadata={'overlap': self.overlap, 'strategy': 'sliding_window'}
            ))

            # Stop if we've reached the end
            if end >= len(code):
                break

        logger.info(
            f"Sliding window chunking: {len(chunks)} chunks "
            f"(size={self.chunk_size}, overlap={self.overlap})"
        )
        return chunks

    def _chunk_hybrid(self, code: str) -> List[CodeChunk]:
        """
        Hybrid chunking - combine semantic and sliding window.

        Uses semantic chunks when available, falls back to sliding window
        for large semantic blocks.

        Args:
            code: Source code to chunk

        Returns:
            List of hybrid CodeChunk objects
        """
        semantic_chunks = self._chunk_semantic(code)
        hybrid_chunks = []

        for sem_chunk in semantic_chunks:
            if sem_chunk.size > self.chunk_size * 2:
                # Large semantic chunk - subdivide with sliding window
                sub_chunks = self._chunk_sliding_window(sem_chunk.content)
                for sub_chunk in sub_chunks:
                    hybrid_chunks.append(CodeChunk(
                        content=sub_chunk.content,
                        chunk_index=len(hybrid_chunks),
                        start_line=sem_chunk.start_line + sub_chunk.start_line,
                        end_line=sem_chunk.start_line + sub_chunk.end_line,
                        language=self.language,
                        metadata={'hybrid': True, 'subdivision': True}
                    ))
            else:
                # Use semantic chunk as-is
                sem_chunk.chunk_index = len(hybrid_chunks)
                hybrid_chunks.append(sem_chunk)

        logger.info(f"Hybrid chunking: {len(hybrid_chunks)} chunks")
        return hybrid_chunks

    @staticmethod
    def estimate_optimal_chunk_size(code: str,
                                     target_chunks: int = 10) -> int:
        """
        Estimate optimal chunk size for the given code.

        Args:
            code: Source code to estimate for
            target_chunks: Target number of chunks

        Returns:
            Recommended chunk size in characters
        """
        if not code:
            return 500

        code_size = len(code)
        optimal_size = max(100, code_size // target_chunks)

        logger.info(
            f"Optimal chunk size estimate: {optimal_size} chars "
            f"(code_size={code_size}, target_chunks={target_chunks})"
        )
        return optimal_size
