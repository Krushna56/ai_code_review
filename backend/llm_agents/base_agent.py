"""
Base LLM Agent

Common interface for all LLM agents.
Code analysis agents (SecurityReviewer, RefactorAgent) use Mistral (primary)
+ Anthropic (fallback) via LLMClientFactory.create_analysis_client().
"""

import logging
from typing import Dict, Any, Optional, List, Generator
from abc import ABC, abstractmethod

import config

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for all LLM agents — analysis agents use Mistral + Anthropic fallback."""

    def __init__(self, provider: str = None, model: str = None):
        # Use the new strict routing: analysis → Mistral first, then Anthropic
        from llm_agents.llm_factory import LLMClientFactory
        try:
            self._llm_client = LLMClientFactory.create_analysis_client()
            self.provider = self._llm_client.provider
            self.model = self._llm_client.model
            logger.info(f"[BaseAgent] Using analysis client: {self.provider}/{self.model}")
        except Exception as e:
            logger.warning(f"[BaseAgent] create_analysis_client failed ({e}), falling back to legacy init")
            self._llm_client = None
            self.provider = provider or config.LLM_PROVIDER
            self.model = model or config.LLM_MODEL

        self.temperature = config.LLM_TEMPERATURE
        self.max_tokens = config.LLM_MAX_TOKENS
        self.client = None  # Legacy raw client (used by _generate_* helpers)

        if not self._llm_client:
            # legacy fallback path
            self._initialize_client()

    def _initialize_client(self):
        """Initialize LLM client"""
        try:
            if self.provider == 'openai':
                from openai import OpenAI
                self.client = OpenAI(api_key=config.OPENAI_API_KEY)
                logger.info(
                    f"Initialized OpenAI client with model: {self.model}")
            elif self.provider == 'anthropic':
                from anthropic import Anthropic
                self.client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
                logger.info(
                    f"Initialized Anthropic client with model: {self.model}")
            elif self.provider == 'mistral':
                from mistralai import Mistral
                self.client = Mistral(api_key=config.MISTRAL_API_KEY)
                logger.info(
                    f"Initialized Mistral AI client with model: {self.model}")
            else:
                raise ValueError(f"Unknown LLM provider: {self.provider}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            raise

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Generate response using the analysis LLM client (Mistral → Anthropic fallback).
        Falls back to legacy per-provider methods if factory client is unavailable.
        """
        # Fast path: use the pre-built factory client
        if self._llm_client is not None:
            try:
                result = self._llm_client.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
                if result:
                    logger.info(f"[BaseAgent] Response generated via {self._llm_client.provider}")
                    return result
            except Exception as e:
                logger.warning(f"[BaseAgent] Factory client failed ({e}), trying legacy path")

        # Legacy fallback: try providers in order
        if self.provider == 'anthropic':
            providers_to_try = [
                ('anthropic', 'claude-3-5-sonnet-20241022', config.ANTHROPIC_API_KEY),
                ('mistral', 'mistral-large-latest', config.MISTRAL_API_KEY),
                ('openai', 'gpt-4o', config.OPENAI_API_KEY)
            ]
        elif self.provider == 'mistral':
            providers_to_try = [
                ('mistral', 'mistral-large-latest', config.MISTRAL_API_KEY),
                ('anthropic', 'claude-3-5-sonnet-20241022', config.ANTHROPIC_API_KEY),
                ('openai', 'gpt-4o', config.OPENAI_API_KEY)
            ]
        else:
            providers_to_try = [
                ('openai', 'gpt-4o', config.OPENAI_API_KEY),
                ('anthropic', 'claude-3-5-sonnet-20241022', config.ANTHROPIC_API_KEY),
                ('mistral', 'mistral-large-latest', config.MISTRAL_API_KEY)
            ]

        last_error = None
        for provider_name, model_name, api_key in providers_to_try:
            if not api_key:
                continue
            try:
                logger.info(f"Trying {provider_name} with model {model_name}")
                self.provider = provider_name
                self.model = model_name
                self._initialize_client()

                if provider_name == 'openai':
                    result = self._generate_openai(prompt, system_prompt)
                elif provider_name == 'anthropic':
                    result = self._generate_anthropic(prompt, system_prompt)
                elif provider_name == 'mistral':
                    result = self._generate_mistral(prompt, system_prompt)

                logger.info(f"✅ Successfully generated response using {provider_name}")
                return result
            except Exception as e:
                last_error = e
                error_msg = str(e)
                if '429' in error_msg or 'quota' in error_msg.lower() or 'rate' in error_msg.lower():
                    logger.warning(f"❌ {provider_name} quota exceeded, trying next...")
                else:
                    logger.warning(f"❌ {provider_name} failed: {error_msg}, trying next...")
                continue

        logger.error(f"All API providers failed. Last error: {last_error}", exc_info=True)
        return None

    def _generate_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using OpenAI API"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        return response.choices[0].message.content

    def _generate_anthropic(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Anthropic API"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def _generate_mistral(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Mistral AI API"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.complete(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        return response.choices[0].message.content

    def generate_stream(self, prompt: str, system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        """
        Generate streaming response from LLM

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)

        Yields:
            Text chunks as they are generated
        """
        try:
            if self.provider == 'openai':
                yield from self._generate_openai_stream(prompt, system_prompt)
            elif self.provider == 'anthropic':
                yield from self._generate_anthropic_stream(prompt, system_prompt)
            elif self.provider == 'mistral':
                yield from self._generate_mistral_stream(prompt, system_prompt)
        except Exception as e:
            logger.error(f"Error generating streaming response: {e}")
            yield f"Error: {str(e)}"

    def _generate_openai_stream(self, prompt: str, system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        """Generate streaming response using OpenAI API"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        stream = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            stream=True
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def _generate_anthropic_stream(self, prompt: str, system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        """Generate streaming response using Anthropic API"""
        with self.client.messages.stream(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}]
        ) as stream:
            for text in stream.text_stream:
                yield text

    def _generate_mistral_stream(self, prompt: str, system_prompt: Optional[str] = None) -> Generator[str, None, None]:
        """Generate streaming response using Mistral AI API"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        stream = self.client.chat.stream(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )

        for chunk in stream:
            if chunk.data.choices[0].delta.content:
                yield chunk.data.choices[0].delta.content

    def count_tokens(self, text: str) -> int:
        """
        Estimate token count (rough approximation)

        Args:
            text: Text to count tokens for

        Returns:
            Estimated token count
        """
        # Rough approximation: 1 token ≈ 4 characters or 0.75 words
        return len(text.split())

    @abstractmethod
    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze code - must be implemented by subclasses

        Args:
            code: Code snippet to analyze
            context: Additional context (RAG results, metrics, etc.)

        Returns:
            Analysis results
        """
        pass

    def build_prompt(self, code: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Build prompt for analysis - can be overridden by subclasses"""
        return code
