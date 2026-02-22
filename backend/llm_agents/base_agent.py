"""
Base LLM Agent

Common interface for all LLM agents
"""

import logging
from typing import Dict, Any, Optional, List, Generator
from abc import ABC, abstractmethod

import config

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for all LLM agents"""

    def __init__(self, provider: str = None, model: str = None):
        self.provider = provider or config.LLM_PROVIDER
        self.model = model or config.LLM_MODEL
        self.temperature = config.LLM_TEMPERATURE
        self.max_tokens = config.LLM_MAX_TOKENS
        self.client = None

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
        Generate response from LLM with automatic fallback
        
        Tries the configured provider first, then falls back to other providers if it fails.
        Fallback order: anthropic → mistral → openai

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)

        Returns:
            Generated text
        """
        # Define fallback order based on current provider
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
        else:  # openai or default
            providers_to_try = [
                ('openai', 'gpt-4o', config.OPENAI_API_KEY),
                ('anthropic', 'claude-3-5-sonnet-20241022', config.ANTHROPIC_API_KEY),
                ('mistral', 'mistral-large-latest', config.MISTRAL_API_KEY)
            ]
        
        last_error = None
        
        for provider_name, model_name, api_key in providers_to_try:
            if not api_key:  # Skip if API key not configured
                continue
                
            try:
                logger.info(f"Trying {provider_name} with model {model_name}")
                
                # Temporarily switch to this provider
                original_provider = self.provider
                original_model = self.model
                self.provider = provider_name
                self.model = model_name
                
                # Re-initialize client for the new provider
                self._initialize_client()
                
                # Try to generate response
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
                
                # Check if it's a quota/rate limit error
                if '429' in error_msg or 'quota' in error_msg.lower() or 'rate' in error_msg.lower():
                    logger.warning(f"❌ {provider_name} quota exceeded or rate limited, trying next provider...")
                else:
                    logger.warning(f"❌ {provider_name} failed: {error_msg}, trying next provider...")
                
                continue
        
        # All providers failed
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
