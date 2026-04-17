"""
LLM Client Factory - Centralized LLM provider management.

Provides a single place to manage LLM client initialization, fallback logic,
and configuration for all LLM providers (OpenAI, Anthropic, Mistral, Gemini).

Routing policy (enforced via create_*_client helpers):
  - Chat / Chatbot       → Gemini
  - Code Analysis        → Mistral (primary) + Anthropic (fallback)
  - Report / Extraction  → OpenAI GPT-4
"""

import logging
from typing import Optional, Type, Dict, Any
from abc import ABC, abstractmethod
import config

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Base class for all LLM clients"""

    def __init__(self, provider: str, model: str, api_key: str):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.client = None

    @abstractmethod
    def complete(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Generate completion for a prompt"""
        pass

    @abstractmethod
    def stream(self, prompt: str, system_prompt: Optional[str] = None,
               temperature: float = 0.7, max_tokens: int = 2000):
        """Stream completion for a prompt"""
        pass


class OpenAIClient(LLMClient):
    """OpenAI LLM client"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        if not api_key:
            api_key = config.OPENAI_API_KEY
        if not model:
            model = config.LLM_MODEL

        super().__init__('openai', model, api_key)

        try:
            from openai import OpenAI as OpenAISDK
            self.client = OpenAISDK(api_key=api_key)
            logger.info(f"Initialized OpenAI client with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise

    def complete(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Generate completion using OpenAI API"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI completion error: {e}")
            return None

    def stream(self, prompt: str, system_prompt: Optional[str] = None,
               temperature: float = 0.7, max_tokens: int = 2000):
        """Stream completion using OpenAI API"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stream=True
            )

            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"OpenAI streaming error: {e}")


class AnthropicClient(LLMClient):
    """Anthropic (Claude) LLM client"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        if not api_key:
            api_key = config.ANTHROPIC_API_KEY
        if not model:
            model = 'claude-3-5-sonnet-20241022'

        super().__init__('anthropic', model, api_key)

        try:
            from anthropic import Anthropic as AnthropicSDK
            self.client = AnthropicSDK(api_key=api_key)
            logger.info(f"Initialized Anthropic client with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            raise

    def complete(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Generate completion using Anthropic API"""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt or "",
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Anthropic completion error: {e}")
            return None

    def stream(self, prompt: str, system_prompt: Optional[str] = None,
               temperature: float = 0.7, max_tokens: int = 2000):
        """Stream completion using Anthropic API"""
        try:
            with self.client.messages.stream(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt or "",
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature
            ) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as e:
            logger.error(f"Anthropic streaming error: {e}")


class MistralClient(LLMClient):
    """Mistral LLM client"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        if not api_key:
            api_key = config.MISTRAL_API_KEY
        if not model:
            model = 'mistral-large-latest'

        super().__init__('mistral', model, api_key)

        try:
            from mistralai import Mistral as MistralSDK
            self.client = MistralSDK(api_key=api_key)
            logger.info(f"Initialized Mistral client with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize Mistral client: {e}")
            raise

    def complete(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Generate completion using Mistral API"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.complete(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Mistral completion error: {e}")
            return None

    def stream(self, prompt: str, system_prompt: Optional[str] = None,
               temperature: float = 0.7, max_tokens: int = 2000):
        """Stream completion using Mistral API"""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.stream(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )

            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"Mistral streaming error: {e}")


class GeminiClient(LLMClient):
    """Google Gemini LLM client (uses google-genai >= 0.3.0 SDK)"""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        if not api_key:
            api_key = config.GEMINI_API_KEY
        if not model:
            model = config.GEMINI_MODEL

        super().__init__('gemini', model, api_key)

        try:
            import google.genai as genai
            # New SDK: genai.Client(api_key=...) — no genai.configure()
            self.client = genai.Client(api_key=api_key)
            logger.info(f"Initialized Gemini client with model: {model}")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            raise

    def complete(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 2000) -> Optional[str]:
        """Generate completion using Gemini API"""
        try:
            from google.genai import types
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            response = self.client.models.generate_content(
                model=self.model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )
            return response.text
        except Exception as e:
            logger.error(f"Gemini completion error: {e}")
            return None

    def stream(self, prompt: str, system_prompt: Optional[str] = None,
               temperature: float = 0.7, max_tokens: int = 2000):
        """Stream completion using Gemini API"""
        try:
            from google.genai import types
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            for chunk in self.client.models.generate_content_stream(
                model=self.model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            ):
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            logger.error(f"Gemini streaming error: {e}")


class LLMClientFactory:
    """Factory for creating and managing LLM clients"""

    # Available providers and their client classes
    PROVIDERS = {
        'openai': OpenAIClient,
        'anthropic': AnthropicClient,
        'mistral': MistralClient,
        'gemini': GeminiClient,
    }

    # Default fallback order
    DEFAULT_FALLBACK_ORDER = ['anthropic', 'mistral', 'openai', 'gemini']

    @classmethod
    def create_client(cls, provider: Optional[str] = None,
                     model: Optional[str] = None,
                     api_key: Optional[str] = None) -> LLMClient:
        """
        Create an LLM client for the specified provider.

        Args:
            provider: Provider name ('openai', 'anthropic', 'mistral', 'gemini')
            model: Model name (uses config defaults if not provided)
            api_key: API key (uses config defaults if not provided)

        Returns:
            Configured LLMClient instance

        Raises:
            ValueError: If provider is invalid or client initialization fails
        """
        provider = provider or config.LLM_PROVIDER
        provider_lower = provider.lower()

        if provider_lower not in cls.PROVIDERS:
            raise ValueError(f"Unknown LLM provider: {provider}")

        client_class = cls.PROVIDERS[provider_lower]
        try:
            client = client_class(api_key=api_key, model=model)
            logger.info(f"Created {provider_lower} LLM client successfully")
            return client
        except Exception as e:
            logger.error(f"Failed to create {provider_lower} LLM client: {e}")
            raise

    @classmethod
    def create_client_with_fallback(
        cls,
        primary_provider: Optional[str] = None,
        fallback_providers: Optional[list] = None,
        model: Optional[str] = None
    ) -> LLMClient:
        """
        Create an LLM client with automatic fallback if primary fails.

        Args:
            primary_provider: Primary provider to try first
            fallback_providers: List of fallback providers in order
            model: Model name (uses config defaults if not provided)

        Returns:
            First successfully initialized LLMClient

        Raises:
            RuntimeError: If all providers fail to initialize
        """
        providers_to_try = [primary_provider or config.LLM_PROVIDER]

        if fallback_providers:
            providers_to_try.extend(fallback_providers)
        else:
            # Add default fallback order (excluding primary)
            for fallback in cls.DEFAULT_FALLBACK_ORDER:
                if fallback not in providers_to_try:
                    providers_to_try.append(fallback)

        last_error = None
        for provider in providers_to_try:
            try:
                logger.info(f"Attempting to initialize {provider} client...")
                client = cls.create_client(provider, model)
                logger.info(f"Successfully initialized {provider} client")
                return client
            except Exception as e:
                last_error = e
                logger.warning(f"Failed to initialize {provider}: {e}. Trying next...")
                continue

        # All providers failed
        error_msg = f"All LLM providers failed: {last_error}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

    @classmethod
    def get_available_providers(cls) -> list:
        """Get list of available LLM providers"""
        available = []
        for provider_name, client_class in cls.PROVIDERS.items():
            try:
                # Check if API key is configured
                if provider_name == 'openai' and config.OPENAI_API_KEY:
                    available.append(provider_name)
                elif provider_name == 'anthropic' and config.ANTHROPIC_API_KEY:
                    available.append(provider_name)
                elif provider_name == 'mistral' and config.MISTRAL_API_KEY:
                    available.append(provider_name)
                elif provider_name == 'gemini' and config.GEMINI_API_KEY:
                    available.append(provider_name)
            except (AttributeError, Exception):
                pass

        logger.info(f"Available LLM providers: {available}")
        return available

    # ──────────────────────────────────────────────────────────────────────────
    # Strict routing helpers — one dedicated LLM per task type
    # ──────────────────────────────────────────────────────────────────────────

    @classmethod
    def create_chat_client(cls) -> LLMClient:
        """
        Gemini-only client for chatbot conversations.
        Falls back to other available providers only if Gemini is unavailable.
        """
        provider = getattr(config, 'CHAT_PROVIDER', 'gemini')
        logger.info(f"[ROUTING] Creating CHAT client → {provider}")
        try:
            return cls.create_client(provider)
        except Exception as e:
            logger.warning(f"Chat provider '{provider}' failed ({e}), trying fallback")
            fallbacks = [p for p in ['gemini', 'openai', 'anthropic', 'mistral'] if p != provider]
            return cls.create_client_with_fallback(provider, fallbacks)

    @classmethod
    def create_analysis_client(cls) -> LLMClient:
        """
        Mistral (primary) + Anthropic (fallback) for code analysis and bug-bounty scanning.
        """
        primary = getattr(config, 'ANALYSIS_PROVIDER', 'mistral')
        fallback = getattr(config, 'ANALYSIS_FALLBACK_PROVIDER', 'anthropic')
        logger.info(f"[ROUTING] Creating ANALYSIS client → {primary} (fallback: {fallback})")
        return cls.create_client_with_fallback(primary, [fallback])

    @classmethod
    def create_report_client(cls) -> LLMClient:
        """
        OpenAI GPT-4 for report writing, structured data extraction, and image analysis.
        Falls back to other available providers only if OpenAI is unavailable.
        """
        provider = getattr(config, 'REPORT_PROVIDER', 'openai')
        logger.info(f"[ROUTING] Creating REPORT client → {provider}")
        try:
            return cls.create_client(provider)
        except Exception as e:
            logger.warning(f"Report provider '{provider}' failed ({e}), trying fallback")
            fallbacks = [p for p in ['openai', 'anthropic', 'mistral', 'gemini'] if p != provider]
            return cls.create_client_with_fallback(provider, fallbacks)
