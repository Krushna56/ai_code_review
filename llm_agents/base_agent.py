"""
Base LLM Agent

Common interface for all LLM agents
"""

import logging
from typing import Dict, Any, Optional, List
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
                logger.info(f"Initialized OpenAI client with model: {self.model}")
            elif self.provider == 'anthropic':
                from anthropic import Anthropic
                self.client = Anthropic(api_key=config.ANTHROPIC_API_KEY)
                logger.info(f"Initialized Anthropic client with model: {self.model}")
            else:
                raise ValueError(f"Unknown LLM provider: {self.provider}")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}")
            raise
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Generate response from LLM
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            
        Returns:
            Generated text
        """
        try:
            if self.provider == 'openai':
                return self._generate_openai(prompt, system_prompt)
            elif self.provider == 'anthropic':
                return self._generate_anthropic(prompt, system_prompt)
        except Exception as e:
            logger.error(f"Error generating response: {e}")
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
