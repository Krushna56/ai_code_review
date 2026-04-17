"""
Description Generator Service

Generates concise AI descriptions for security findings using Gemini API.
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class DescriptionGenerator:
    """Service for generating AI descriptions of security findings"""

    def __init__(self):
        """Initialize Gemini API"""
        api_key = os.getenv('GEMINI_API_KEY')
        model_name = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
        self._model_name = model_name
        self._client = None

        if not api_key:
            logger.warning("GEMINI_API_KEY not found in environment")
        else:
            try:
                import google.genai as genai
                # New SDK: genai.Client(api_key=...) — no genai.configure()
                self._client = genai.Client(api_key=api_key)
                logger.info("Gemini API client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini API: {e}")
                self._client = None

    @property
    def model(self):
        """Backwards-compat shim — True if client is available."""
        return self._client

    def generate_description(self, finding: Dict[str, Any]) -> str:
        """
        Generate a concise 1-sentence description for a security finding.

        Args:
            finding: Security finding dictionary

        Returns:
            AI-generated description or fallback message
        """
        if not self._client:
            return "AI description unavailable"

        try:
            finding_type = finding.get('type', 'unknown')
            severity = finding.get('severity', 'UNKNOWN')
            title = finding.get('title', 'Security Issue')
            owasp_name = finding.get('owasp_name', '')

            prompt = (
                "Generate a concise, actionable 1-sentence description for this security finding.\n"
                "Keep it under 100 characters and focus on the risk and fix.\n\n"
                f"Type: {finding_type}\n"
                f"Severity: {severity}\n"
                f"Title: {title}\n"
                f"OWASP: {owasp_name}\n\n"
                "Description:"
            )

            from google.genai import types
            response = self._client.models.generate_content(
                model=self._model_name,
                contents=prompt,
                config=types.GenerateContentConfig(max_output_tokens=150),
            )
            description = response.text.strip()

            if len(description) > 150:
                description = description[:147] + "..."

            return description

        except Exception as e:
            logger.error(f"Error generating description: {e}")
            return f"{finding.get('severity', 'UNKNOWN')} {finding.get('type', 'unknown')} issue detected"


# Singleton instance
_description_generator = None


def get_description_generator() -> DescriptionGenerator:
    """Get or create description generator singleton"""
    global _description_generator
    if _description_generator is None:
        _description_generator = DescriptionGenerator()
    return _description_generator
