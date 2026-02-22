"""
Description Generator Service

Generates concise AI descriptions for security findings using Gemini API.
"""

import google.generativeai as genai
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class DescriptionGenerator:
    """Service for generating AI descriptions of security findings"""
    
    def __init__(self):
        """Initialize Gemini API"""
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            logger.warning("GEMINI_API_KEY not found in environment")
            self.model = None
        else:
            try:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                logger.info("Gemini API initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini API: {e}")
                self.model = None
    
    def generate_description(self, finding: Dict[str, Any]) -> str:
        """
        Generate a concise 1-sentence description for a security finding
        
        Args:
            finding: Security finding dictionary
            
        Returns:
            AI-generated description or fallback message
        """
        if not self.model:
            return "AI description unavailable"
        
        try:
            # Build prompt
            finding_type = finding.get('type', 'unknown')
            severity = finding.get('severity', 'UNKNOWN')
            title = finding.get('title', 'Security Issue')
            owasp_name = finding.get('owasp_name', '')
            
            prompt = f"""Generate a concise, actionable 1-sentence description for this security finding.
Keep it under 100 characters and focus on the risk and fix.

Type: {finding_type}
Severity: {severity}
Title: {title}
OWASP: {owasp_name}

Description:"""
            
            # Generate response
            response = self.model.generate_content(prompt)
            description = response.text.strip()
            
            # Truncate if too long
            if len(description) > 150:
                description = description[:147] + "..."
            
            return description
            
        except Exception as e:
            logger.error(f"Error generating description: {e}")
            return f"{severity} {finding_type} issue detected"


# Singleton instance
_description_generator = None


def get_description_generator() -> DescriptionGenerator:
    """Get or create description generator singleton"""
    global _description_generator
    if _description_generator is None:
        _description_generator = DescriptionGenerator()
    return _description_generator
