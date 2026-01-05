"""
Security Reviewer Agent

Specialized LLM agent for security analysis
"""

import logging
from typing import Dict, Any, Optional, List
from .base_agent import BaseAgent

logger = logging.getLogger(__name__)


class SecurityReviewer(BaseAgent):
    """LLM agent specialized in security review"""
    
    def __init__(self, provider: str = None, model: str = None):
        super().__init__(provider, model)
        self.system_prompt = """You are a senior security engineer conducting a code security review.
Your task is to identify security vulnerabilities, explain their impact, and provide fix suggestions.

Focus on:
- SQL injection, XSS, CSRF vulnerabilities
- Authentication and authorization issues
- Insecure cryptography
- Input validation problems
- Sensitive data exposure
- Insecure dependencies

Provide:
1. Clear description of the vulnerability
2. Potential impact and severity (Critical/High/Medium/Low)
3. Specific fix recommendations with code examples
4. Best practices to prevent similar issues

Be precise and actionable. If no issues are found, say so clearly."""
    
    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze code for security issues
        
        Args:
            code: Code snippet to analyze
            context: Additional context (static analysis results, similar code, etc.)
            
        Returns:
            Security analysis results
        """
        prompt = self.build_prompt(code, context)
        response = self.generate(prompt, self.system_prompt)
        
        if response:
            return {
                'agent': 'SecurityReviewer',
                'analysis': response,
                'code_analyzed': code[:200] + '...' if len(code) > 200 else code
            }
        else:
            return {
                'agent': 'SecurityReviewer',
                'error': 'Failed to generate analysis'
            }
    
    def build_prompt(self, code: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Build security analysis prompt"""
        prompt = f"""Analyze the following code for security vulnerabilities:

```
{code}
```
"""
        
        if context:
            # Add static analysis results
            if 'static_analysis' in context:
                static_issues = context['static_analysis']
                if static_issues:
                    prompt += f"\n\nStatic analysis found {len(static_issues)} potential issues:\n"
                    for issue in static_issues[:3]:  # Top 3
                        prompt += f"- {issue.get('issue_text', issue.get('message', 'Unknown'))}\n"
            
            # Add similar vulnerable code examples
            if 'similar_code' in context:
                similar = context['similar_code']
                if similar:
                    prompt += "\n\nSimilar code patterns have been flagged before. Pay special attention to similar patterns.\n"
        
        prompt += "\n\nProvide a detailed security analysis."
        
        return prompt
