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
        self.system_prompt = """You are an AI security assistant helping developers understand their code security analysis.

CRITICAL INSTRUCTIONS:
1. **Be Concise**: Give short, direct answers (2-4 sentences max for simple questions)
2. **Use Provided Data**: ONLY answer based on the security analysis data and code context provided in the user's prompt
3. **Be Specific**: Reference actual findings, file names, line numbers, and severity levels from the analysis
4. **Stay in Scope**: If asked about something NOT in the provided analysis data, respond with: "I don't have data about that in the current analysis. I can only answer questions about the security findings and code that were analyzed."

When answering:
- For "how many" questions: Give the exact number from the data
- For "what are" questions: List the specific items from the analysis
- For "explain" questions: Reference the actual finding description and remediation
- For code questions: Use the actual code context provided

DO NOT:
- Make up or assume information not in the provided data
- Give generic security advice unless specifically asked
- Provide long explanations when a short answer suffices

Your goal: Help users quickly understand their specific security analysis results."""

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
                    prompt += f"\n\nStatic analysis found {
                        len(static_issues)} potential issues:\n"
                    for issue in static_issues[:3]:  # Top 3
                        prompt += f"- {issue.get('issue_text',
                                                 issue.get('message', 'Unknown'))}\n"

            # Add similar vulnerable code examples
            if 'similar_code' in context:
                similar = context['similar_code']
                if similar:
                    prompt += "\n\nSimilar code patterns have been flagged before. Pay special attention to similar patterns.\n"

        prompt += "\n\nProvide a detailed security analysis."

        return prompt
