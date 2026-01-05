"""
Refactor Agent

Specialized LLM agent for code refactoring suggestions
"""

import logging
from typing import Dict, Any, Optional
from .base_agent import BaseAgent

logger = logging.getLogger(__name__)


class RefactorAgent(BaseAgent):
    """LLM agent specialized in refactoring suggestions"""
    
    def __init__(self, provider: str = None, model: str = None):
        super().__init__(provider, model)
        self.system_prompt = """You are an expert software engineer specializing in code refactoring and clean code practices.
Your task is to identify code smells and suggest refactorings to improve code quality.

Focus on:
- Code smells (Long Method, God Class, Duplicate Code, etc.)
- SOLID principles violations
- Design pattern opportunities
- Code readability and maintainability
- Performance optimizations
- Naming conventions

Provide:
1. Identified code smells or issues
2. Why they are problematic
3. Specific refactoring suggestions with code examples
4. Expected benefits of the refactoring

Be constructive and provide clear, actionable advice."""
    
    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze code for refactoring opportunities
        
        Args:
            code: Code snippet to analyze
            context: Additional context (metrics, similar code, etc.)
            
        Returns:
            Refactoring suggestions
        """
        prompt = self.build_prompt(code, context)
        response = self.generate(prompt, self.system_prompt)
        
        if response:
            return {
                'agent': 'RefactorAgent',
                'analysis': response,
                'code_analyzed': code[:200] + '...' if len(code) > 200 else code
            }
        else:
            return {
                'agent': 'RefactorAgent',
                'error': 'Failed to generate analysis'
            }
    
    def build_prompt(self, code: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Build refactoring analysis prompt"""
        prompt = f"""Analyze the following code and suggest refactorings to improve quality:

```
{code}
```
"""
        
        if context:
            # Add code metrics
            if 'metrics' in context:
                metrics = context['metrics']
                prompt += f"\n\nCode Metrics:\n"
                prompt += f"- Lines of Code: {metrics.get('loc', 'N/A')}\n"
                prompt += f"- Cyclomatic Complexity: {metrics.get('complexity', 'N/A')}\n"
                prompt += f"- Functions: {metrics.get('functions', 'N/A')}\n"
                prompt += f"- Classes: {metrics.get('classes', 'N/A')}\n"
                
                if metrics.get('wmc', 0) > 0:
                    prompt += f"- Weighted Methods per Class: {metrics['wmc']}\n"
                if metrics.get('lcom', 0) > 5:
                    prompt += f"- Lack of Cohesion (LCOM): {metrics['lcom']} (high - consider splitting class)\n"
            
            # Add linter issues
            if 'linter_issues' in context:
                issues = context['linter_issues']
                if issues:
                    prompt += f"\n\nLinter found {len(issues)} code quality issues. Consider addressing these in your refactoring.\n"
        
        prompt += "\n\nProvide specific refactoring suggestions with code examples."
        
        return prompt
