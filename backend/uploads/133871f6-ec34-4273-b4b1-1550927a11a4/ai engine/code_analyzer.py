from google import genai
from google.genai import types
from config import Config
import json
import re


class CodeAnalyzer:
    """AI-powered code analysis using Google Gemini"""

    def __init__(self):
        """Initialize Gemini API for code analysis"""
        if not Config.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY not found in environment variables")

        self.client = genai.Client(api_key=Config.GEMINI_API_KEY)
        self.model_name = Config.GEMINI_MODEL

    def analyze_logic(self, code, language, filename):
        """
        Extract logic summary explaining what the code does

        Args:
            code: Source code content
            language: Programming language
            filename: Name of the file

        Returns:
            dict: Logic analysis with summary and key points
        """
        prompt = f"""Analyze this {language} code and provide a clear logic summary.

Filename: {filename}

Requirements:
1. Explain WHAT the code does (not HOW it does it)
2. Identify the main purpose and functionality
3. List key operations and algorithms used
4. Note any important edge cases or validations
5. Keep it concise but comprehensive

Code:
{code[:15000]}

Return your analysis as JSON with this structure:
{{
    "main_purpose": "One sentence describing what this code does",
    "key_functionalities": [
        "Functionality 1",
        "Functionality 2",
        "Functionality 3"
    ],
    "algorithms_used": ["Algorithm 1", "Algorithm 2"],
    "logic_flow": "2-3 sentences describing the overall logic flow"
}}

JSON Response:"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            result_text = response.text.strip()

            # Clean JSON response
            if result_text.startswith('```'):
                result_text = result_text.split('```')[1]
                if result_text.startswith('json'):
                    result_text = result_text[4:]

            result_text = result_text.strip()
            logic_analysis = json.loads(result_text)

            return logic_analysis

        except Exception as e:
            print(f"Error analyzing code logic: {str(e)}")
            return {
                "main_purpose": "Code analysis unavailable",
                "key_functionalities": [],
                "algorithms_used": [],
                "logic_flow": "Unable to analyze code logic"
            }

    def analyze_architecture(self, code, language, filename):
        """
        Generate architecture description of code structure

        Args:
            code: Source code content
            language: Programming language
            filename: Name of the file

        Returns:
            dict: Architecture analysis with components and structure
        """
        prompt = f"""Analyze the architecture and structure of this {language} code.

Filename: {filename}

Identify:
1. **Code Organization**: How the code is structured (classes, functions, modules)
2. **Components**: Main components and their responsibilities
3. **Dependencies**: External libraries, frameworks, or modules used
4. **Design Patterns**: Any recognizable design patterns
5. **Data Flow**: How data moves through the code

Code:
{code[:15000]}

Return JSON with this structure:
{{
    "structure_type": "Type of code organization (e.g., 'Object-Oriented', 'Functional', 'Procedural')",
    "components": [
        {{
            "name": "Component/Class/Module name",
            "type": "class/function/module",
            "purpose": "What it does",
            "dependencies": ["dependency1", "dependency2"]
        }}
    ],
    "external_dependencies": ["library1", "library2"],
    "design_patterns": ["pattern1", "pattern2"],
    "architecture_summary": "2-3 sentences describing the overall architecture"
}}

JSON Response:"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            result_text = response.text.strip()

            # Clean JSON response
            if result_text.startswith('```'):
                result_text = result_text.split('```')[1]
                if result_text.startswith('json'):
                    result_text = result_text[4:]

            result_text = result_text.strip()
            arch_analysis = json.loads(result_text)

            return arch_analysis

        except Exception as e:
            print(f"Error analyzing architecture: {str(e)}")
            return {
                "structure_type": "Unknown",
                "components": [],
                "external_dependencies": [],
                "design_patterns": [],
                "architecture_summary": "Unable to analyze architecture"
            }

    def generate_diagram(self, code, language, filename):
        """
        Generate mermaid diagram showing code flow/structure

        Args:
            code: Source code content
            language: Programming language
            filename: Name of the file

        Returns:
            str: Mermaid diagram code
        """
        prompt = f"""Create a mermaid diagram to visualize this {language} code structure.

Filename: {filename}

Instructions:
1. Choose the MOST APPROPRIATE diagram type:
   - Use 'flowchart TD' for procedural/functional code showing execution flow
   - Use 'classDiagram' for object-oriented code showing class relationships
   - Use 'graph TD' for simple module/component relationships
2. Keep it clear and concise (max 15 nodes)
3. Show main components, functions, or classes
4. Indicate relationships and flow direction
5. Use meaningful node labels

Code:
{code[:10000]}

Return ONLY the mermaid diagram code (no explanation, no markdown blocks, just the raw mermaid code).
Start directly with the diagram type (e.g., 'flowchart TD' or 'classDiagram').

Mermaid Diagram:"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            diagram = response.text.strip()

            # Clean up response
            if diagram.startswith('```'):
                # Remove markdown code blocks
                parts = diagram.split('```')
                if len(parts) >= 2:
                    diagram = parts[1]
                    if diagram.startswith('mermaid'):
                        diagram = diagram[7:]

            diagram = diagram.strip()

            # Validate it starts with a known mermaid diagram type
            valid_starts = ['flowchart', 'graph',
                            'classDiagram', 'sequenceDiagram', 'stateDiagram']
            if not any(diagram.startswith(start) for start in valid_starts):
                # Default to flowchart
                diagram = "flowchart TD\n    Start[Code Analysis]\n    Start --> End[Diagram Generation Failed]"

            return diagram

        except Exception as e:
            print(f"Error generating diagram: {str(e)}")
            return "flowchart TD\n    Start[Code File]\n    Start --> Error[Unable to generate diagram]"

    def extract_code_metrics(self, code, language):
        """
        Extract basic code metrics (lines, functions, classes, etc.)

        Args:
            code: Source code content
            language: Programming language

        Returns:
            dict: Code metrics
        """
        lines = code.split('\n')
        total_lines = len(lines)

        # Count non-empty, non-comment lines (basic heuristic)
        code_lines = 0
        comment_lines = 0
        blank_lines = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                blank_lines += 1
            elif stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                comment_lines += 1
            else:
                code_lines += 1

        # Simple pattern matching for functions and classes
        function_pattern = r'(def |function |func |fn |public |private |protected )[\w]+\s*\('
        class_pattern = r'(class |interface |struct |type )\w+'

        functions = len(re.findall(function_pattern, code))
        classes = len(re.findall(class_pattern, code))

        return {
            'total_lines': total_lines,
            'code_lines': code_lines,
            'comment_lines': comment_lines,
            'blank_lines': blank_lines,
            'functions': functions,
            'classes': classes,
            'language': language
        }

    def analyze_complete(self, code, language, filename):
        """
        Perform complete code analysis combining all analysis types

        Args:
            code: Source code content
            language: Programming language
            filename: Name of the file

        Returns:
            dict: Complete analysis results
        """
        try:
            print(f"Analyzing {language} code: {filename}")

            # Extract metrics
            metrics = self.extract_code_metrics(code, language)

            # Analyze logic
            logic = self.analyze_logic(code, language, filename)

            # Analyze architecture
            architecture = self.analyze_architecture(code, language, filename)

            # Generate diagram
            diagram = self.generate_diagram(code, language, filename)

            return {
                'success': True,
                'filename': filename,
                'language': language,
                'metrics': metrics,
                'logic_summary': logic,
                'architecture': architecture,
                'diagram': diagram
            }

        except Exception as e:
            print(f"Error in complete code analysis: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'filename': filename,
                'language': language
            }
