from google import genai
from google.genai import types
from config import Config
import json


class Summarizer:
    """AI-powered summarization using Google Gemini (NEW API)"""

    def __init__(self):
        """Initialize Gemini API"""
        if not Config.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY not found in environment variables")

        # Initialize the new client
        self.client = genai.Client(api_key=Config.GEMINI_API_KEY)
        self.model_name = Config.GEMINI_MODEL

    def extract_key_elements(self, text):
        """
        Extract key elements from document text

        Returns:
            list: List of key elements/topics
        """
        prompt = f"""Analyze the following document and extract the most important key elements, topics, and concepts.

Return ONLY a JSON array of strings, with up to {Config.MAX_KEY_ELEMENTS} key elements. Each element should be concise (2-5 words).

Example format: ["Machine Learning", "Data Processing", "Neural Networks"]

Document:
{text[:8000]}

JSON array of key elements:"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            result_text = response.text.strip()

            # Clean up the response to get valid JSON
            if result_text.startswith('```'):
                # Remove markdown code blocks
                result_text = result_text.split('```')[1]
                if result_text.startswith('json'):
                    result_text = result_text[4:]

            result_text = result_text.strip()

            # Parse JSON
            key_elements = json.loads(result_text)

            # Ensure we have a list and limit to MAX_KEY_ELEMENTS
            if isinstance(key_elements, list):
                return key_elements[:Config.MAX_KEY_ELEMENTS]
            else:
                return []

        except Exception as e:
            print(f"Error extracting key elements: {str(e)}")
            # Fallback: extract simple keywords
            return self._extract_simple_keywords(text)

    def _extract_simple_keywords(self, text):
        """Fallback method to extract simple keywords"""
        # Simple keyword extraction as fallback
        words = text.split()[:500]
        return ["Document Analysis", "Content Summary", "Key Information"]

    def extract_legal_loopholes(self, text):
        """
        Extract loopholes, conflicts, and legal gaps from legal documents
        Returns dict with conflicts, restrictions, and issues
        """
        prompt = f"""Analyze this legal document and identify:

1. **Conflicting Clauses**: Find sections that contradict each other
2. **Restrictive vs Permissive**: Identify where one clause restricts but another allows
3. **Legal Gaps**: Find missing protections or unclear terms
4. **Law Conflicts**: Note any laws/sections that conflict with each other

Format your response as JSON with this structure:
{{
    "conflicts": [
        {{
            "issue": "Brief description of conflict",
            "clause_a": "First conflicting clause reference",
            "clause_b": "Second conflicting clause reference",
            "explanation": "One line explanation of the conflict"
        }}
    ],
    "loopholes": [
        {{
            "issue": "Description of loophole",
            "location": "Where it appears",
            "risk": "Potential risk in one line"
        }}
    ]
}}

Document:
{text[:10000]}

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
            legal_analysis = json.loads(result_text)

            return legal_analysis

        except Exception as e:
            print(f"Error extracting legal loopholes: {str(e)}")
            return {"conflicts": [], "loopholes": []}

    def extract_law_references(self, text):
        """
        Extract referenced laws/sections and provide simple explanations
        Returns list of laws with one-line explanations
        """
        prompt = f"""Extract all law references, sections, and acts mentioned in this document.
For each law, provide a simple one-line explanation.

Format as JSON array:
[
    {{
        "reference": "Section 10(a) of Contract Act",
        "explanation": "Simple one-line explanation of what this law means"
    }}
]

Keep explanations VERY simple and in plain language.

Document:
{text[:10000]}

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
            law_refs = json.loads(result_text)

            # Limit to 10 most important laws
            if isinstance(law_refs, list):
                return law_refs[:10]
            return []

        except Exception as e:
            print(f"Error extracting law references: {str(e)}")
            return []

    def generate_summary(self, text, page_count, requested_lines=None, document_type='general'):
        """
        Generate summary based on document size and type

        Args:
            text: Document text content
            page_count: Number of pages in document
            requested_lines: User-requested number of summary lines (optional)
            document_type: Type of document for specialized analysis

        Returns:
            str: Generated summary
        """
        # Calculate minimum lines based on document size
        if page_count == 1:
            min_lines = Config.MIN_SUMMARY_LINES
        else:
            # Minimum: 2 lines per page (to avoid too short summaries for large docs)
            min_lines = max(Config.MIN_SUMMARY_LINES, page_count * 2)

        # If user specified lines, use it (but enforce minimum)
        if requested_lines:
            target_lines = max(min_lines, requested_lines)
        else:
            # Default: 4 lines per page
            target_lines = page_count * Config.DEFAULT_LINES_PER_PAGE
            if page_count == 1:
                target_lines = Config.MIN_SUMMARY_LINES
            elif page_count <= 3:
                target_lines = page_count * 3

        # Specialized prompts based on document type
        type_specific_instructions = self._get_type_specific_instructions(
            document_type)

        prompt = f"""You are an expert document summarizer specializing in {Config.DOCUMENT_TYPES.get(document_type, 'General Document')} analysis.

Create a concise summary of the following document.

Requirements:
- The summary should be EXACTLY {target_lines} lines long
- Each line should be a complete, meaningful sentence
- Focus on the most important information
- Be clear, concise, and informative
- Do NOT use bullet points, just numbered lines
- Do NOT include introductory phrases like "This document discusses..."

{type_specific_instructions}

Document ({page_count} page{'s' if page_count != 1 else ''}):
{text[:15000]}

Summary ({target_lines} lines):"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            summary = response.text.strip()

            # Ensure the summary doesn't have extra formatting
            lines = [line.strip()
                     for line in summary.split('\n') if line.strip()]

            # Remove numbering if present
            cleaned_lines = []
            for line in lines:
                # Remove leading numbers and dots
                if line and line[0].isdigit():
                    line = line.lstrip('0123456789.-) ').strip()
                if line:
                    cleaned_lines.append(line)

            # Join and return
            return ' '.join(cleaned_lines[:target_lines])

        except Exception as e:
            raise Exception(f"Error generating summary: {str(e)}")

    def _get_type_specific_instructions(self, document_type):
        """Get specialized instructions based on document type"""
        instructions = {
            'legal': """
Special Focus for Legal Documents:
- Identify key legal issues, parties involved, and outcomes
- Highlight important dates, deadlines, and jurisdictions
- Note critical clauses, obligations, and rights
- Mention case citations or statutes if present""",

            'code': """
Special Focus for Code/Technical Files:
- Describe the main purpose and functionality
- Identify key functions, classes, or modules
- Note technologies, frameworks, or libraries used
- Mention any critical algorithms or design patterns""",

            'book': """
Special Focus for Books/Novels:
- Summarize the main plot or narrative arc
- Identify key characters and their roles
- Describe the theme, setting, and genre
- Note the writing style and tone""",

            'letter': """
Special Focus for Letters/Emails:
- Identify sender, recipient, and purpose
- Summarize key requests, information, or actions needed
- Note tone (formal/informal) and urgency
- Highlight important dates or deadlines""",

            'research': """
Special Focus for Research Papers:
- State research question/hypothesis
- Summarize methodology and key findings
- Note conclusions and implications
- Mention sample size, data sources, or limitations"""
        }

        return instructions.get(document_type, "")

    def generate_detailed_overview(self, text, document_type='general'):
        """
        Generate a detailed 6-7 line overview of what happened in the document
        This provides more context than the quick summary

        Args:
            text: Document text content
            document_type: Type of document for specialized context

        Returns:
            str: Detailed overview (6-7 lines)
        """
        target_lines = Config.DETAILED_OVERVIEW_LINES

        # Type-specific overview prompts
        type_context = {
            'book': "Tell the story from beginning to end, including the main plot developments.",
            'research': "Explain the research journey from question to conclusion.",
            'legal': "Walk through the legal matter from initial situation to resolution.",
            'code': "Explain the code's architecture and how different parts work together.",
            'letter': "Describe the full context and purpose of the communication.",
            'general': "Explain the complete context and main points of the document."
        }

        context_instruction = type_context.get(
            document_type, type_context['general'])

        prompt = f"""Create a detailed overview explaining what actually happens in this {Config.DOCUMENT_TYPES.get(document_type, 'document')}.

{context_instruction}

Requirements:
- Write EXACTLY {target_lines} lines
- Each line should be a complete, flowing sentence
- Provide a narrative that gives full context
- Use clear, engaging language
- Focus on the key events/points in chronological or logical order
- Do NOT use bullet points or numbers

Document excerpt:
{text[:15000]}

Detailed Overview ({target_lines} lines):"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            overview = response.text.strip()

            # Clean formatting
            lines = [line.strip()
                     for line in overview.split('\n') if line.strip()]

            # Remove numbering if present
            cleaned_lines = []
            for line in lines:
                if line and line[0].isdigit():
                    line = line.lstrip('0123456789.-) ').strip()
                if line:
                    cleaned_lines.append(line)

            return ' '.join(cleaned_lines[:target_lines])

        except Exception as e:
            print(f"Error generating detailed overview: {str(e)}")
            return None

    def analyze_document(self, text, page_count, requested_lines=None, document_type='general', include_overview=True):
        """
        Complete document analysis: extract key elements and generate summary

        Args:
            requested_lines: Optional user-specified number of summary lines
            document_type: Type of document for specialized analysis
            include_overview: Whether to include detailed overview (default: True)

        Returns:
            dict: Contains 'summary', 'key_elements', 'overview', and 'minimum_lines'
        """
        try:
            # Calculate minimum recommended lines
            if page_count == 1:
                min_lines = Config.MIN_SUMMARY_LINES
            else:
                min_lines = max(Config.MIN_SUMMARY_LINES, page_count * 2)

            # Generate summary with document type
            summary = self.generate_summary(
                text, page_count, requested_lines, document_type)

            # Generate detailed overview if requested
            detailed_overview = None
            if include_overview:
                detailed_overview = self.generate_detailed_overview(
                    text, document_type)

            # Extract key elements
            key_elements = self.extract_key_elements(text)

            # Perform legal-specific analysis if document type is legal
            legal_analysis = None
            law_references = None
            if document_type == 'legal':
                print("Performing enhanced legal analysis...")
                legal_analysis = self.extract_legal_loopholes(text)
                law_references = self.extract_law_references(text)

            result = {
                'summary': summary,
                'key_elements': key_elements,
                'page_count': page_count,
                'minimum_lines': min_lines,
                'actual_lines': requested_lines if requested_lines else page_count * Config.DEFAULT_LINES_PER_PAGE,
                'document_type': document_type
            }

            # Add overview if generated
            if detailed_overview:
                result['detailed_overview'] = detailed_overview

            # Add legal-specific data if available
            if legal_analysis:
                result['legal_analysis'] = legal_analysis
            if law_references:
                result['law_references'] = law_references

            return result

        except Exception as e:
            raise Exception(f"Error analyzing document: {str(e)}")
