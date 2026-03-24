"""
Report Agent - OpenAI-powered report writing, data extraction, and image analysis.

This agent is exclusively powered by OpenAI GPT-4 (via create_report_client).
It handles:
  - Structured security report generation
  - Code data extraction (functions, classes, imports, secrets)
  - Image / screenshot analysis (GPT-4V)
"""

import logging
import json
import base64
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportAgent:
    """OpenAI-powered agent for report writing, data extraction, and image analysis."""

    SYSTEM_PROMPT = """You are a senior security engineer writing professional security reports.
Your reports are clear, structured, executive-ready, and contain:
- An executive summary with risk score
- Prioritized findings with CVSS scores where applicable
- Actionable remediation steps
- Code examples for fixes
Always respond in valid JSON when asked for structured data."""

    def __init__(self):
        from llm_agents.llm_factory import LLMClientFactory
        try:
            self.client = LLMClientFactory.create_report_client()
            logger.info(f"ReportAgent initialized with provider: {self.client.provider}")
        except Exception as e:
            logger.error(f"ReportAgent: failed to initialize LLM client: {e}")
            self.client = None

    # ──────────────────────────────────────────────────────────────────────
    # Report Generation
    # ──────────────────────────────────────────────────────────────────────

    def generate_report(self, findings: List[Dict[str, Any]], summary: Dict[str, Any] = None) -> str:
        """
        Generate a professional security report from analysis findings.

        Args:
            findings: List of security/bounty findings dicts
            summary: Optional executive summary dict

        Returns:
            Markdown-formatted report string
        """
        if not self.client:
            return self._fallback_report(findings, summary)

        try:
            findings_text = json.dumps(findings[:20], indent=2)  # Cap at 20 findings
            summary_text = json.dumps(summary or {}, indent=2)

            prompt = f"""Write a professional security report for the following findings.

## Executive Summary Data:
{summary_text}

## Security Findings (top 20):
{findings_text}

Format your response as a Markdown report with:
1. Executive Summary (2-3 sentences, risk level, total findings)
2. Critical & High Findings (detailed with file paths and fix suggestions)
3. Medium & Low Findings (brief list)
4. Remediation Priority Matrix
5. Next Steps

Be concise but comprehensive."""

            result = self.client.complete(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                temperature=0.2,
                max_tokens=3000
            )
            return result or self._fallback_report(findings, summary)

        except Exception as e:
            logger.error(f"ReportAgent.generate_report error: {e}")
            return self._fallback_report(findings, summary)

    # ──────────────────────────────────────────────────────────────────────
    # Code Data Extraction
    # ──────────────────────────────────────────────────────────────────────

    def extract_data_from_code(self, code: str, filename: str = "unknown") -> Dict[str, Any]:
        """
        Extract structured data from code: functions, classes, imports, secrets, endpoints.

        Args:
            code: Source code string
            filename: Filename for context

        Returns:
            Dict with extracted data fields
        """
        if not self.client:
            return {"error": "Report agent not available", "filename": filename}

        try:
            prompt = f"""Analyze this code and extract structured data as JSON.

File: {filename}

```
{code[:4000]}
```

Return ONLY a JSON object with these fields:
{{
  "functions": ["list of function names"],
  "classes": ["list of class names"],
  "imports": ["list of imported modules"],
  "endpoints": ["list of API endpoints/routes found"],
  "hardcoded_secrets": ["list of potential hardcoded secrets (redacted)"],
  "dependencies": ["external libraries used"],
  "language": "detected programming language",
  "complexity_notes": "brief note on code complexity"
}}"""

            result = self.client.complete(
                prompt=prompt,
                system_prompt="You are a code analysis tool. Respond ONLY with valid JSON, no other text.",
                temperature=0.1,
                max_tokens=1500
            )

            if result:
                # Strip markdown code fences if present
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("```")[1]
                    if cleaned.startswith("json"):
                        cleaned = cleaned[4:]
                return json.loads(cleaned)
            return {"error": "Empty response", "filename": filename}

        except json.JSONDecodeError as e:
            logger.warning(f"ReportAgent.extract_data_from_code JSON parse error: {e}")
            return {"error": f"JSON parse error: {e}", "filename": filename, "raw": result}
        except Exception as e:
            logger.error(f"ReportAgent.extract_data_from_code error: {e}")
            return {"error": str(e), "filename": filename}

    # ──────────────────────────────────────────────────────────────────────
    # Image Analysis (GPT-4V)
    # ──────────────────────────────────────────────────────────────────────

    def analyze_image(self, image_path: str, question: str = None) -> Dict[str, Any]:
        """
        Analyze a screenshot or image of code using GPT-4V.

        Args:
            image_path: Absolute path to the image file
            question: Optional specific question about the image

        Returns:
            Dict with 'description', 'code_found', 'issues', 'text_extracted'
        """
        if not self.client or self.client.provider != 'openai':
            return {"error": "Image analysis requires OpenAI provider with GPT-4V"}

        try:
            from openai import OpenAI as OpenAISDK
            import config

            image_path = Path(image_path)
            if not image_path.exists():
                return {"error": f"Image file not found: {image_path}"}

            # Encode image to base64
            with open(image_path, "rb") as f:
                image_data = base64.b64encode(f.read()).decode("utf-8")

            # Determine MIME type
            suffix = image_path.suffix.lower()
            mime_map = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                        '.gif': 'image/gif', '.webp': 'image/webp'}
            mime_type = mime_map.get(suffix, 'image/png')

            oai_client = OpenAISDK(api_key=config.OPENAI_API_KEY)

            user_question = question or "Describe this image. If it contains code, extract it and identify any security issues."

            response = oai_client.chat.completions.create(
                model="gpt-4o",
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": user_question},
                        {"type": "image_url", "image_url": {
                            "url": f"data:{mime_type};base64,{image_data}"
                        }}
                    ]
                }],
                max_tokens=1500
            )

            content = response.choices[0].message.content
            return {
                "description": content,
                "image_path": str(image_path),
                "model_used": "gpt-4o",
                "question": user_question
            }

        except Exception as e:
            logger.error(f"ReportAgent.analyze_image error: {e}")
            return {"error": str(e), "image_path": str(image_path)}

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _fallback_report(self, findings: List[Dict], summary: Dict) -> str:
        """Generate a simple markdown report without LLM."""
        total = len(findings)
        critical = sum(1 for f in findings if f.get('severity', '').upper() == 'CRITICAL')
        high = sum(1 for f in findings if f.get('severity', '').upper() == 'HIGH')

        lines = [
            "# Security Analysis Report",
            "",
            "## Executive Summary",
            f"Total findings: **{total}** | Critical: **{critical}** | High: **{high}**",
            "",
            "## Findings",
        ]
        for i, f in enumerate(findings[:20], 1):
            lines.append(f"### {i}. {f.get('title', 'Unknown')} `[{f.get('severity', 'N/A')}]`")
            lines.append(f"- **File**: `{f.get('file_path', 'N/A')}`")
            if f.get('description'):
                lines.append(f"- **Description**: {f['description']}")
            if f.get('remediation'):
                lines.append(f"- **Fix**: {f['remediation']}")
            lines.append("")

        return "\n".join(lines)
