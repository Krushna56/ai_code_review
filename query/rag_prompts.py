"""
RAG Prompt Templates

Specialized prompts for different security analysis scenarios.
"""

from typing import Dict, Any, List, Optional


class RAGPromptTemplates:
    """Collection of RAG prompt templates for security analysis"""

    @staticmethod
    def hardcoded_secrets_prompt(code_chunks: List[Dict[str, Any]],
                                 query: str) -> str:
        """Prompt for hardcoded secrets analysis"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a security analyst reviewing code for hardcoded secrets and credentials.

**User Question**: {query}

**Code to Analyze**:
{context}

**Your Task**:
1. Identify any hardcoded secrets, API keys, passwords, or tokens
2. For each finding, specify:
   - Exact location (file and line number)
   - Type of secret (API key, password, token, etc.)
   - Severity (Critical/High/Medium/Low)
   - Why it's a security risk
   - Recommended fix (environment variables, secret manager, etc.)

3. If no secrets are found, clearly state that

**Format your response as**:
- **Summary**: Brief overview of findings
- **Detailed Findings**: List each secret with location and recommendations
- **Best Practices**: General advice for secret management

Be specific and cite exact file locations and line numbers from the code provided above."""

    @staticmethod
    def sql_injection_prompt(code_chunks: List[Dict[str, Any]],
                             query: str) -> str:
        """Prompt for SQL injection analysis"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a security expert analyzing code for SQL injection vulnerabilities.

**User Question**: {query}

**Code to Analyze**:
{context}

**Your Task**:
1. Examine all SQL query construction patterns
2. Identify potential SQL injection vulnerabilities:
   - String concatenation in SQL queries
   - Missing parameterized queries
   - Unsafe use of user input
   - Dynamic query building without sanitization

3. For each vulnerability, provide:
   - Location (file:line)
   - Vulnerable code snippet
   - Attack vector explanation
   - Severity assessment
   - Secure code example using parameterized queries

**Format**:
- **Vulnerability Summary**: Count and severity breakdown
- **Detailed Analysis**: Each vulnerability with secure alternative
- **Mitigation Strategy**: Overall recommendations

Focus on actionable, developer-friendly guidance."""

    @staticmethod
    def xss_vulnerability_prompt(code_chunks: List[Dict[str, Any]],
                                 query: str) -> str:
        """Prompt for XSS vulnerability analysis"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a web security specialist analyzing code for Cross-Site Scripting (XSS) vulnerabilities.

**User Question**: {query}

**Code to Analyze**:
{context}

**Your Task**:
1. Look for:
   - Unescaped HTML rendering (innerHTML, document.write)
   - Client-side eval() usage
   - Unsafe DOM manipulation
   - Missing output encoding

2. Classify findings:
   - **Reflected XSS**: Immediate user input reflection
   - **Stored XSS**: Persisted untrusted data
   - **DOM-based XSS**: Client-side script vulnerabilities

3. For each issue:
   - Location and vulnerable code
   - Attack scenario example
   - Severity (Critical/High/Medium)
   - Fix using proper encoding/escaping

**Response Format**:
- **Executive Summary**: XSS risk overview
- **Findings**: Detailed vulnerability list
- **Remediation**: Specific fixes with code examples"""

    @staticmethod
    def insecure_crypto_prompt(code_chunks: List[Dict[str, Any]],
                               query: str) -> str:
        """Prompt for cryptography analysis"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a cryptography security expert reviewing code for insecure cryptographic practices.

**User Question**: {query}

**Code to Analyze**:
{context}

**Your Task**:
1. Identify weak or broken cryptographic algorithms:
   - MD5, SHA1 (for hashing)
   - DES, RC4 (for encryption)
   - ECB mode usage
   - Weak key sizes

2. Check for:
   - Hardcoded encryption keys
   - Missing salt in password hashing
   - Predictable random number generation
   - SSL/TLS verification disabled

3. Provide:
   - Location and vulnerable usage
   - Why it's insecure (attacks like rainbow tables, birthday attacks)
   - Modern secure alternatives (SHA-256, AES-GCM, bcrypt)
   - Code examples for migration

**Format**:
- **Crypto Issues Found**: Summary table
- **Detailed Analysis**: Each issue with remediation
- **Modern Best Practices**: Recommended cryptographic stack"""

    @staticmethod
    def location_finder_prompt(code_chunks: List[Dict[str, Any]],
                               query: str) -> str:
        """Prompt for locating specific implementations"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a code navigation assistant helping locate specific implementations.

**User Question**: {query}

**Relevant Code**:
{context}

**Your Task**:
1. Identify where the requested functionality is implemented
2. For each relevant code chunk:
   - File and line range
   - Class/function name
   - Brief description of what it does
   - How it relates to the question

3. If the implementation spans multiple files, explain the flow

4. Highlight any security concerns in the implementation

**Format**:
- **Primary Location**: Main implementation file and function
- **Related Components**: Other files/functions involved
- **Implementation Notes**: Key details about how it works
- **Security Observations**: Any security-relevant patterns (if applicable)"""

    @staticmethod
    def general_security_prompt(code_chunks: List[Dict[str, Any]],
                                query: str) -> str:
        """General security analysis prompt"""
        context = RAGPromptTemplates._format_code_context(code_chunks)

        return f"""You are a senior security engineer conducting a comprehensive code security review.

**User Question**: {query}

**Code to Review**:
{context}

**Your Task**:
1. Analyze the code for security vulnerabilities including but not limited to:
   - OWASP Top 10 issues
   - Authentication/authorization flaws
   - Input validation problems
   - Insecure data handling
   - Configuration issues

2. For each finding:
   - Vulnerability type and OWASP category
   - Location (file:lines)
   - Severity (Critical/High/Medium/Low)
   - Exploitation scenario
   - Remediation guidance with code examples

3. Provide prioritized recommendations

**Response Format**:
- **Security Overview**: High-level summary
- **Critical Issues**: Must-fix vulnerabilities
- **High/Medium Issues**: Important findings
- **Best Practices**: General security improvements
- **Implementation Roadmap**: Prioritized fix order"""

    @staticmethod
    def _format_code_context(code_chunks: List[Dict[str, Any]]) -> str:
        """Format code chunks into readable context"""
        formatted = []

        for i, chunk in enumerate(code_chunks, 1):
            file_loc = f"{chunk.get('file', 'Unknown')}:{chunk.get(
                'start_line', '?')}-{chunk.get('end_line', '?')}"
            chunk_type = chunk.get('type', 'code')
            name = chunk.get('name', 'N/A')
            score = chunk.get('score', 0)

            formatted.append(f"""
### Code Chunk {i} (Relevance: {score:.2f})
**File**: `{file_loc}`
**Type**: {chunk_type}
**Name**: {name}

```{chunk.get('language', 'text')}
{chunk.get('code', 'No code available')}
```
""")

        return "\n".join(formatted)

    @staticmethod
    def get_prompt_for_intent(intent: str, code_chunks: List[Dict[str, Any]],
                              query: str) -> str:
        """
        Get appropriate prompt template based on intent

        Args:
            intent: Detected query intent
            code_chunks: Retrieved code chunks
            query: User's question

        Returns:
            Formatted prompt
        """
        prompt_map = {
            'hardcoded_secrets': RAGPromptTemplates.hardcoded_secrets_prompt,
            'sql_injection': RAGPromptTemplates.sql_injection_prompt,
            'xss': RAGPromptTemplates.xss_vulnerability_prompt,
            'pattern': RAGPromptTemplates.insecure_crypto_prompt,  # Can be refined
            'location': RAGPromptTemplates.location_finder_prompt,
            'general': RAGPromptTemplates.general_security_prompt,
        }

        prompt_func = prompt_map.get(
            intent, RAGPromptTemplates.general_security_prompt)
        return prompt_func(code_chunks, query)
