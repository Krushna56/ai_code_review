"""
Fix Generator

Generates automated fix suggestions and remediation guidance for common security issues.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import re

logger = logging.getLogger(__name__)


class FixGenerator:
    """Generate fix suggestions for security vulnerabilities"""

    # Fix templates for common vulnerability types
    FIX_TEMPLATES = {
        'hardcoded_secret': {
            'difficulty': 'EASY',
            'estimated_time': '5-10 minutes',
            'steps': [
                'Remove the hardcoded secret from the source code',
                'Add the secret to a `.env` file (ensure it\'s in .gitignore)',
                'Load the secret from environment variables',
                'Update deployment configuration to include the environment variable'
            ],
            'references': [
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
                'https://12factor.net/config'
            ]
        },
        'sql_injection': {
            'difficulty': 'MEDIUM',
            'estimated_time': '15-30 minutes',
            'steps': [
                'Replace string concatenation with parameterized queries',
                'Use ORM methods for database operations where possible',
                'Validate and sanitize all user inputs',
                'Apply principle of least privilege to database permissions'
            ],
            'references': [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            ]
        },
        'xss': {
            'difficulty': 'MEDIUM',
            'estimated_time': '10-20 minutes',
            'steps': [
                'HTML-escape all user-supplied data in output',
                'Use Content Security Policy (CSP) headers',
                'Use framework-specific output encoding functions',
                'Validate input on both client and server side'
            ],
            'references': [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
            ]
        },
        'weak_crypto': {
            'difficulty': 'MEDIUM',
            'estimated_time': '20-30 minutes',
            'steps': [
                'Replace weak algorithms with strong alternatives (AES-256-GCM, ChaCha20)',
                'Use cryptographically secure random number generators',
                'Implement proper key management practices',
                'Use bcrypt or Argon2 for password hashing'
            ],
            'references': [
                'https://owasp.org/www-community/vulnerabilities/Using_a_broken_or_risky_cryptographic_algorithm',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
            ]
        },
        'path_traversal': {
            'difficulty': 'MEDIUM',
            'estimated_time': '15-25 minutes',
            'steps': [
                'Use allowlists for file paths',
                'Canonicalize file paths and check against a base directory',
                'Reject paths containing ".." or absolute paths',
                'Use framework-specific path validation functions'
            ],
            'references': [
                'https://owasp.org/www-community/attacks/Path_Traversal',
                'https://cwe.mitre.org/data/definitions/22.html'
            ]
        },
        'insecure_deserialization': {
            'difficulty': 'HARD',
            'estimated_time': '30-60 minutes',
            'steps': [
                'Avoid deserializing untrusted data when possible',
                'Use safe data interchange formats (JSON) instead of native serialization',
                'Implement integrity checks (HMAC) before deserialization',
                'Run deserialization in restricted/sandboxed environments'
            ],
            'references': [
                'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
                'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
            ]
        }
    }

    def generate_fix_suggestion(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate fix suggestion for a security finding

        Args:
            finding: Security finding dictionary
            context: Additional context (framework, language, etc.)

        Returns:
            Fix suggestion with steps, code examples, and references
        """
        finding_type = self._normalize_finding_type(finding.get('type', ''))

        # Get base template
        template = self.FIX_TEMPLATES.get(
            finding_type, self._get_default_template())

        # Generate code example if applicable
        code_example = self._generate_code_example(
            finding, finding_type, context)

        # Build fix suggestion
        fix_suggestion = {
            'finding_id': finding.get('id'),
            'fix_type': 'template',
            'difficulty': template['difficulty'],
            'estimated_time': template['estimated_time'],
            'steps': template['steps'],
            'code_example': code_example,
            'references': template['references']
        }

        # Add CVE-specific remediation if applicable
        if finding.get('cve_id'):
            cve_fix = self._generate_cve_fix(finding)
            if cve_fix:
                fix_suggestion.update(cve_fix)

        return fix_suggestion

    def _normalize_finding_type(self, finding_type: str) -> str:
        """Normalize finding type to template key"""
        # Map various finding type names to template keys
        type_mapping = {
            'secret': 'hardcoded_secret',
            'hardcoded_password': 'hardcoded_secret',
            'hardcoded_key': 'hardcoded_secret',
            'api_key': 'hardcoded_secret',
            'sql': 'sql_injection',
            'sqli': 'sql_injection',
            'cross_site_scripting': 'xss',
            'weak_crypto': 'weak_crypto',
            'weak_hash': 'weak_crypto',
            'md5': 'weak_crypto',
            'sha1': 'weak_crypto',
            'path_traversal': 'path_traversal',
            'directory_traversal': 'path_traversal',
            'deserialize': 'insecure_deserialization',
            'pickle': 'insecure_deserialization'
        }

        normalized = finding_type.lower().replace(' ', '_').replace('-', '_')
        return type_mapping.get(normalized, normalized)

    def _get_default_template(self) -> Dict[str, Any]:
        """Get default template for unknown vulnerability types"""
        return {
            'difficulty': 'MEDIUM',
            'estimated_time': '15-30 minutes',
            'steps': [
                'Review the vulnerability details carefully',
                'Consult framework-specific security documentation',
                'Implement appropriate input validation and output encoding',
                'Test the fix thoroughly'
            ],
            'references': [
                'https://owasp.org/www-project-top-ten/',
                'https://cwe.mitre.org/'
            ]
        }

    def _generate_code_example(
        self,
        finding: Dict[str, Any],
        finding_type: str,
        context: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, str]]:
        """Generate before/after code example"""
        language = context.get('language', 'python') if context else 'python'

        if finding_type == 'hardcoded_secret':
            return self._generate_secret_fix_example(finding, language)
        elif finding_type == 'sql_injection':
            return self._generate_sql_injection_fix_example(language)
        elif finding_type == 'xss':
            return self._generate_xss_fix_example(language)
        elif finding_type == 'weak_crypto':
            return self._generate_crypto_fix_example(language)

        return None

    def _generate_secret_fix_example(self, finding: Dict[str, Any], language: str) -> Dict[str, str]:
        """Generate example for hardcoded secret fix"""
        if language == 'python':
            before = """# ❌ Hardcoded secret
API_KEY = "sk-1234567890abcdef"  
DATABASE_PASSWORD = "mysecretpassword"
"""
            after = """# ✅ Use environment variables
import os

API_KEY = os.getenv("API_KEY")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")

# Add to .env file (ensure it's in .gitignore):
# API_KEY=sk-1234567890abcdef
# DATABASE_PASSWORD=mysecretpassword
"""
        elif language in ['javascript', 'typescript']:
            before = """// ❌ Hardcoded secret
const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "mysecretpassword";
"""
            after = """// ✅ Use environment variables
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// Add to .env file:
// API_KEY=sk-1234567890abcdef
// DB_PASSWORD=mysecretpassword
"""
        elif language == 'java':
            before = """// ❌ Hardcoded secret
String API_KEY = "sk-1234567890abcdef";
String DB_PASSWORD = "mysecretpassword";
"""
            after = """// ✅ Use environment variables
String API_KEY = System.getenv("API_KEY");
String DB_PASSWORD = System.getenv("DB_PASSWORD");

// Or use application.properties:
// api.key=${API_KEY}
// db.password=${DB_PASSWORD}
"""
        else:
            before = "# Hardcoded secret detected"
            after = "# Use environment variables or secrets manager"

        return {'before': before, 'after': after, 'language': language}

    def _generate_sql_injection_fix_example(self, language: str) -> Dict[str, str]:
        """Generate example for SQL injection fix"""
        if language == 'python':
            before = """# ❌ Vulnerable to SQL injection
query = f"SELECT * FROM users WHERE username = '{user_input}'"
cursor.execute(query)
"""
            after = """# ✅ Use parameterized query
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (user_input,))

# Or use ORM
user = User.query.filter_by(username=user_input).first()
"""
        elif language in ['javascript', 'typescript']:
            before = """// ❌ Vulnerable to SQL injection
const query = `SELECT * FROM users WHERE username = '${userInput}'`;
db.query(query);
"""
            after = """// ✅ Use parameterized query
const query = 'SELECT * FROM users WHERE username = ?';
db.query(query, [userInput]);

// Or use ORM
const user = await User.findOne({ where: { username: userInput } });
"""
        elif language == 'java':
            before = """// ❌ Vulnerable to SQL injection
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
"""
            after = """// ✅ Use PreparedStatement
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();
"""
        else:
            before = "# String concatenation in SQL query"
            after = "# Use parameterized queries or ORM"

        return {'before': before, 'after': after, 'language': language}

    def _generate_xss_fix_example(self, language: str) -> Dict[str, str]:
        """Generate example for XSS fix"""
        if language == 'python':
            before = """# ❌ Unescaped output (Flask/Jinja2)
return f"<div>Hello {user_input}</div>"
"""
            after = """# ✅ Use template escaping
from markupsafe import escape
return f"<div>Hello {escape(user_input)}</div>"

# Or use Jinja2 templates (auto-escaping enabled)
# {{ user_input }}  - automatically escaped
"""
        elif language in ['javascript', 'typescript']:
            before = """// ❌ Dangerous innerHTML
element.innerHTML = userInput;
"""
            after = """// ✅ Use textContent or sanitize
element.textContent = userInput;

// Or use DOMPurify for HTML
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
"""
        else:
            before = "# Direct output of user input"
            after = "# Use output encoding/escaping"

        return {'before': before, 'after': after, 'language': language}

    def _generate_crypto_fix_example(self, language: str) -> Dict[str, str]:
        """Generate example for weak cryptography fix"""
        if language == 'python':
            before = """# ❌ Weak cryptography
import hashlib
import md5

# Weak hash
password_hash = hashlib.md5(password.encode()).hexdigest()

# Weak encryption
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)
"""
            after = """# ✅ Strong cryptography
import bcrypt
from cryptography.fernet import Fernet

# Strong password hashing
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Strong encryption (AES-256)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
"""
        elif language == 'java':
            before = """// ❌ Weak cryptography
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());
"""
            after = """// ✅ Strong cryptography
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);
"""
        else:
            before = "# Weak algorithm (MD5, DES, SHA-1)"
            after = "# Use strong algorithms (bcrypt, AES-256, SHA-256+)"

        return {'before': before, 'after': after, 'language': language}

    def _generate_cve_fix(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate CVE-specific remediation"""
        fixed_versions = finding.get('fixed_versions', [])
        package_name = finding.get('package_name')
        ecosystem = finding.get('ecosystem', 'unknown')

        if not fixed_versions or not package_name:
            return None

        # Generate upgrade command
        upgrade_cmd = self._generate_upgrade_command(
            ecosystem, package_name, fixed_versions[0]
        )

        return {
            'cve_remediation': {
                'action': f"Upgrade {package_name} to version {fixed_versions[0]} or later",
                'upgrade_command': upgrade_cmd,
                'fixed_versions': fixed_versions,
                'severity': finding.get('severity'),
                'references': finding.get('references', [])
            }
        }

    def _generate_upgrade_command(
        self,
        ecosystem: str,
        package: str,
        version: str
    ) -> str:
        """Generate package manager-specific upgrade command"""
        ecosystem = ecosystem.lower()

        if ecosystem == 'pypi':
            return f"pip install {package}=={version}"
        elif ecosystem == 'npm':
            return f"npm install {package}@{version}"
        elif ecosystem == 'maven':
            return f"Update pom.xml: <version>{version}</version>"
        elif ecosystem == 'gradle':
            return f"Update build.gradle: implementation '{package}:{version}'"
        else:
            return f"Upgrade {package} to {version}"

    def generate_code_diff(
        self,
        before_code: str,
        after_code: str,
        language: str = 'python'
    ) -> str:
        """
        Generate unified diff format

        Args:
            before_code: Vulnerable code
            after_code: Fixed code
            language: Programming language for syntax

        Returns:
            Diff string
        """
        from difflib import unified_diff

        before_lines = before_code.splitlines(keepends=True)
        after_lines = after_code.splitlines(keepends=True)

        diff = unified_diff(
            before_lines,
            after_lines,
            fromfile='before (vulnerable)',
            tofile='after (fixed)',
            lineterm=''
        )

        return '\n'.join(diff)

    def batch_generate_fixes(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate fixes for multiple findings

        Args:
            findings: List of security findings
            context: Shared context

        Returns:
            List of fix suggestions
        """
        fixes = []

        for finding in findings:
            try:
                fix = self.generate_fix_suggestion(finding, context)
                fixes.append(fix)
            except Exception as e:
                logger.error(f"Error generating fix for {
                             finding.get('id')}: {e}")
                fixes.append({
                    'finding_id': finding.get('id'),
                    'error': str(e)
                })

        return fixes


def generate_fix(finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to generate a fix suggestion

    Args:
        finding: Security finding
        context: Additional context

    Returns:
        Fix suggestion
    """
    generator = FixGenerator()
    return generator.generate_fix_suggestion(finding, context)
