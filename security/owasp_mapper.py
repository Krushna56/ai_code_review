"""
OWASP Mapper

Map vulnerabilities and security issues to OWASP Top 10 2021 categories.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class OWASPCategory:
    """OWASP Top 10 2021 category information"""
    id: str
    name: str
    description: str
    reference_url: str


class OWASPMapper:
    """Map security issues to OWASP Top 10 2021 categories"""
    
    # OWASP Top 10 2021 Categories
    OWASP_CATEGORIES = {
        "A01:2021": OWASPCategory(
            id="A01:2021",
            name="Broken Access Control",
            description="Failures in access control, allowing unauthorized access to resources",
            reference_url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ),
        "A02:2021": OWASPCategory(
            id="A02:2021",
            name="Cryptographic Failures",
            description="Failures related to cryptography, leading to sensitive data exposure",
            reference_url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        ),
        "A03:2021": OWASPCategory(
            id="A03:2021",
            name="Injection",
            description="Injection flaws such as SQL, NoSQL, OS, and LDAP injection",
            reference_url="https://owasp.org/Top10/A03_2021-Injection/"
        ),
        "A04:2021": OWASPCategory(
            id="A04:2021",
            name="Insecure Design",
            description="Missing or ineffective control design",
            reference_url="https://owasp.org/Top10/A04_2021-Insecure_Design/"
        ),
        "A05:2021": OWASPCategory(
            id="A05:2021",
            name="Security Misconfiguration",
            description="Security misconfigurations at any level of the application stack",
            reference_url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ),
        "A06:2021": OWASPCategory(
            id="A06:2021",
            name="Vulnerable and Outdated Components",
            description="Using vulnerable, outdated, or unsupported components",
            reference_url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        ),
        "A07:2021": OWASPCategory(
            id="A07:2021",
            name="Identification and Authentication Failures",
            description="Authentication and session management implementation flaws",
            reference_url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        ),
        "A08:2021": OWASPCategory(
            id="A08:2021",
            name="Software and Data Integrity Failures",
            description="Code and infrastructure failures that don't protect against integrity violations",
            reference_url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        ),
        "A09:2021": OWASPCategory(
            id="A09:2021",
            name="Security Logging and Monitoring Failures",
            description="Insufficient logging, monitoring, and incident response",
            reference_url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        ),
        "A10:2021": OWASPCategory(
            id="A10:2021",
            name="Server-Side Request Forgery (SSRF)",
            description="Fetching remote resources without validating user-supplied URLs",
            reference_url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        )
    }
    
    # Comprehensive CWE to OWASP mapping
    CWE_OWASP_MAPPING = {
        # A01:2021 - Broken Access Control
        "CWE-22": "A01:2021",   # Path Traversal
        "CWE-23": "A01:2021",   # Relative Path Traversal
        "CWE-35": "A01:2021",   # Path Traversal
        "CWE-59": "A01:2021",   # Link Following
        "CWE-200": "A01:2021",  # Information Exposure
        "CWE-201": "A01:2021",  # Information Exposure Through Sent Data
        "CWE-219": "A01:2021",  # Storage of File with Sensitive Data
        "CWE-264": "A01:2021",  # Permissions, Privileges, and Access Controls
        "CWE-275": "A01:2021",  # Permission Issues
        "CWE-284": "A01:2021",  # Improper Access Control
        "CWE-285": "A01:2021",  # Improper Authorization
        "CWE-352": "A01:2021",  # Cross-Site Request Forgery (CSRF)
        "CWE-359": "A01:2021",  # Exposure of Private Information
        "CWE-377": "A01:2021",  # Insecure Temporary File
        "CWE-425": "A01:2021",  # Direct Request
        "CWE-441": "A01:2021",  # Unintended Proxy or Intermediary
        "CWE-497": "A01:2021",  # Exposure of System Data
        "CWE-538": "A01:2021",  # File and Directory Information Exposure
        "CWE-540": "A01:2021",  # Information Exposure Through Source Code
        "CWE-548": "A01:2021",  # Information Exposure Through Directory Listing
        "CWE-552": "A01:2021",  # Files or Directories Accessible to External Parties
        "CWE-566": "A01:2021",  # Authorization Bypass
        "CWE-601": "A01:2021",  # URL Redirection to Untrusted Site
        "CWE-639": "A01:2021",  # Authorization Bypass Through User-Controlled Key
        "CWE-651": "A01:2021",  # Information Exposure Through WSDL File
        "CWE-668": "A01:2021",  # Exposure of Resource to Wrong Sphere
        "CWE-706": "A01:2021",  # Use of Incorrectly-Resolved Name or Reference
        "CWE-862": "A01:2021",  # Missing Authorization
        "CWE-863": "A01:2021",  # Incorrect Authorization
        "CWE-913": "A01:2021",  # Improper Control of Dynamically-Managed Code Resources
        "CWE-922": "A01:2021",  # Insecure Storage of Sensitive Information
        
        # A02:2021 - Cryptographic Failures
        "CWE-259": "A02:2021",  # Use of Hard-coded Password
        "CWE-260": "A02:2021",  # Password in Configuration File
        "CWE-261": "A02:2021",  # Weak Cryptography for Passwords
        "CWE-296": "A02:2021",  # Improper Following of Chain of Trust
        "CWE-310": "A02:2021",  # Cryptographic Issues
        "CWE-311": "A02:2021",  # Missing Encryption of Sensitive Data
        "CWE-312": "A02:2021",  # Cleartext Storage of Sensitive Information
        "CWE-313": "A02:2021",  # Cleartext Storage in a File or on Disk
        "CWE-314": "A02:2021",  # Cleartext Storage in the Registry
        "CWE-315": "A02:2021",  # Cleartext Storage of Sensitive Information in a Cookie
        "CWE-316": "A02:2021",  # Cleartext Storage of Sensitive Information in Memory
        "CWE-317": "A02:2021",  # Cleartext Storage of Sensitive Information in GUI
        "CWE-318": "A02:2021",  # Cleartext Storage in Executable
        "CWE-319": "A02:2021",  # Cleartext Transmission of Sensitive Information
        "CWE-320": "A02:2021",  # Key Management Errors
        "CWE-321": "A02:2021",  # Use of Hard-coded Cryptographic Key
        "CWE-322": "A02:2021",  # Key Exchange without Entity Authentication
        "CWE-323": "A02:2021",  # Reusing a Nonce, Key Pair in Encryption
        "CWE-324": "A02:2021",  # Use of a Key Past its Expiration Date
        "CWE-325": "A02:2021",  # Missing Required Cryptographic Step
        "CWE-326": "A02:2021",  # Inadequate Encryption Strength
        "CWE-327": "A02:2021",  # Use of a Broken or Risky Cryptographic Algorithm
        "CWE-328": "A02:2021",  # Reversible One-Way Hash
        "CWE-329": "A02:2021",  # Not Using a Random IV with CBC Mode
        "CWE-330": "A02:2021",  # Use of Insufficiently Random Values
        "CWE-331": "A02:2021",  # Insufficient Entropy
        "CWE-334": "A02:2021",  # Small Space of Random Values
        "CWE-335": "A02:2021",  # Incorrect Usage of Seeds in Pseudo-Random Number Generator
        "CWE-336": "A02:2021",  # Same Seed in Pseudo-Random Number Generator
        "CWE-337": "A02:2021",  # Predictable Seed in Pseudo-Random Number Generator
        "CWE-338": "A02:2021",  # Use of Cryptographically Weak PRNG
        "CWE-340": "A02:2021",  # Predictability Problems
        "CWE-347": "A02:2021",  # Improper Verification of Cryptographic Signature
        "CWE-523": "A02:2021",  # Unprotected Transport of Credentials
        "CWE-780": "A02:2021",  # Use of RSA Algorithm without OAEP
        "CWE-798": "A02:2021",  # Use of Hard-coded Credentials
        "CWE-916": "A02:2021",  # Use of Password Hash With Insufficient Computational Effort
        
        # A03:2021 - Injection
        "CWE-73": "A03:2021",   # External Control of File Name or Path
        "CWE-74": "A03:2021",   # Improper Neutralization of Special Elements
        "CWE-75": "A03:2021",   # Failure to Sanitize Special Elements
        "CWE-77": "A03:2021",   # Command Injection
        "CWE-78": "A03:2021",   # OS Command Injection
        "CWE-79": "A03:2021",   # Cross-site Scripting (XSS)
        "CWE-80": "A03:2021",   # Improper Neutralization of Script-Related HTML Tags
        "CWE-83": "A03:2021",   # Improper Neutralization of Script in Attributes
        "CWE-87": "A03:2021",   # Improper Neutralization of Alternate XSS Syntax
        "CWE-88": "A03:2021",   # Argument Injection
        "CWE-89": "A03:2021",   # SQL Injection
        "CWE-90": "A03:2021",   # LDAP Injection
        "CWE-91": "A03:2021",   # XML Injection
        "CWE-93": "A03:2021",   # Improper Neutralization of CRLF Sequences
        "CWE-94": "A03:2021",   # Code Injection
        "CWE-95": "A03:2021",   # Eval Injection
        "CWE-96": "A03:2021",   # Improper Neutralization of Directives
        "CWE-97": "A03:2021",   # Improper Neutralization of Server-Side Includes
        "CWE-98": "A03:2021",   # PHP Remote File Inclusion
        "CWE-99": "A03:2021",   # Resource Injection
        "CWE-100": "A03:2021",  # Technology-Specific Input Validation Issues
        "CWE-116": "A03:2021",  # Improper Encoding or Escaping of Output
        "CWE-117": "A03:2021",  # Improper Output Neutralization for Logs
        "CWE-134": "A03:2021",  # Uncontrolled Format String
        "CWE-564": "A03:2021",  # SQL Injection: Hibernate
        "CWE-610": "A03:2021",  # Externally Controlled Reference
        "CWE-643": "A03:2021",  # Improper Neutralization of Data within XPath Expressions
        "CWE-652": "A03:2021",  # Improper Neutralization of Data within XQuery Expressions
        "CWE-917": "A03:2021",  # Improper Neutralization of Special Elements used in an Expression Language Statement
        
        # A04:2021 - Insecure Design
        "CWE-209": "A04:2021",  # Information Exposure Through Error Message
        "CWE-256": "A04:2021",  # Unprotected Storage of Credentials
        "CWE-257": "A04:2021",  # Storing Passwords in a Recoverable Format
        "CWE-266": "A04:2021",  # Incorrect Privilege Assignment
        "CWE-269": "A04:2021",  # Improper Privilege Management
        "CWE-280": "A04:2021",  # Improper Handling of Insufficient Permissions
        "CWE-384": "A04:2021",  # Session Fixation
        "CWE-602": "A04:2021",  # Client-Side Enforcement of Server-Side Security
        "CWE-650": "A04:2021",  # Trusting HTTP Permission Methods on the Server Side
        "CWE-653": "A04:2021",  # Insufficient Compartmentalization
        "CWE-656": "A04:2021",  # Reliance on Security Through Obscurity
        "CWE-657": "A04:2021",  # Violation of Secure Design Principles
        "CWE-799": "A04:2021",  # Improper Control of Interaction Frequency
        
        # A05:2021 - Security Misconfiguration
        "CWE-2": "A05:2021",    # Environment
        "CWE-11": "A05:2021",   # ASP.NET Misconfiguration
        "CWE-13": "A05:2021",   # ASP.NET Misconfiguration: Password in Configuration File
        "CWE-15": "A05:2021",   # External Control of System or Configuration Setting
        "CWE-16": "A05:2021",   # Configuration
        "CWE-260": "A05:2021",  # Password in Configuration File
        "CWE-315": "A05:2021",  # Cleartext Storage of Sensitive Information in a Cookie
        "CWE-520": "A05:2021",  # .NET Misconfiguration: Use of Impersonation
        "CWE-526": "A05:2021",  # Information Exposure Through Environmental Variables
        "CWE-537": "A05:2021",  # Information Exposure Through Java Runtime Error Message
        "CWE-541": "A05:2021",  # Information Exposure Through Include Source Code
        "CWE-547": "A05:2021",  # Use of Hard-coded, Security-relevant Constants
        "CWE-611": "A05:2021",  # Improper Restriction of XML External Entity Reference
        "CWE-614": "A05:2021",  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        "CWE-756": "A05:2021",  # Missing Custom Error Page
        "CWE-776": "A05:2021",  # Improper Restriction of Recursive Entity References in DTDs
        "CWE-942": "A05:2021",  # Overly Permissive Cross-domain Whitelist
        "CWE-1004": "A05:2021", # Sensitive Cookie Without 'HttpOnly' Flag
        "CWE-1032": "A05:2021", # OWASP Top Ten 2017 Category A6 - Security Misconfiguration
        "CWE-1174": "A05:2021", # ASP.NET Misconfiguration: Improper Model Validation
        
        # A06:2021 - Vulnerable and Outdated Components
        "CWE-1035": "A06:2021", # OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities
        "CWE-1104": "A06:2021", # Use of Unmaintained Third Party Components
        
        # A07:2021 - Identification and Authentication Failures
        "CWE-255": "A07:2021",  # Credentials Management
        "CWE-259": "A07:2021",  # Use of Hard-coded Password
        "CWE-287": "A07:2021",  # Improper Authentication
        "CWE-288": "A07:2021",  # Authentication Bypass Using an Alternate Path or Channel
        "CWE-290": "A07:2021",  # Authentication Bypass by Spoofing
        "CWE-294": "A07:2021",  # Authentication Bypass by Capture-replay
        "CWE-295": "A07:2021",  # Improper Certificate Validation
        "CWE-297": "A07:2021",  # Improper Validation of Certificate
        "CWE-300": "A07:2021",  # Channel Accessible by Non-Endpoint
        "CWE-302": "A07:2021",  # Authentication Bypass by Assumed-Immutable Data
        "CWE-304": "A07:2021",  # Missing Critical Step in Authentication
        "CWE-306": "A07:2021",  # Missing Authentication for Critical Function
        "CWE-307": "A07:2021",  # Improper Restriction of Excessive Authentication Attempts
        "CWE-346": "A07:2021",  # Origin Validation Error
        "CWE-384": "A07:2021",  # Session Fixation
        "CWE-521": "A07:2021",  # Weak Password Requirements
        "CWE-522": "A07:2021",  # Insufficiently Protected Credentials
        "CWE-640": "A07:2021",  # Weak Password Recovery Mechanism
        "CWE-798": "A07:2021",  # Use of Hard-coded Credentials
        "CWE-804": "A07:2021",  # Guessable CAPTCHA
        "CWE-916": "A07:2021",  # Use of Password Hash With Insufficient Computational Effort
        "CWE-1216": "A07:2021", # Lockout Mechanism Errors
        
        # A08:2021 - Software and Data Integrity Failures
        "CWE-345": "A08:2021",  # Insufficient Verification of Data Authenticity
        "CWE-353": "A08:2021",  # Missing Support for Integrity Check
        "CWE-426": "A08:2021",  # Untrusted Search Path
        "CWE-494": "A08:2021",  # Download of Code Without Integrity Check
        "CWE-502": "A08:2021",  # Deserialization of Untrusted Data
        "CWE-565": "A08:2021",  # Reliance on Cookies without Validation
        "CWE-784": "A08:2021",  # Reliance on Cookies without Validation and Integrity Checking
        "CWE-829": "A08:2021",  # Inclusion of Functionality from Untrusted Control Sphere
        "CWE-830": "A08:2021",  # Inclusion of Web Functionality from Untrusted Source
        "CWE-915": "A08:2021",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        
        # A09:2021 - Security Logging and Monitoring Failures
        "CWE-117": "A09:2021",  # Improper Output Neutralization for Logs
        "CWE-223": "A09:2021",  # Omission of Security-relevant Information
        "CWE-532": "A09:2021",  # Information Exposure Through Log Files
        "CWE-778": "A09:2021",  # Insufficient Logging
        
        # A10:2021 - Server-Side Request Forgery (SSRF)
        "CWE-918": "A10:2021",  # Server-Side Request Forgery (SSRF)
    }
    
    # Vulnerability type to OWASP mapping (for non-CWE classifications)
    VULN_TYPE_OWASP_MAPPING = {
        # Injection-related
        "sql_injection": "A03:2021",
        "xss": "A03:2021",
        "command_injection": "A03:2021",
        "ldap_injection": "A03:2021",
        "xml_injection": "A03:2021",
        "code_injection": "A03:2021",
        
        # Cryptography-related
        "weak_crypto": "A02:2021",
        "hardcoded_secret": "A02:2021",
        "insecure_random": "A02:2021",
        "cleartext_storage": "A02:2021",
        "weak_hash": "A02:2021",
        
        # Access control
        "path_traversal": "A01:2021",
        "csrf": "A01:2021",
        "open_redirect": "A01:2021",
        "missing_auth": "A01:2021",
        
        # Authentication
        "weak_password": "A07:2021",
        "session_fixation": "A07:2021",
        "broken_auth": "A07:2021",
        
        # Deserialization
        "deserialization": "A08:2021",
        "unsafe_deserialization": "A08:2021",
        
        # SSRF
        "ssrf": "A10:2021",
        
        # Configuration
        "misconfiguration": "A05:2021",
        "xxe": "A05:2021",
        "debug_mode": "A05:2021",
        
        # Outdated components
        "cve": "A06:2021",
        "vulnerable_dependency": "A06:2021",
        "outdated_component": "A06:2021",
    }
    
    def map_cwe_to_owasp(self, cwe_id: str) -> Optional[str]:
        """
        Map CWE ID to OWASP Top 10 2021 category
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            
        Returns:
            OWASP category ID or None if not mapped
        """
        # Normalize CWE ID
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        
        return self.CWE_OWASP_MAPPING.get(cwe_id)
    
    def map_vulnerability_type(self, vuln_type: str) -> Optional[str]:
        """
        Map vulnerability type to OWASP category
        
        Args:
            vuln_type: Vulnerability type (e.g., "sql_injection")
            
        Returns:
            OWASP category ID or None if not mapped
        """
        vuln_type_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
        return self.VULN_TYPE_OWASP_MAPPING.get(vuln_type_lower)
    
    def get_owasp_details(self, category_id: str) -> Optional[OWASPCategory]:
        """
        Get detailed information about an OWASP category
        
        Args:
            category_id: OWASP category ID (e.g., "A03:2021")
            
        Returns:
            OWASPCategory object or None if not found
        """
        return self.OWASP_CATEGORIES.get(category_id)
    
    def add_owasp_context(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich vulnerability with OWASP category information
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enriched vulnerability dictionary
        """
        owasp_category_id = None
        
        # Try mapping from CWE IDs
        if 'cwe_ids' in vulnerability and vulnerability['cwe_ids']:
            for cwe_id in vulnerability['cwe_ids']:
                owasp_category_id = self.map_cwe_to_owasp(cwe_id)
                if owasp_category_id:
                    break
        
        # Try mapping from vulnerability type
        if not owasp_category_id and 'type' in vulnerability:
            owasp_category_id = self.map_vulnerability_type(vulnerability['type'])
        
        # Add OWASP information
        if owasp_category_id:
            category = self.get_owasp_details(owasp_category_id)
            if category:
                vulnerability['owasp_category'] = category.id
                vulnerability['owasp_name'] = category.name
                vulnerability['owasp_description'] = category.description
                vulnerability['owasp_reference'] = category.reference_url
        else:
            vulnerability['owasp_category'] = None
            vulnerability['owasp_name'] = "Not Mapped"
        
        return vulnerability


def enrich_with_owasp(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function to enrich vulnerabilities with OWASP context
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        List of enriched vulnerabilities
    """
    mapper = OWASPMapper()
    return [mapper.add_owasp_context(vuln) for vuln in vulnerabilities]
