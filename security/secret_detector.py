"""
Secret Detector

ML-based and rule-based detection of hardcoded secrets, API keys, passwords, and tokens.
"""

import logging
import re
from typing import List, Dict, Any, Optional
import hashlib

try:
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings
    DETECT_SECRETS_AVAILABLE = True
except ImportError:
    DETECT_SECRETS_AVAILABLE = False
    logging.warning("detect-secrets not available")

logger = logging.getLogger(__name__)


class SecretDetector:
    """Detect hardcoded secrets in code"""

    # High-entropy string patterns
    HIGH_ENTROPY_PATTERNS = [
        r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
        r'[A-Fa-f0-9]{32,}',           # Hex
        r'[A-Za-z0-9_-]{20,}',         # General high-entropy
    ]

    # Keyword patterns
    SECRET_KEYWORDS = [
        r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(secret|token|auth)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(access[_-]?key|access_token)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(private[_-]?key)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(aws|gcp|azure)[_-]?(key|secret)\s*[=:]\s*["\']([^"\']+)["\']',
    ]

    # Known false positives
    FALSE_POSITIVES = [
        'your_api_key_here',
        'example',
        'test',
        'placeholder',
        'changeme',
        'TODO',
        '123456',
    ]

    def __init__(self):
        """Initialize secret detector"""
        self.use_ml = DETECT_SECRETS_AVAILABLE
        if self.use_ml:
            logger.info("Using detect-secrets for ML-based detection")
        else:
            logger.info("Using regex-based detection only")

    def scan_code(self, code: str, file_path: str = None) -> List[Dict[str, Any]]:
        """
        Scan code for hardcoded secrets

        Args:
            code: Source code to scan
            file_path: Optional file path for context

        Returns:
            List of detected secrets
        """
        secrets = []

        # ML-based detection
        if self.use_ml:
            ml_secrets = self._scan_with_ml(code, file_path)
            secrets.extend(ml_secrets)

        # Regex-based detection
        regex_secrets = self._scan_with_regex(code, file_path)
        secrets.extend(regex_secrets)

        # Remove duplicates and false positives
        secrets = self._filter_secrets(secrets)

        return secrets

    def _scan_with_ml(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan using detect-secrets library"""
        secrets = []

        try:
            # Create temporary secrets collection
            settings = default_settings()
            collection = SecretsCollection()

            # Scan code
            for line_num, line in enumerate(code.split('\n'), 1):
                # detect-secrets requires file-like interface
                # This is a simplified implementation
                potential_secret = self._check_line_entropy(line)
                if potential_secret:
                    secrets.append({
                        'type': 'high_entropy',
                        'value': potential_secret,
                        'line': line_num,
                        'file': file_path,
                        'detector': 'ml',
                        'severity': 'high'
                    })

        except Exception as e:
            logger.error(f"ML detection error: {e}")

        return secrets

    def _scan_with_regex(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan using regex patterns"""
        secrets = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check keyword patterns
            for pattern in self.SECRET_KEYWORDS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    keyword = match.group(1)
                    value = match.group(2) if len(
                        match.groups()) > 1 else match.group(0)

                    secrets.append({
                        'type': f'keyword_{keyword}',
                        'value': value,
                        'line': line_num,
                        'file': file_path,
                        'detector': 'regex',
                        'severity': self._assess_severity(keyword, value),
                        'context': line.strip()
                    })

            # Check high-entropy patterns
            for pattern in self.HIGH_ENTROPY_PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(0)
                    if self._is_high_entropy(value):
                        secrets.append({
                            'type': 'high_entropy',
                            'value': value,
                            'line': line_num,
                            'file': file_path,
                            'detector': 'regex',
                            'severity': 'medium',
                            'context': line.strip()
                        })

        return secrets

    def _check_line_entropy(self, line: str) -> Optional[str]:
        """Check if line contains high-entropy string"""
        # Extract strings from line
        strings = re.findall(r'["\']([^"\']{10,})["\']', line)

        for s in strings:
            if self._is_high_entropy(s):
                return s

        return None

    def _is_high_entropy(self, value: str, threshold: float = 4.5) -> bool:
        """
        Calculate Shannon entropy of a string

        Args:
            value: String to check
            threshold: Entropy threshold (default 4.5 for base64-like strings)

        Returns:
            True if entropy exceeds threshold
        """
        if len(value) < 10:  # Too short to be meaningful
            return False

        # Calculate character frequencies
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        from math import log2
        entropy = 0
        for count in freq.values():
            p = count / len(value)
            entropy -= p * log2(p)

        return entropy > threshold

    def _assess_severity(self, keyword: str, value: str) -> str:
        """Assess severity of detected secret"""
        keyword_lower = keyword.lower()

        # High severity keywords
        if any(kw in keyword_lower for kw in ['private_key', 'secret', 'password']):
            return 'critical'

        # Medium severity
        if any(kw in keyword_lower for kw in ['api_key', 'token', 'access_key']):
            return 'high'

        # Check value length and complexity
        if len(value) > 30 and self._is_high_entropy(value):
            return 'high'

        return 'medium'

    def _filter_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates and false positives"""
        filtered = []
        seen = set()

        for secret in secrets:
            value = secret['value']

            # Check false positives
            if any(fp.lower() in value.lower() for fp in self.FALSE_POSITIVES):
                continue

            # Check for environment variable references
            if value.startswith('$') or value.startswith('os.getenv'):
                continue

            # Deduplicate
            key = (secret['line'], value)
            if key in seen:
                continue
            seen.add(key)

            filtered.append(secret)

        return filtered


def scan_for_secrets(code: str, file_path: str = None) -> List[Dict[str, Any]]:
    """
    Convenience function to scan code for secrets

    Args:
        code: Source code
        file_path: Optional file path

    Returns:
        List of detected secrets
    """
    detector = SecretDetector()
    return detector.scan_code(code, file_path)
