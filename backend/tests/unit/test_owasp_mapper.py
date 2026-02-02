"""
Unit tests for OWASPMapper
"""

from security.owasp_mapper import OWASPMapper, OWASPCategory
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestOWASPMapper:
    """Test OWASP mapping functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.mapper = OWASPMapper()

    def test_map_cwe_sql_injection(self):
        """Test mapping SQL injection CWE to OWASP"""
        owasp_id = self.mapper.map_cwe_to_owasp("CWE-89")
        assert owasp_id == "A03:2021"  # Injection

    def test_map_cwe_xss(self):
        """Test mapping XSS CWE to OWASP"""
        owasp_id = self.mapper.map_cwe_to_owasp("CWE-79")
        assert owasp_id == "A03:2021"  # Injection

    def test_map_cwe_weak_crypto(self):
        """Test mapping weak crypto CWE to OWASP"""
        owasp_id = self.mapper.map_cwe_to_owasp("CWE-327")
        assert owasp_id == "A02:2021"  # Cryptographic Failures

    def test_map_cwe_deserialization(self):
        """Test mapping deserialization CWE to OWASP"""
        owasp_id = self.mapper.map_cwe_to_owasp("CWE-502")
        assert owasp_id == "A08:2021"  # Software and Data Integrity Failures

    def test_map_cwe_without_prefix(self):
        """Test mapping CWE without CWE- prefix"""
        owasp_id = self.mapper.map_cwe_to_owasp("89")
        assert owasp_id == "A03:2021"  # Should normalize to CWE-89

    def test_map_unknown_cwe(self):
        """Test mapping unknown CWE"""
        owasp_id = self.mapper.map_cwe_to_owasp("CWE-99999")
        assert owasp_id is None

    def test_map_vulnerability_type(self):
        """Test mapping vulnerability types"""
        assert self.mapper.map_vulnerability_type(
            "sql_injection") == "A03:2021"
        assert self.mapper.map_vulnerability_type("xss") == "A03:2021"
        assert self.mapper.map_vulnerability_type("weak_crypto") == "A02:2021"
        assert self.mapper.map_vulnerability_type(
            "hardcoded_secret") == "A02:2021"
        assert self.mapper.map_vulnerability_type("cve") == "A06:2021"
        assert self.mapper.map_vulnerability_type("ssrf") == "A10:2021"

    def test_map_vulnerability_type_case_insensitive(self):
        """Test vulnerability type mapping is case-insensitive"""
        assert self.mapper.map_vulnerability_type(
            "SQL_INJECTION") == "A03:2021"
        assert self.mapper.map_vulnerability_type("Weak Crypto") == "A02:2021"

    def test_get_owasp_details(self):
        """Test getting OWASP category details"""
        category = self.mapper.get_owasp_details("A03:2021")

        assert category is not None
        assert isinstance(category, OWASPCategory)
        assert category.id == "A03:2021"
        assert category.name == "Injection"
        assert "injection" in category.description.lower()
        assert "owasp.org" in category.reference_url

    def test_get_unknown_owasp_category(self):
        """Test getting unknown OWASP category"""
        category = self.mapper.get_owasp_details("A99:2021")
        assert category is None

    def test_add_owasp_context_with_cwe(self):
        """Test enriching vulnerability with OWASP context from CWE"""
        vuln = {
            'cve_id': 'CVE-2021-12345',
            'cwe_ids': ['CWE-89', 'CWE-20']
        }

        enriched = self.mapper.add_owasp_context(vuln)

        assert enriched['owasp_category'] == 'A03:2021'
        assert enriched['owasp_name'] == 'Injection'
        assert 'owasp_description' in enriched
        assert 'owasp_reference' in enriched

    def test_add_owasp_context_with_type(self):
        """Test enriching vulnerability with OWASP context from type"""
        vuln = {
            'type': 'hardcoded_secret',
            'title': 'Hardcoded API Key'
        }

        enriched = self.mapper.add_owasp_context(vuln)

        assert enriched['owasp_category'] == 'A02:2021'
        assert enriched['owasp_name'] == 'Cryptographic Failures'

    def test_add_owasp_context_unmapped(self):
        """Test enriching vulnerability with no mapping"""
        vuln = {
            'cve_id': 'CVE-2021-99999',
            'cwe_ids': []
        }

        enriched = self.mapper.add_owasp_context(vuln)

        assert enriched['owasp_category'] is None
        assert enriched['owasp_name'] == 'Not Mapped'

    def test_all_owasp_categories_exist(self):
        """Test that all OWASP Top 10 2021 categories are defined"""
        expected_categories = [
            "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
            "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"
        ]

        for cat_id in expected_categories:
            category = self.mapper.get_owasp_details(cat_id)
            assert category is not None
            assert category.id == cat_id
            assert len(category.name) > 0
            assert len(category.description) > 0
            assert "https://owasp.org" in category.reference_url


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
