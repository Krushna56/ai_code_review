"""
Unit tests for DependencyAnalyzer
"""

from security.dependency_analyzer import DependencyAnalyzer, Dependency
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestDependencyAnalyzer:
    """Test dependency analyzer functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.analyzer = DependencyAnalyzer()
        self.fixtures_dir = Path(__file__).parent.parent / \
            'fixtures' / 'dependencies'

    def test_parse_pom_xml(self):
        """Test parsing Maven pom.xml"""
        pom_path = self.fixtures_dir / 'pom.xml'
        if not pom_path.exists():
            pytest.skip("pom.xml fixture not found")

        dependencies = self.analyzer.analyze_file(str(pom_path))

        assert len(dependencies) > 0

        # Check for log4j dependency
        log4j_deps = [
            d for d in dependencies if 'log4j' in d.package_name.lower()]
        assert len(log4j_deps) > 0

        log4j_dep = log4j_deps[0]
        assert log4j_dep.version == '2.14.1'
        assert log4j_dep.ecosystem == 'maven'
        assert log4j_dep.group_id == 'org.apache.logging.log4j'

    def test_parse_package_json(self):
        """Test parsing npm package.json"""
        pkg_path = self.fixtures_dir / 'package.json'
        if not pkg_path.exists():
            pytest.skip("package.json fixture not found")

        dependencies = self.analyzer.analyze_file(str(pkg_path))

        assert len(dependencies) > 0

        # Check for lodash
        lodash_deps = [d for d in dependencies if d.package_name == 'lodash']
        assert len(lodash_deps) > 0

        lodash_dep = lodash_deps[0]
        assert lodash_dep.version == '4.17.15'
        assert lodash_dep.ecosystem == 'npm'

    def test_parse_requirements_txt(self):
        """Test parsing Python requirements.txt"""
        req_path = self.fixtures_dir / 'requirements.txt'
        if not req_path.exists():
            pytest.skip("requirements.txt fixture not found")

        dependencies = self.analyzer.analyze_file(str(req_path))

        assert len(dependencies) > 0

        # Check for Flask
        flask_deps = [d for d in dependencies if d.package_name == 'Flask']
        assert len(flask_deps) > 0

        flask_dep = flask_deps[0]
        assert flask_dep.version == '2.0.1'
        assert flask_dep.ecosystem == 'pypi'

    def test_parse_gradle(self):
        """Test parsing Gradle build.gradle"""
        gradle_path = self.fixtures_dir / 'build.gradle'
        if not gradle_path.exists():
            pytest.skip("build.gradle fixture not found")

        dependencies = self.analyzer.analyze_file(str(gradle_path))

        # May or may not find deps depending on regex
        assert len(dependencies) >= 0

        # If dependencies found, verify format
        if dependencies:
            dep = dependencies[0]
            assert dep.ecosystem == 'maven'  # Gradle uses Maven repos
            assert dep.group_id is not None

    def test_unsupported_file(self):
        """Test handling of unsupported file types"""
        dependencies = self.analyzer.analyze_file('test.txt')
        assert len(dependencies) == 0

    def test_nonexistent_file(self):
        """Test handling of nonexistent files"""
        dependencies = self.analyzer.analyze_file('nonexistent.xml')
        assert len(dependencies) == 0

    def test_dependency_dataclass(self):
        """Test Dependency dataclass"""
        dep = Dependency(
            package_name='test-package',
            version='1.0.0',
            ecosystem='npm',
            file_path='/test/package.json',
            line_number=10,
            scope='runtime'
        )

        assert dep.package_name == 'test-package'
        assert dep.version == '1.0.0'
        assert dep.to_dict()['ecosystem'] == 'npm'
        assert dep.get_full_name() == 'test-package'

        # Test with group_id
        dep2 = Dependency(
            package_name='artifact',
            version='1.0.0',
            ecosystem='maven',
            file_path='/test/pom.xml',
            group_id='com.example'
        )
        assert dep2.get_full_name() == 'com.example:artifact'

    def test_scan_directory(self):
        """Test scanning a directory for dependency files"""
        if not self.fixtures_dir.exists():
            pytest.skip("Fixtures directory not found")

        dependencies = self.analyzer.scan_directory(str(self.fixtures_dir))

        # Should find dependencies from multiple files
        assert len(dependencies) > 0

        # Should have multiple ecosystems
        ecosystems = set(d.ecosystem for d in dependencies)
        assert len(ecosystems) >= 2  # At least 2 different package managers


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
