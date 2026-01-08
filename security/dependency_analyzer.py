"""
Dependency Analyzer

Parse and extract dependencies from various package manager files:
- Maven (pom.xml)
- Gradle (build.gradle, build.gradle.kts)
- npm (package.json, package-lock.json)
- Python (requirements.txt, Pipfile, pyproject.toml)
"""

import logging
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a single dependency"""
    package_name: str
    version: str
    ecosystem: str  # maven, npm, pypi, gradle
    file_path: str
    line_number: int = 0
    scope: str = "compile"  # compile, dev, test, runtime
    group_id: Optional[str] = None  # For Maven/Gradle
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def get_full_name(self) -> str:
        """Get full package identifier"""
        if self.group_id:
            return f"{self.group_id}:{self.package_name}"
        return self.package_name


class DependencyAnalyzer:
    """Analyze and extract dependencies from various package manager files"""
    
    SUPPORTED_FILES = {
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'build.gradle.kts': 'gradle',
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'requirements.txt': 'pypi',
        'Pipfile': 'pypi',
        'pyproject.toml': 'pypi'
    }
    
    def __init__(self):
        """Initialize dependency analyzer"""
        self.dependencies: List[Dependency] = []
    
    def analyze_file(self, file_path: str) -> List[Dependency]:
        """
        Analyze a dependency file and extract all dependencies
        
        Args:
            file_path: Path to dependency file
            
        Returns:
            List of Dependency objects
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []
        
        file_name = file_path.name
        
        if file_name not in self.SUPPORTED_FILES:
            logger.warning(f"Unsupported dependency file: {file_name}")
            return []
        
        ecosystem = self.SUPPORTED_FILES[file_name]
        
        try:
            if file_name == 'pom.xml':
                return self._parse_pom_xml(str(file_path))
            elif file_name in ['build.gradle', 'build.gradle.kts']:
                return self._parse_gradle(str(file_path))
            elif file_name == 'package.json':
                return self._parse_package_json(str(file_path))
            elif file_name == 'package-lock.json':
                return self._parse_package_lock_json(str(file_path))
            elif file_name == 'requirements.txt':
                return self._parse_requirements_txt(str(file_path))
            elif file_name == 'Pipfile':
                return self._parse_pipfile(str(file_path))
            elif file_name == 'pyproject.toml':
                return self._parse_pyproject_toml(str(file_path))
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return []
        
        return []
    
    def _parse_pom_xml(self, file_path: str) -> List[Dependency]:
        """
        Parse Maven pom.xml file
        
        Args:
            file_path: Path to pom.xml
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle XML namespace
            namespace = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            # Try without namespace first
            deps = root.findall('.//dependency')
            
            # If not found, try with namespace
            if not deps:
                deps = root.findall('.//maven:dependency', namespace)
            
            for dep in deps:
                group_id_elem = dep.find('groupId') or dep.find('maven:groupId', namespace)
                artifact_id_elem = dep.find('artifactId') or dep.find('maven:artifactId', namespace)
                version_elem = dep.find('version') or dep.find('maven:version', namespace)
                scope_elem = dep.find('scope') or dep.find('maven:scope', namespace)
                
                if group_id_elem is not None and artifact_id_elem is not None:
                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text
                    version = version_elem.text if version_elem is not None else "unknown"
                    scope = scope_elem.text if scope_elem is not None else "compile"
                    
                    # Get line number (approximate)
                    line_number = 0
                    
                    dependency = Dependency(
                        package_name=artifact_id,
                        version=version,
                        ecosystem='maven',
                        file_path=file_path,
                        line_number=line_number,
                        scope=scope,
                        group_id=group_id
                    )
                    dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing pom.xml: {e}")
        
        return dependencies
    
    def _parse_gradle(self, file_path: str) -> List[Dependency]:
        """
        Parse Gradle build file (build.gradle or build.gradle.kts)
        
        Args:
            file_path: Path to build.gradle
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        # Regex patterns for Gradle dependencies
        # Matches: implementation 'group:artifact:version'
        # Matches: compile "group:artifact:version"
        # Matches: testImplementation group:'artifact':version
        patterns = [
            r"(implementation|compile|api|testImplementation|testCompile|runtimeOnly)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            r"(implementation|compile|api|testImplementation|testCompile|runtimeOnly)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]"
        ]
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip comments
                if line.startswith('//') or line.startswith('/*'):
                    continue
                
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        if len(match.groups()) == 4:
                            scope, group_id, artifact_id, version = match.groups()
                        else:
                            # Handle alternative format
                            scope = match.group(1)
                            group_id = match.group(2)
                            artifact_id = match.group(3)
                            version = match.group(4)
                        
                        dependency = Dependency(
                            package_name=artifact_id,
                            version=version,
                            ecosystem='maven',  # Gradle uses Maven repos
                            file_path=file_path,
                            line_number=line_num,
                            scope=scope,
                            group_id=group_id
                        )
                        dependencies.append(dependency)
        
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing Gradle file: {e}")
        
        return dependencies
    
    def _parse_package_json(self, file_path: str) -> List[Dependency]:
        """
        Parse npm package.json file
        
        Args:
            file_path: Path to package.json
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse dependencies
            for dep_type in ['dependencies', 'devDependencies']:
                deps = data.get(dep_type, {})
                scope = 'dev' if dep_type == 'devDependencies' else 'runtime'
                
                for package_name, version in deps.items():
                    # Clean version (remove ^, ~, etc.)
                    clean_version = re.sub(r'[\^~>=<]', '', version).strip()
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=clean_version,
                        ecosystem='npm',
                        file_path=file_path,
                        line_number=0,
                        scope=scope
                    )
                    dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing package.json: {e}")
        
        return dependencies
    
    def _parse_package_lock_json(self, file_path: str) -> List[Dependency]:
        """
        Parse npm package-lock.json file
        
        Args:
            file_path: Path to package-lock.json
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # package-lock.json v1 format
            if 'dependencies' in data:
                deps = data['dependencies']
                for package_name, info in deps.items():
                    version = info.get('version', 'unknown')
                    dev = info.get('dev', False)
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=version,
                        ecosystem='npm',
                        file_path=file_path,
                        line_number=0,
                        scope='dev' if dev else 'runtime'
                    )
                    dependencies.append(dependency)
            
            # package-lock.json v2/v3 format
            elif 'packages' in data:
                packages = data['packages']
                for package_path, info in packages.items():
                    if package_path == '':  # Root package
                        continue
                    
                    # Extract package name from path
                    package_name = package_path.replace('node_modules/', '')
                    version = info.get('version', 'unknown')
                    dev = info.get('dev', False)
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=version,
                        ecosystem='npm',
                        file_path=file_path,
                        line_number=0,
                        scope='dev' if dev else 'runtime'
                    )
                    dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing package-lock.json: {e}")
        
        return dependencies
    
    def _parse_requirements_txt(self, file_path: str) -> List[Dependency]:
        """
        Parse Python requirements.txt file
        
        Args:
            file_path: Path to requirements.txt
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        # Regex for requirements.txt format
        # Matches: package==1.2.3, package>=1.2.3, package~=1.2.3, etc.
        pattern = r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9.]+.*?)$'
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Skip options like -r, -e, --index-url
                if line.startswith('-'):
                    continue
                
                match = re.match(pattern, line)
                if match:
                    package_name, operator, version = match.groups()
                    
                    # Clean version
                    clean_version = version.strip()
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=clean_version,
                        ecosystem='pypi',
                        file_path=file_path,
                        line_number=line_num,
                        scope='runtime'
                    )
                    dependencies.append(dependency)
                else:
                    # Handle package without version
                    package_name = line.split('[')[0].strip()  # Handle extras like package[extra]
                    if package_name:
                        dependency = Dependency(
                            package_name=package_name,
                            version='latest',
                            ecosystem='pypi',
                            file_path=file_path,
                            line_number=line_num,
                            scope='runtime'
                        )
                        dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path: str) -> List[Dependency]:
        """
        Parse Python Pipfile (TOML format)
        
        Args:
            file_path: Path to Pipfile
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            import toml
        except ImportError:
            # Try tomli for Python 3.11+
            try:
                import tomli as toml
            except ImportError:
                logger.warning("toml library not available, skipping Pipfile parsing")
                return dependencies
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Parse packages and dev-packages
            for section in ['packages', 'dev-packages']:
                packages = data.get(section, {})
                scope = 'dev' if section == 'dev-packages' else 'runtime'
                
                for package_name, version_spec in packages.items():
                    # Handle different version formats
                    if isinstance(version_spec, str):
                        version = version_spec.replace('==', '').replace('~=', '').replace('>=', '').strip()
                    elif isinstance(version_spec, dict):
                        version = version_spec.get('version', 'latest')
                    else:
                        version = 'latest'
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=version,
                        ecosystem='pypi',
                        file_path=file_path,
                        line_number=0,
                        scope=scope
                    )
                    dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing Pipfile: {e}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path: str) -> List[Dependency]:
        """
        Parse Python pyproject.toml file
        
        Args:
            file_path: Path to pyproject.toml
            
        Returns:
            List of dependencies
        """
        dependencies = []
        
        try:
            import toml
        except ImportError:
            try:
                import tomli as toml
            except ImportError:
                logger.warning("toml library not available, skipping pyproject.toml parsing")
                return dependencies
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)
            
            # Parse dependencies from various sections
            # Poetry format
            if 'tool' in data and 'poetry' in data['tool']:
                poetry = data['tool']['poetry']
                
                for section in ['dependencies', 'dev-dependencies']:
                    deps = poetry.get(section, {})
                    scope = 'dev' if section == 'dev-dependencies' else 'runtime'
                    
                    for package_name, version_spec in deps.items():
                        if package_name == 'python':  # Skip Python version
                            continue
                        
                        if isinstance(version_spec, str):
                            version = version_spec.replace('^', '').replace('~', '').replace('>=', '').strip()
                        elif isinstance(version_spec, dict):
                            version = version_spec.get('version', 'latest')
                        else:
                            version = 'latest'
                        
                        dependency = Dependency(
                            package_name=package_name,
                            version=version,
                            ecosystem='pypi',
                            file_path=file_path,
                            line_number=0,
                            scope=scope
                        )
                        dependencies.append(dependency)
            
            # PEP 621 format
            if 'project' in data:
                project = data['project']
                deps = project.get('dependencies', [])
                
                for dep_spec in deps:
                    # Parse: package>=1.2.3 or package==1.2.3
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9.]+.*?)$', dep_spec)
                    if match:
                        package_name, operator, version = match.groups()
                    else:
                        package_name = dep_spec
                        version = 'latest'
                    
                    dependency = Dependency(
                        package_name=package_name,
                        version=version,
                        ecosystem='pypi',
                        file_path=file_path,
                        line_number=0,
                        scope='runtime'
                    )
                    dependencies.append(dependency)
            
            logger.info(f"Parsed {len(dependencies)} dependencies from {file_path}")
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml: {e}")
        
        return dependencies
    
    def scan_directory(self, directory: str) -> List[Dependency]:
        """
        Scan a directory for dependency files and extract all dependencies
        
        Args:
            directory: Path to directory to scan
            
        Returns:
            List of all dependencies found
        """
        all_dependencies = []
        directory = Path(directory)
        
        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return []
        
        # Search for supported dependency files
        for file_pattern in self.SUPPORTED_FILES.keys():
            for file_path in directory.rglob(file_pattern):
                logger.info(f"Found dependency file: {file_path}")
                deps = self.analyze_file(str(file_path))
                all_dependencies.extend(deps)
        
        logger.info(f"Total dependencies found: {len(all_dependencies)}")
        return all_dependencies


def analyze_dependencies(path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze dependencies
    
    Args:
        path: Path to dependency file or directory
        
    Returns:
        List of dependency dictionaries
    """
    analyzer = DependencyAnalyzer()
    path_obj = Path(path)
    
    if path_obj.is_file():
        dependencies = analyzer.analyze_file(str(path))
    elif path_obj.is_dir():
        dependencies = analyzer.scan_directory(str(path))
    else:
        logger.error(f"Invalid path: {path}")
        return []
    
    return [dep.to_dict() for dep in dependencies]
