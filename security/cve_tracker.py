"""
CVE Tracker

Detect and track Common Vulnerabilities and Exposures (CVEs) in dependencies
using the Open Source Vulnerabilities (OSV) API.
"""

import logging
import time
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

try:
    import osv
    OSV_AVAILABLE = True
except ImportError:
    OSV_AVAILABLE = False
    logging.warning("osv library not available, CVE tracking disabled")

logger = logging.getLogger(__name__)


@dataclass
class CVEVulnerability:
    """Represents a CVE vulnerability"""
    cve_id: str
    package_name: str
    package_version: str
    ecosystem: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: Optional[float] = None
    summary: str = ""
    published: str = ""
    modified: str = ""
    fixed_versions: List[str] = None
    references: List[str] = None
    cwe_ids: List[str] = None
    aliases: List[str] = None
    
    def __post_init__(self):
        """Initialize mutable defaults"""
        if self.fixed_versions is None:
            self.fixed_versions = []
        if self.references is None:
            self.references = []
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.aliases is None:
            self.aliases = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class CVETracker:
    """Track CVEs using OSV API"""
    
    RATE_LIMIT = 200  # Requests per minute
    CACHE_EXPIRY_HOURS = 24
    
    def __init__(self, cache_dir: str = None):
        """
        Initialize CVE tracker
        
        Args:
            cache_dir: Directory for caching CVE results
        """
        if not OSV_AVAILABLE:
            raise RuntimeError("osv library not installed. Install with: pip install osv")
        
        self.cache_dir = Path(cache_dir) if cache_dir else Path(".cache/cve")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.request_count = 0
        self.request_window_start = time.time()
    
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        elapsed = current_time - self.request_window_start
        
        # Reset counter every minute
        if elapsed >= 60:
            self.request_count = 0
            self.request_window_start = current_time
        
        # If we've hit the rate limit, wait
        if self.request_count >= self.RATE_LIMIT:
            wait_time = 60 - elapsed
            if wait_time > 0:
                logger.warning(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)
                self.request_count = 0
                self.request_window_start = time.time()
        
        self.request_count += 1
    
    def _get_cache_key(self, package: str, version: str, ecosystem: str) -> str:
        """
        Generate cache key for a package
        
        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem (pypi, npm, maven)
            
        Returns:
            Cache key string
        """
        key_str = f"{ecosystem}:{package}:{version}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[List[CVEVulnerability]]:
        """
        Retrieve cached CVE results
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached vulnerabilities or None if not cached/expired
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            
            # Check expiry
            cached_time = datetime.fromisoformat(data['timestamp'])
            if datetime.now() - cached_time > timedelta(hours=self.CACHE_EXPIRY_HOURS):
                logger.info(f"Cache expired for {cache_key}")
                return None
            
            # Reconstruct vulnerabilities
            vulnerabilities = []
            for vuln_data in data['vulnerabilities']:
                vuln = CVEVulnerability(**vuln_data)
                vulnerabilities.append(vuln)
            
            logger.info(f"Cache hit for {cache_key}")
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    def _cache_result(self, cache_key: str, vulnerabilities: List[CVEVulnerability]):
        """
        Cache CVE results
        
        Args:
            cache_key: Cache key
            vulnerabilities: List of vulnerabilities to cache
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': [v.to_dict() for v in vulnerabilities]
            }
            
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Cached result for {cache_key}")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")
    
    def _assess_severity(self, cvss_score: Optional[float]) -> str:
        """
        Map CVSS score to severity level
        
        Args:
            cvss_score: CVSS score (0-10)
            
        Returns:
            Severity string
        """
        if cvss_score is None:
            return "UNKNOWN"
        
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _parse_osv_response(self, osv_vulns: List[Any], package: str, version: str, ecosystem: str) -> List[CVEVulnerability]:
        """
        Parse OSV API response into CVEVulnerability objects
        
        Args:
            osv_vulns: OSV vulnerability objects
            package: Package name
            version: Package version
            ecosystem: Package ecosystem
            
        Returns:
            List of CVEVulnerability objects
        """
        vulnerabilities = []
        
        for vuln in osv_vulns:
            try:
                # Extract CVE ID (or use OSV ID if no CVE)
                cve_id = None
                aliases = getattr(vuln, 'aliases', []) or []
                
                for alias in aliases:
                    if alias.startswith('CVE-'):
                        cve_id = alias
                        break
                
                if not cve_id:
                    cve_id = getattr(vuln, 'id', 'UNKNOWN')
                
                # Extract CVSS score
                cvss_score = None
                severity_info = getattr(vuln, 'severity', None)
                if severity_info and isinstance(severity_info, list) and len(severity_info) > 0:
                    # OSV format: [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}]
                    score_str = severity_info[0].get('score', '')
                    # Parse CVSS score from string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    # For simplicity, we'll try to extract the base score
                    # In practice, you might use a CVSS library
                    if 'score' in severity_info[0]:
                        try:
                            # Try to get numeric score if available
                            cvss_score = float(severity_info[0].get('score', 0))
                        except (ValueError, TypeError):
                            pass
                
                # If no CVSS score, try to infer from severity
                if cvss_score is None and hasattr(vuln, 'database_specific'):
                    db_specific = getattr(vuln, 'database_specific', {})
                    if isinstance(db_specific, dict):
                        cvss_score = db_specific.get('cvss_score')
                
                # Extract summary
                summary = getattr(vuln, 'summary', '') or getattr(vuln, 'details', '')[:200]
                
                # Extract published/modified dates
                published = getattr(vuln, 'published', '')
                modified = getattr(vuln, 'modified', '')
                
                # Extract fixed versions
                fixed_versions = []
                affected = getattr(vuln, 'affected', []) or []
                for affect in affected:
                    ranges = getattr(affect, 'ranges', []) or []
                    for range_info in ranges:
                        events = getattr(range_info, 'events', []) or []
                        for event in events:
                            if hasattr(event, 'fixed'):
                                fixed_versions.append(getattr(event, 'fixed'))
                
                # Extract references
                references = []
                refs = getattr(vuln, 'references', []) or []
                for ref in refs:
                    if hasattr(ref, 'url'):
                        references.append(getattr(ref, 'url'))
                
                # Extract CWE IDs
                cwe_ids = []
                if hasattr(vuln, 'database_specific'):
                    db_specific = getattr(vuln, 'database_specific', {})
                    if isinstance(db_specific, dict):
                        cwe_ids = db_specific.get('cwe_ids', [])
                
                severity = self._assess_severity(cvss_score)
                
                vulnerability = CVEVulnerability(
                    cve_id=cve_id,
                    package_name=package,
                    package_version=version,
                    ecosystem=ecosystem,
                    severity=severity,
                    cvss_score=cvss_score,
                    summary=summary,
                    published=published,
                    modified=modified,
                    fixed_versions=fixed_versions,
                    references=references,
                    cwe_ids=cwe_ids,
                    aliases=aliases
                )
                vulnerabilities.append(vulnerability)
            except Exception as e:
                logger.error(f"Error parsing vulnerability: {e}")
                continue
        
        return vulnerabilities
    
    def query_osv(self, package: str, version: str, ecosystem: str) -> List[CVEVulnerability]:
        """
        Query OSV API for vulnerabilities in a specific package
        
        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem (pypi, npm, Maven, etc.)
            
        Returns:
            List of CVEVulnerability objects
        """
        # Check cache first
        cache_key = self._get_cache_key(package, version, ecosystem)
        cached = self._get_cached_result(cache_key)
        if cached is not None:
            return cached
        
        # Apply rate limiting
        self._rate_limit()
        
        # Map ecosystem to OSV format
        osv_ecosystem_map = {
            'pypi': 'PyPI',
            'npm': 'npm',
            'maven': 'Maven',
            'gradle': 'Maven',  # Gradle uses Maven repos
        }
        osv_ecosystem = osv_ecosystem_map.get(ecosystem.lower(), ecosystem)
        
        try:
            logger.info(f"Querying OSV for {package}:{version} ({osv_ecosystem})")
            
            # Query OSV API
            query = osv.query(f"{package}@{version}", ecosystem=osv_ecosystem)
            
            if query and hasattr(query, 'vulns'):
                osv_vulns = query.vulns
                vulnerabilities = self._parse_osv_response(osv_vulns, package, version, ecosystem)
                
                # Cache the result
                self._cache_result(cache_key, vulnerabilities)
                
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {package}:{version}")
                return vulnerabilities
            else:
                # No vulnerabilities found
                logger.info(f"No vulnerabilities found for {package}:{version}")
                self._cache_result(cache_key, [])
                return []
        except Exception as e:
            logger.error(f"Error querying OSV API: {e}")
            return []
    
    def batch_query_osv(self, dependencies: List[Dict[str, str]]) -> Dict[str, List[CVEVulnerability]]:
        """
        Query OSV API for multiple dependencies
        
        Args:
            dependencies: List of dependency dicts with 'package_name', 'version', 'ecosystem'
            
        Returns:
            Dictionary mapping package identifier to list of vulnerabilities
        """
        results = {}
        
        for dep in dependencies:
            package = dep.get('package_name')
            version = dep.get('version')
            ecosystem = dep.get('ecosystem')
            
            if not package or not version or not ecosystem:
                logger.warning(f"Incomplete dependency info: {dep}")
                continue
            
            # Create package identifier
            pkg_id = f"{package}:{version}"
            
            # Query for vulnerabilities
            vulnerabilities = self.query_osv(package, version, ecosystem)
            
            if vulnerabilities:
                results[pkg_id] = vulnerabilities
        
        logger.info(f"Batch query completed: {len(results)} vulnerable packages found")
        return results
    
    def get_cve_details(self, cve_id: str) -> Optional[CVEVulnerability]:
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            
        Returns:
            CVEVulnerability object or None if not found
        """
        self._rate_limit()
        
        try:
            logger.info(f"Querying OSV for CVE {cve_id}")
            
            # Query by CVE ID
            vuln = osv.get(cve_id)
            
            if vuln:
                # Extract package info (use first affected package)
                package = "unknown"
                version = "unknown"
                ecosystem = "unknown"
                
                if hasattr(vuln, 'affected') and vuln.affected:
                    affected = vuln.affected[0]
                    if hasattr(affected, 'package'):
                        pkg = affected.package
                        ecosystem = getattr(pkg, 'ecosystem', 'unknown')
                        package = getattr(pkg, 'name', 'unknown')
                    
                    # Get a version from ranges
                    if hasattr(affected, 'versions') and affected.versions:
                        version = affected.versions[0]
                
                vulnerabilities = self._parse_osv_response([vuln], package, version, ecosystem)
                
                if vulnerabilities:
                    return vulnerabilities[0]
            
            logger.warning(f"CVE {cve_id} not found in OSV database")
            return None
        except Exception as e:
            logger.error(f"Error querying CVE details: {e}")
            return None


def scan_dependencies_for_cves(dependencies: List[Dict[str, str]], cache_dir: str = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convenience function to scan dependencies for CVEs
    
    Args:
        dependencies: List of dependency dictionaries
        cache_dir: Optional cache directory
        
    Returns:
        Dictionary mapping package identifiers to vulnerabilities
    """
    if not OSV_AVAILABLE:
        logger.error("osv library not available")
        return {}
    
    tracker = CVETracker(cache_dir=cache_dir)
    results = tracker.batch_query_osv(dependencies)
    
    # Convert to dict format
    return {pkg_id: [v.to_dict() for v in vulns] for pkg_id, vulns in results.items()}
