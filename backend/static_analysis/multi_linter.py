"""
Multi-Linter Integration

Unified interface for running multiple static analysis tools:
- Bandit (security)
- Semgrep (patterns)
- Pylint (code quality)
- Ruff (style, very fast)
"""

import subprocess
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import config

logger = logging.getLogger(__name__)


class LinterResult:
    """Container for linter results"""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.issues = []
        self.success = False
        self.error_message = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tool': self.tool_name,
            'success': self.success,
            'issues': self.issues,
            'error': self.error_message
        }


class MultiLinter:
    """Run multiple linters and aggregate results"""

    def __init__(self):
        self.results = {}

    def run_bandit(self, path: str) -> LinterResult:
        """Run Bandit security scanner"""
        result = LinterResult('bandit')

        if not config.ENABLE_BANDIT:
            logger.info("Bandit is disabled")
            return result

        try:
            from bandit.core import manager as bandit_manager
            from bandit.core import config as bandit_config

            # Create Bandit config
            b_conf = bandit_config.BanditConfig()

            # Create manager and run scan
            b_mgr = bandit_manager.BanditManager(b_conf, 'file')
            b_mgr.discover_files([path], True)
            b_mgr.run_tests()

            # Extract issues
            for issue in b_mgr.results:
                result.issues.append({
                    'file': issue.fname,
                    'line': issue.lineno,
                    'severity': issue.severity,
                    'confidence': issue.confidence,
                    'test_id': issue.test_id,
                    'issue_text': issue.text,
                    'code': issue.get_code()
                })

            result.success = True
            logger.info(f"Bandit found {len(result.issues)} issues")

        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Bandit error: {e}")

        return result

    def run_semgrep(self, path: str) -> LinterResult:
        """Run Semgrep pattern scanner"""
        result = LinterResult('semgrep')

        if not config.ENABLE_SEMGREP:
            logger.info("Semgrep is disabled")
            return result

        try:
            # Run semgrep with auto config (uses registry rules)
            cmd = ['semgrep', '--config=auto', '--json', path]
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=300)

            if proc.returncode == 0 or proc.returncode == 1:  # 1 means findings
                output = json.loads(proc.stdout)

                for finding in output.get('results', []):
                    result.issues.append({
                        'file': finding.get('path'),
                        'line': finding.get('start', {}).get('line'),
                        'severity': finding.get('extra', {}).get('severity', 'INFO'),
                        'rule_id': finding.get('check_id'),
                        'message': finding.get('extra', {}).get('message'),
                        'code': finding.get('extra', {}).get('lines')
                    })

                result.success = True
                logger.info(f"Semgrep found {len(result.issues)} issues")
            else:
                result.error_message = proc.stderr

        except FileNotFoundError:
            result.error_message = "Semgrep not installed. Install with: pip install semgrep"
            logger.warning(result.error_message)
        except subprocess.TimeoutExpired:
            result.error_message = "Semgrep timed out"
            logger.error(result.error_message)
        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Semgrep error: {e}")

        return result

    def run_pylint(self, path: str) -> LinterResult:
        """Run Pylint code quality checker"""
        result = LinterResult('pylint')

        if not config.ENABLE_PYLINT:
            logger.info("Pylint is disabled")
            return result

        try:
            cmd = ['pylint', '--output-format=json', path]
            proc = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=300)

            # Pylint returns non-zero for issues, which is expected
            if proc.stdout:
                output = json.loads(proc.stdout)

                for issue in output:
                    result.issues.append({
                        'file': issue.get('path'),
                        'line': issue.get('line'),
                        # convention, refactor, warning, error
                        'severity': issue.get('type'),
                        'message': issue.get('message'),
                        'symbol': issue.get('symbol'),
                        'message_id': issue.get('message-id')
                    })

                result.success = True
                logger.info(f"Pylint found {len(result.issues)} issues")

        except FileNotFoundError:
            result.error_message = "Pylint not installed. Install with: pip install pylint"
            logger.warning(result.error_message)
        except subprocess.TimeoutExpired:
            result.error_message = "Pylint timed out"
            logger.error(result.error_message)
        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Pylint error: {e}")

        return result

    def run_ruff(self, path: str) -> LinterResult:
        """Run Ruff fast Python linter"""
        result = LinterResult('ruff')

        if not config.ENABLE_RUFF:
            logger.info("Ruff is disabled")
            return result

        try:
            cmd = ['ruff', 'check', '--output-format=json', path]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)

            if proc.stdout:
                output = json.loads(proc.stdout)

                for issue in output:
                    result.issues.append({
                        'file': issue.get('filename'),
                        'line': issue.get('location', {}).get('row'),
                        'column': issue.get('location', {}).get('column'),
                        'severity': 'warning',
                        'code': issue.get('code'),
                        'message': issue.get('message'),
                        'fix': issue.get('fix')
                    })

                result.success = True
                logger.info(f"Ruff found {len(result.issues)} issues")

        except FileNotFoundError:
            result.error_message = "Ruff not installed. Install with: pip install ruff"
            logger.warning(result.error_message)
        except subprocess.TimeoutExpired:
            result.error_message = "Ruff timed out"
            logger.error(result.error_message)
        except Exception as e:
            result.error_message = str(e)
            logger.error(f"Ruff error: {e}")

        return result

    def run_all(self, path: str) -> Dict[str, LinterResult]:
        """Run all enabled linters"""
        self.results = {}

        # Run each linter
        self.results['bandit'] = self.run_bandit(path)
        self.results['semgrep'] = self.run_semgrep(path)
        self.results['pylint'] = self.run_pylint(path)
        self.results['ruff'] = self.run_ruff(path)

        return self.results

    def get_aggregated_results(self) -> Dict[str, Any]:
        """Get aggregated results from all linters"""
        total_issues = 0
        by_severity = {'critical': 0, 'high': 0,
                       'medium': 0, 'low': 0, 'info': 0}
        by_source = {}  # Count issues by tool
        all_issues = []

        for tool_name, result in self.results.items():
            if result.success:
                total_issues += len(result.issues)
                by_source[tool_name] = len(
                    result.issues)  # Track issues per tool

                for issue in result.issues:
                    # Normalize severity
                    severity = self._normalize_severity(
                        issue.get('severity', 'info'))
                    by_severity[severity] += 1

                    # Add tool name to issue
                    issue['tool'] = tool_name
                    all_issues.append(issue)

        return {
            'total_issues': total_issues,
            'by_severity': by_severity,
            'by_source': by_source,  # Add this field
            'issues': all_issues,
            'tools_run': list(self.results.keys()),
            'tools_succeeded': [name for name, res in self.results.items() if res.success]
        }

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels across different tools"""
        severity_lower = str(severity).lower()

        if severity_lower in ['critical', 'high', 'error']:
            return 'high'
        elif severity_lower in ['medium', 'warning']:
            return 'medium'
        elif severity_lower in ['low', 'convention', 'refactor']:
            return 'low'
        else:
            return 'info'


def run_all_linters(path: str) -> Dict[str, Any]:
    """
    Convenience function to run all linters

    Args:
        path: Path to file or directory to analyze

    Returns:
        Aggregated results from all linters
    """
    linter = MultiLinter()
    linter.run_all(path)
    return linter.get_aggregated_results()
