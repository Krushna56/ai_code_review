"""
Git Commit History Extractor
=============================
Extracts real commit-level data from a repository's .git folder.
Used to power the "Issues Over Time" and "Created vs Resolved Issues"
timeline charts on the dashboard.

Supports:
- Local repos with .git/ directory (cloned GitHub repos always have this)
- Fallback to estimated timeline when no .git is present (plain ZIP uploads)
"""

import os
import subprocess
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Commit classification keywords
# ─────────────────────────────────────────────────────────────────────────────

FIX_KEYWORDS = [
    'fix', 'bug', 'patch', 'hotfix', 'resolve', 'revert',
    'repair', 'correct', 'remediat', 'close', 'closes', 'closes #',
    'security', 'vuln', 'cve', 'sqli', 'xss', 'csrf', 'sanitiz',
]

FEATURE_KEYWORDS = [
    'feat', 'add', 'new', 'implement', 'create', 'introduce',
    'support', 'enable', 'init', 'initial', 'start', 'begin',
    'build', 'setup', 'scaffold', 'bootstrap',
]

REFACTOR_KEYWORDS = [
    'refactor', 'clean', 'improve', 'perf', 'optimiz', 'rename',
    'move', 'reorganiz', 'restructur', 'simplif', 'dedup',
]

DOCS_KEYWORDS = ['doc', 'readme', 'comment', 'changelog', 'license', 'typo']
TEST_KEYWORDS = ['test', 'spec', 'unittest', 'coverage', 'ci', 'lint']


def classify_commit(message: str) -> str:
    """
    Classify a commit message as one of:
    - 'fix'      → counts as a resolved/fixed issue
    - 'feature'  → counts as new code introduced (may introduce issues)
    - 'refactor' → neutral improvement
    - 'docs'     → documentation only
    - 'test'     → test changes
    - 'other'    → unclassified

    Uses conventional commit keyword matching (case-insensitive).
    """
    msg = message.lower()

    if any(kw in msg for kw in FIX_KEYWORDS):
        return 'fix'
    if any(kw in msg for kw in TEST_KEYWORDS):
        return 'test'
    if any(kw in msg for kw in DOCS_KEYWORDS):
        return 'docs'
    if any(kw in msg for kw in REFACTOR_KEYWORDS):
        return 'refactor'
    if any(kw in msg for kw in FEATURE_KEYWORDS):
        return 'feature'
    return 'other'


def has_git_repo(repo_path: str) -> bool:
    """Check if a path contains a valid git repository."""
    git_dir = os.path.join(repo_path, '.git')
    return os.path.isdir(git_dir)


def extract_git_log(repo_path: str, days: int = 90) -> List[Dict[str, Any]]:
    """
    Run `git log` on a repository and return structured commit entries.

    Args:
        repo_path: Path to the root of the git repository
        days: How many days of history to fetch

    Returns:
        List of commit dicts, each with: hash, date, message, author, type
        Returns [] if repo has no .git or git is not available.
    """
    if not has_git_repo(repo_path):
        logger.info(f"No .git directory found at {repo_path} — skipping git log")
        return []

    since_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    cmd = [
        'git', '-C', repo_path, 'log',
        f'--since={since_date}',
        '--pretty=format:%H|||%ad|||%s|||%ae',
        '--date=short',
        '--no-merges',
    ]

    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=30,
            encoding='utf-8',
            errors='ignore'
        )

        commits = []
        for line in out.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split('|||', 3)
            if len(parts) < 4:
                continue

            commit_hash, date_str, message, author = parts
            commit_type = classify_commit(message)

            commits.append({
                'hash':    commit_hash[:8],
                'date':    date_str.strip(),   # YYYY-MM-DD
                'message': message.strip(),
                'author':  author.strip(),
                'type':    commit_type,
            })

        logger.info(f"Extracted {len(commits)} commits from git log (last {days} days)")
        return commits

    except subprocess.TimeoutExpired:
        logger.warning("git log timed out — skipping commit history")
        return []
    except subprocess.CalledProcessError as e:
        logger.warning(f"git log failed: {e}")
        return []
    except FileNotFoundError:
        logger.warning("git not found in PATH — skipping commit history")
        return []
    except Exception as e:
        logger.error(f"Unexpected error in extract_git_log: {e}")
        return []


def extract_file_churn(repo_path: str, days: int = 90) -> Dict[str, int]:
    """
    Extract file churn (number of times each file was modified) from git log.

    Returns:
        Dict mapping file path → churn count
    """
    if not has_git_repo(repo_path):
        return {}

    since_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    cmd = [
        'git', '-C', repo_path, 'log',
        f'--since={since_date}',
        '--name-only',
        '--pretty=format:',
        '--no-merges',
    ]

    try:
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=30,
            encoding='utf-8',
            errors='ignore'
        )

        churn: Dict[str, int] = defaultdict(int)
        for line in out.strip().splitlines():
            f = line.strip()
            if f:
                churn[f] += 1

        return dict(churn)

    except Exception as e:
        logger.warning(f"File churn extraction failed: {e}")
        return {}


def build_issue_timeline(
    commits: List[Dict[str, Any]],
    total_issues: int = 0,
    days: int = 30,
) -> Dict[str, Any]:
    """
    Build the daily issue timeline from git commit data.

    Strategy:
    - 'fix' commits on a day → resolved issues for that day
    - 'feature'/'other' commits → potentially introduced new issues (weighted)
    - Counts are scaled proportionally to the total_issues count

    Args:
        commits:      List of commit dicts from extract_git_log()
        total_issues: Total issues found by static analysis
        days:         Number of days for the timeline window

    Returns:
        Dict with labels, new_issues, resolved_issues, commit_count, has_git
    """
    today = datetime.now().date()
    date_range = [
        (today - timedelta(days=i)).isoformat()
        for i in range(days - 1, -1, -1)
    ]

    # Index commits by date
    commits_by_date: Dict[str, List[Dict]] = defaultdict(list)
    for c in commits:
        d = c.get('date', '')
        if d:
            commits_by_date[d].append(c)

    new_per_day = []
    resolved_per_day = []

    # Scale factor: distribute total issues across commit activity
    # More active days get proportionally more issues
    total_commit_weight = sum(
        len(commits_by_date.get(d, [])) for d in date_range
    )
    scale = (total_issues / max(1, total_commit_weight)) if total_issues else 1

    for date_str in date_range:
        day_commits = commits_by_date.get(date_str, [])

        fix_count     = sum(1 for c in day_commits if c['type'] == 'fix')
        feature_count = sum(1 for c in day_commits if c['type'] in ('feature', 'other'))

        # Resolved issues: fix commits drive resolution
        resolved = round(fix_count * scale * 1.2)
        # New issues: feature/other commits introduce new code (and bugs)
        new = round(feature_count * scale * 0.8)

        resolved_per_day.append(resolved)
        new_per_day.append(new)

    return {
        'labels':          date_range,
        'new_issues':      new_per_day,
        'resolved_issues': resolved_per_day,
        'commit_count':    len(commits),
        'has_git':         len(commits) > 0,
        'source':          'git' if len(commits) > 0 else 'estimated',
    }


def build_fallback_timeline(total_issues: int = 50, days: int = 30) -> Dict[str, Any]:
    """
    Generate a realistic estimated timeline when no git history is available.
    Uses a sine-wave pattern to simulate realistic issue trends.

    Args:
        total_issues: Total issues to distribute
        days:         Number of days to simulate

    Returns:
        Same structure as build_issue_timeline() but with source='estimated'
    """
    import math

    today = datetime.now().date()
    date_range = [
        (today - timedelta(days=i)).isoformat()
        for i in range(days - 1, -1, -1)
    ]

    base = max(1, total_issues // days)
    new_per_day = []
    resolved_per_day = []

    for i in range(days):
        # Sine wave with noise gives realistic-looking trends
        wave = math.sin(i * math.pi / 7)              # weekly cycle
        new  = max(0, round(base * (1 + 0.5 * wave)))
        resolved = max(0, round(base * (0.8 + 0.3 * math.cos(i * math.pi / 10))))

        new_per_day.append(new)
        resolved_per_day.append(resolved)

    return {
        'labels':          date_range,
        'new_issues':      new_per_day,
        'resolved_issues': resolved_per_day,
        'commit_count':    0,
        'has_git':         False,
        'source':          'estimated',
    }


def analyze_repo_git(repo_path: str, total_issues: int = 0, timeline_days: int = 30) -> Dict[str, Any]:
    """
    Main entry point: extract all git data for a repository.

    Args:
        repo_path:     Path to the uploaded/cloned repo
        total_issues:  Total issues found by static analysis (for scaling)
        timeline_days: Days of history for the timeline charts

    Returns:
        Dict with timeline data + file churn + commit stats
    """
    commits = extract_git_log(repo_path, days=max(timeline_days, 90))
    file_churn = extract_file_churn(repo_path, days=90)

    if commits:
        timeline = build_issue_timeline(commits, total_issues, days=timeline_days)
    else:
        timeline = build_fallback_timeline(total_issues, days=timeline_days)

    return {
        'timeline':         timeline,
        'file_churn':       file_churn,
        'total_commits':    len(commits),
        'has_git':          len(commits) > 0,
        'authors':          list({c['author'] for c in commits}),
        'commit_types': {
            'fix':      sum(1 for c in commits if c['type'] == 'fix'),
            'feature':  sum(1 for c in commits if c['type'] == 'feature'),
            'refactor': sum(1 for c in commits if c['type'] == 'refactor'),
            'test':     sum(1 for c in commits if c['type'] == 'test'),
            'docs':     sum(1 for c in commits if c['type'] == 'docs'),
            'other':    sum(1 for c in commits if c['type'] == 'other'),
        },
    }
