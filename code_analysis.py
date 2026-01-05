import os
import json
from autopep8 import fix_code
import difflib
from bandit.core import manager as bandit_manager
from bandit.core import config as bandit_config

def highlight_code_diff(original_code, modified_code):
    """
    Highlights differences in modified code using <span class="highlight">.
    Only highlights added or changed lines.
    """
    original_lines = original_code.splitlines()
    modified_lines = modified_code.splitlines()
    diff = list(difflib.ndiff(original_lines, modified_lines))

    highlighted = []
    for line in diff:
        if line.startswith('+ '):
            highlighted.append(f'<span class="highlight">{line[2:]}</span>')
        elif line.startswith('? '):
            continue
        elif line.startswith('  '):
            highlighted.append(line[2:])
        # Do not include removed lines
    return '\n'.join(highlighted)


def analyze_codebase(input_path, output_path):
    summary = {
        "bugs_fixed": 0,
        "security_issues": 0,
        "smells_removed": 0,
        "files_updated": 0
    }
    details = {}

    for root, _, files in os.walk(input_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, input_path)

                with open(file_path, "r", encoding="utf-8") as f:
                    original_code = f.read()

                formatted_code = fix_code(original_code)

                # Save formatted version to disk (overwriting original)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_code)

                # Save before/after version in memory
                details[rel_path] = {
                    "before": original_code,
                    "after": highlight_code_diff(original_code, formatted_code)
                }

                summary["bugs_fixed"] += 1
                summary["files_updated"] += 1

    # Run Bandit using Python API instead of subprocess
    try:
        # Create Bandit config
        b_conf = bandit_config.BanditConfig()
        
        # Create manager and run scan
        b_mgr = bandit_manager.BanditManager(b_conf, 'file')
        b_mgr.discover_files([input_path], True)
        b_mgr.run_tests()
        
        issues = [issue.as_dict() for issue in b_mgr.results]
        summary["security_issues"] = len(issues)

        # Save results to JSON file
        bandit_output_path = os.path.join(output_path, "bandit.json")
        with open(bandit_output_path, "w", encoding="utf-8") as f:
            json.dump({"results": issues}, f, indent=2)

        if not issues:
            security_report = "✅ No major security issues found by Bandit!"
        else:
            security_report = f"⚠️ Found {len(issues)} potential security issues:\n\n"
            for issue in issues[:5]:
                security_report += (
                    f"🔍 **{issue.get('test_id', 'N/A')}**: {issue.get('issue_text', 'N/A')} at "
                    f"{issue.get('filename', 'N/A')}:{issue.get('line_number', 'N/A')}\n"
                )
            if len(issues) > 5:
                security_report += f"\n...and {len(issues) - 5} more."
    except Exception as e:
        security_report = (
            "❌ Bandit failed to analyze your code.\n"
            "It might be due to malformed Python files or unexpected structure.\n"
            f"**Error Log**: {str(e)}"
        )

    return {
        "summary": summary,
        "details": details,
        "security": security_report
    }