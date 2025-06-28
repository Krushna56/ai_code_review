import os
import json
import subprocess
from autopep8 import fix_code
import difflib

def contains_python_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                return True
    return False

def highlight_code_diff(original_code, modified_code):
    original_lines = original_code.splitlines()
    modified_lines = modified_code.splitlines()
    diff = list(difflib.ndiff(original_lines, modified_lines))

    highlighted_lines = []
    for line in diff:
        if line.startswith('+ '):
            highlighted_lines.append(f'<span class="highlight">{line[2:]}</span>')
        elif line.startswith('? '):
            continue
        else:
            highlighted_lines.append(line[2:] if line.startswith(('  ', '- ')) else line)

    return '\n'.join(highlighted_lines)

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

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_code)

                highlighted = highlight_code_diff(original_code, formatted_code)

                details[rel_path] = {
                    "before": original_code,
                    "after": formatted_code,
                    "highlighted": highlighted
                }

                summary["bugs_fixed"] += 1
                summary["smells_removed"] += 0
                summary["files_updated"] += 1

    try:
        if contains_python_files(input_path):
            bandit_output_path = os.path.join(output_path, "bandit.json")
            bandit_cmd = [
                "bandit", "-r", input_path, "-f", "json", "-o", bandit_output_path
            ]
            subprocess.run(bandit_cmd, check=True)
            with open(bandit_output_path, "r", encoding="utf-8") as f:
                bandit_data = json.load(f)

            issues = bandit_data.get("results", [])
            summary["security_issues"] = len(issues)

            security_report = f"🔐 Found {len(issues)} potential security issues.\n"
            for issue in issues[:5]:
                security_report += f"• [{issue['test_id']}] {issue['issue_text']} at {issue['filename']}:{issue['line_number']}\n"
            if len(issues) > 5:
                security_report += f"...and {len(issues) - 5} more issues."
        else:
            security_report = "⚠️ No Python files found. Skipped security analysis."
    except subprocess.CalledProcessError as e:
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
