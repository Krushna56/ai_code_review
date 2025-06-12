import os
import subprocess
import json
import shutil
import tempfile

def run_bandit_analysis(code_path):
    try:
        result = subprocess.run(
            ['bandit', '-r', code_path, '-f', 'json'],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        return {
            "error": True,
            "message": "Bandit failed to analyze the code. This usually happens if the uploaded folder doesn't contain valid Python files or the structure is unsupported."
        }

def run_autopep8_analysis(code_path):
    issues = []
    for root, _, files in os.walk(code_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                result = subprocess.run(
                    ['autopep8', '--diff', file_path],
                    capture_output=True,
                    text=True
                )
                if result.stdout:
                    issues.append({"file": file_path, "diff": result.stdout})
    return issues

def analyze_codebase(input_path, output_path):
    os.makedirs(output_path, exist_ok=True)

    # Run Bandit for security checks
    bandit_result = run_bandit_analysis(input_path)
    security_report = []

    if isinstance(bandit_result, dict) and bandit_result.get("error"):
        security_report.append({"type": "error", "message": bandit_result["message"]})
    else:
        for result in bandit_result.get("results", []):
            security_report.append({
                "filename": result.get("filename"),
                "issue_text": result.get("issue_text"),
                "line_number": result.get("line_number"),
                "severity": result.get("issue_severity"),
                "confidence": result.get("issue_confidence"),
                "code": result.get("code")
            })

    # Run autopep8 for formatting issues
    pep8_issues = run_autopep8_analysis(input_path)

    # Summary
    summary = {
        "bugs_fixed": len(pep8_issues),
        "security_issues": len(security_report) if isinstance(security_report, list) else 0,
        "smells_removed": 0,
        "files_updated": len(pep8_issues)
    }

    return {
        "summary": summary,
        "details": pep8_issues,
        "security": security_report
    }
