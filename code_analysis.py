import os
import zipfile
import ast
# import bandit
import black
import subprocess
import shutil
import json
# from bandit.core.manager import BanditManager
# from bandit.core.config import Config
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from radon.raw import analyze

def extract_codebase(zip_path, extract_to='uploads/extracted'):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    return extract_to

def get_code_files(directory, extensions=('.py',)):
    code_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(extensions):
                code_files.append(os.path.join(root, file))
    return code_files



def analyze_python_file(file_path):
    issues = {
        "syntax_error": False,
        "complexity_score": 0,
        "functions": 0,
        "classes": 0,
    }
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                issues["functions"] += 1
            elif isinstance(node, ast.ClassDef):
                issues["classes"] += 1

        # Basic fake complexity = functions + classes for now
        issues["complexity_score"] = issues["functions"] * 1.5 + issues["classes"] * 2

    except SyntaxError:
        issues["syntax_error"] = True

    return issues

def analyze_codebase(path):
    report = {
        "total_files": 0,
        "files_with_errors": [],
        "summary": {
            "bugs_fixed": 0,
            "security_issues": 0,
            "smells_removed": 0,
            "files_updated": 0,
        }
    }

    code_files = get_code_files(path)
    report["total_files"] = len(code_files)

    for file_path in code_files:
        result = analyze_python_file(file_path)
        if result["syntax_error"]:
            report["files_with_errors"].append(file_path)
        # We'll later increase summary counts based on actual fixes
        report["summary"]["files_updated"] += 1

    return report

def run_bandit_scan(target_path):
    config = Config()
    manager = BanditManager(config, 'file')
    manager.discover_files([target_path])
    manager.run_tests()
    # Gather results summary
    issues = []
    for result in manager.results:
        issues.append({
            'filename': result.fname,
            'line_number': result.lineno,
            'issue_text': result.text,
            'severity': result.severity,
            'confidence': result.confidence,
        })
    return issues

def auto_format_code(code_str):
    try:
        formatted_code = black.format_str(code_str, mode=black.Mode())
        return formatted_code
    except black.NothingChanged:
        return code_str

def analyze_code_smells(code_str):
    complexity_results = cc_visit(code_str)
    maintainability_score = mi_visit(code_str, True)
    return {
        "complexity": complexity_results,
        "maintainability": maintainability_score,
    }

def analyze_codebase(path):
    # 1. Run Bandit for security
    security_issues = run_bandit_scan(path)
    
    # 2. Read and auto-format code files
    # (Walk through files, read content, run auto_format_code)
    
    # 3. Run code smell & complexity detection
    # (Analyze each file's code string)
    
    # 4. Aggregate summary
    summary = {
        'bugs_fixed': 0,  # Placeholder, update after fixes
        'security_issues': len(security_issues),
        'smells_removed': 0,  # Update accordingly
        'files_updated': 0,   # Count files reformatted/refactored
    }
    
    # Return both summary and detailed report
    return summary, {
        'security_issues': security_issues,
        # add other details
    }


def run_bandit_scan(path):
    result_file = os.path.join(path, "bandit_output.json")
    try:
        subprocess.run([
            "bandit", "-r", path, "-f", "json", "-o", result_file
        ], check=True)
        with open(result_file, "r") as f:
            data = json.load(f)
        os.remove(result_file)
        return data["results"]
    except Exception as e:
        print("Bandit scan failed:", e)
        return []


def auto_format_code(file_path):
    try:
        subprocess.run(["black", file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print("Black formatting failed:", e)


def analyze_code_complexity(file_content):
    smells = cc_visit(file_content)
    mi_score = mi_visit(file_content, True)
    raw = analyze(file_content)
    return {
        "smells": len([s for s in smells if s.complexity > 10]),
        "mi_score": mi_score,
        "loc": raw.loc,
        "lloc": raw.lloc,
        "sloc": raw.sloc
    }


def process_code_file(file_path, output_path):
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    metrics = analyze_code_complexity(content)

    # Refactor
    auto_format_code(file_path)

    # Copy updated file to output directory
    rel_path = os.path.relpath(file_path)
    dest_path = os.path.join(output_path, rel_path)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy(file_path, dest_path)

    return metrics


def analyze_codebase(input_dir, output_dir):
    summary = {
        "bugs_fixed": 0,
        "security_issues": 0,
        "smells_removed": 0,
        "files_updated": 0
    }

    file_metrics = []
    security_issues = run_bandit_scan(input_dir)
    summary["security_issues"] = len(security_issues)

    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                metrics = process_code_file(file_path, output_dir)

                summary["smells_removed"] += metrics["smells"]
                summary["files_updated"] += 1

                file_metrics.append({
                    "file": file_path,
                    "metrics": metrics
                })

    return {
        "summary": summary,
        "details": file_metrics,
        "security": security_issues
    }

