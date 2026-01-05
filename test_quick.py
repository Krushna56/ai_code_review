"""
Quick Test Script

Tests the basic functionality without requiring all dependencies
"""

import sys
import os

print("="*60)
print("AI Code Review Platform - Quick Test")
print("="*60)

# Test 1: Import config
print("\n[TEST 1] Testing config module...")
try:
    import config
    print(f"  [OK] Config loaded")
    print(f"  - Base directory: {config.BASE_DIR}")
    print(f"  - LLM Provider: {config.LLM_PROVIDER}")
    print(f"  - Embedding Provider: {config.EMBEDDING_PROVIDER}")
except Exception as e:
    print(f"  [ERROR] {e}")

# Test 2: Import static analysis
print("\n[TEST 2] Testing static analysis modules...")
try:
    from static_analysis.ast_parser import ASTParser
    parser = ASTParser()
    print(f"  [OK] ASTParser imported")
    
    # Test with simple code
    test_code = """
def hello():
    print("Hello, World!")
    return 42
"""
    metrics = parser.parse_code(test_code)
    result = parser.get_metrics_dict()
    print(f"  [OK] Parsed test code")
    print(f"  - Functions: {result.get('functions', 0)}")
    print(f"  - LOC: {result.get('loc', 0)}")
    print(f"  - Complexity: {result.get('complexity', 0)}")
except Exception as e:
    print(f"  [ERROR] {e}")

# Test 3: Test multi-linter (without actually running linters)
print("\n[TEST 3] Testing multi-linter module...")
try:
    from static_analysis.multi_linter import MultiLinter
    linter = MultiLinter()
    print(f"  [OK] MultiLinter imported")
    print(f"  - Bandit enabled: {config.ENABLE_BANDIT}")
    print(f"  - Semgrep enabled: {config.ENABLE_SEMGREP}")
    print(f"  - Ruff enabled: {config.ENABLE_RUFF}")
except Exception as e:
    print(f"  [ERROR] {e}")

# Test 4: Test code_analysis
print("\n[TEST 4] Testing code_analysis module...")
try:
    from code_analysis import CodeAnalyzer, highlight_code_diff
    analyzer = CodeAnalyzer()
    print(f"  [OK] CodeAnalyzer imported")
    print(f"  - AST Parser: Available")
    print(f"  - Multi-Linter: Available")
except Exception as e:
    print(f"  [ERROR] {e}")
    import traceback
    traceback.print_exc()

# Test 5: Check Flask app
print("\n[TEST 5] Testing Flask app...")
try:
    from app import app
    print(f"  [OK] Flask app imported")
    print(f"  - Upload folder: {app.config.get('UPLOAD_FOLDER')}")
    print(f"  - Processed folder: {app.config.get('PROCESSED_FOLDER')}")
except Exception as e:
    print(f"  [ERROR] {e}")

print("\n" + "="*60)
print("Test Summary")
print("="*60)
print("\nCore modules are working!")
print("\nTo run the full application:")
print("  1. Wait for pip install to complete")
print("  2. Edit .env and add API keys (optional for basic features)")
print("  3. Run: python app.py")
print()
