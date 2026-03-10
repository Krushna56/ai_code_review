#!/usr/bin/env python
"""Test script to check all imports"""
import sys
import signal

print("Starting import test...")

try:
    print("1. Importing config...")
    import config
    print("   ✓ config imported")
except Exception as e:
    print(f"   ✗ Error importing config: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

try:
    print("2. Importing analyzer...")
    import analyzer
    print("   ✓ analyzer imported")
except Exception as e:
    print(f"   ✗ Error importing analyzer: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

try:
    print("3. Importing app...")
    from app import app
    print("   ✓ app imported")
except Exception as e:
    print(f"   ✗ Error importing app: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✓ All imports successful!")
