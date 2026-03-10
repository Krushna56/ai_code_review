#!/usr/bin/env python
"""Test Flask app functionality"""
import sys

print("Testing Flask app...")

try:
    print("1. Importing and creating Flask app...")
    from app import app
    print("   ✓ Flask app created")
    
    print("2. Creating test client...")
    with app.app_context():
        client = app.test_client()
        print("   ✓ Test client created")
        
        print("3. Testing /health endpoint...")
        response = client.get('/health')
        print(f"   Status: {response.status_code}")
        print(f"   Data: {response.get_json()}")
        
        if response.status_code == 200:
            print("   ✓ /health endpoint working")
        else:
            print(f"   ✗ /health endpoint returned {response.status_code}")
            sys.exit(1)
    
    print("\n✓ Flask app is working!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
