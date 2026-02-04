"""
Test Chat API Endpoints
"""
import requests
import json

BASE_URL = "http://localhost:5000"

print("Testing Chat API Endpoints...")
print("=" * 50)

# Test 1: Create Session
print("\n1. Testing POST /api/v2/chat/session")
try:
    response = requests.post(
        f"{BASE_URL}/api/v2/chat/session",
        json={"user_id": "test_user", "metadata": {"test": True}},
        timeout=10
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 201:
        data = response.json()
        session_id = data.get('session_id')
        print(f"[OK] Session created: {session_id}")
        
        # Test 2: Send Message
        print("\n2. Testing POST /api/v2/chat/message")
        response2 = requests.post(
            f"{BASE_URL}/api/v2/chat/message",
            json={"session_id": session_id, "message": "Hello"},
            timeout=30
        )
        print(f"Status Code: {response2.status_code}")
        print(f"Response: {response2.text[:500]}")
        
        if response2.status_code == 200:
            print("[OK] Message sent successfully")
        else:
            print(f"[ERROR] Message failed")
    else:
        print(f"[ERROR] Session creation failed")
        
except requests.exceptions.ConnectionError:
    print("[ERROR] Cannot connect to server. Is Flask running on port 5000?")
except requests.exceptions.Timeout:
    print("[ERROR] Request timed out")
except Exception as e:
    print(f"[ERROR] {type(e).__name__}: {str(e)}")
