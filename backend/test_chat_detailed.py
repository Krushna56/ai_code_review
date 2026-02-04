"""
Test Chat API with detailed error capture
"""
import requests
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:5000"

print("Testing Chat Message with Error Capture...")
print("=" * 50)

# Create session first
print("\n1. Creating session...")
session_response = requests.post(
    f"{BASE_URL}/api/v2/chat/session",
    json={"user_id": "test_user"},
    timeout=10
)

if session_response.status_code != 201:
    print(f"[ERROR] Failed to create session: {session_response.text}")
    exit(1)

session_id = session_response.json()['session_id']
print(f"[OK] Session ID: {session_id}")

# Send a test message
print("\n2. Sending test message...")
message_response = requests.post(
    f"{BASE_URL}/api/v2/chat/message",
    json={
        "session_id": session_id,
        "message": "Hello, can you help me?"
    },
    timeout=30
)

print(f"\nStatus Code: {message_response.status_code}")
print(f"\nFull Response:")
print(json.dumps(message_response.json(), indent=2))

# Check if it's the error message
response_data = message_response.json()
if "I apologize, but I encountered an error" in response_data.get('content', ''):
    print("\n[ERROR] Chatbot returned error message!")
    print("This means the LLM API call is failing.")
    print("\nPossible causes:")
    print("1. OpenAI API quota exceeded")
    print("2. Invalid API key")
    print("3. Model name incorrect")
    print("4. Network/firewall blocking OpenAI API")
    print("\nCheck the Flask server logs for detailed error messages.")
else:
    print("\n[OK] Chatbot responded successfully!")
