"""
Test OpenAI API Connection
"""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

api_key = os.getenv('OPENAI_API_KEY')
print(f"API Key loaded: {api_key[:20]}..." if api_key else "API Key: None")
print(f"API Key length: {len(api_key) if api_key else 0}")

try:
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    
    print("\n[OK] OpenAI client initialized successfully")
    
    # Test a simple completion
    print("\nTesting API call...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Say 'Hello, chatbot is working!'"}],
        max_tokens=50
    )
    
    print(f"[OK] API call successful!")
    print(f"Response: {response.choices[0].message.content}")
    
except Exception as e:
    print(f"\n[ERROR] {type(e).__name__}: {str(e)}")
