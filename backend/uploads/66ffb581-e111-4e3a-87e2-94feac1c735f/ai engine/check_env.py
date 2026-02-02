from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv('GEMINI_API_KEY', '')
secret_key = os.getenv('SECRET_KEY', '')
debug = os.getenv('DEBUG', '')

print("Environment Check:")
print(f"API Key exists: {bool(api_key)}")
print(f"API Key length: {len(api_key)}")
print(f"API Key first 10 chars: {api_key[:10] if api_key else 'EMPTY'}")
print(f"Secret Key exists: {bool(secret_key)}")
print(f"Debug value: {debug}")
