from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

# Test with gemini-2.5-flash
try:
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents='Summarize this in one sentence: This is a test document about AI'
    )
    print("SUCCESS!")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"ERROR: {e}")
