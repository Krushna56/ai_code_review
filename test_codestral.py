"""
Quick test script to verify Codestral integration
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from llm_agents.security_reviewer import SecurityReviewer

def test_codestral():
    """Test Codestral integration"""
    print("=" * 60)
    print("Testing Codestral Integration")
    print("=" * 60)
    
    # Check configuration
    print(f"\n[*] LLM Provider: {config.LLM_PROVIDER}")
    print(f"[*] LLM Model: {config.LLM_MODEL}")
    print(f"[*] API Key configured: {'Yes' if config.MISTRAL_API_KEY else 'No'}")
    
    if not config.MISTRAL_API_KEY:
        print("\n[ERROR] MISTRAL_API_KEY not found in .env file")
        print("Please add: MISTRAL_API_KEY=your_key_here")
        return False
    
    # Initialize agent
    print("\nInitializing Codestral agent...")
    try:
        agent = SecurityReviewer(provider='mistral', model='codestral-latest')
        print("[*] Agent initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize agent: {e}")
        return False
    
    # Test code for analysis
    test_code = """
def calculate_sum(numbers):
    total = 0
    for num in numbers:
        total += num
    return total

# Potential security issue: SQL injection
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)
"""
    
    # Test generation
    print("\nTesting code analysis with Codestral...")
    try:
        result = agent.generate(
            prompt=f"Review this Python code for potential issues and suggest improvements:\n\n{test_code}",
            system_prompt="You are an expert code reviewer focused on security and best practices."
        )
        
        print("\n" + "=" * 60)
        print("Codestral Analysis Result:")
        print("=" * 60)
        print(result)
        print("=" * 60)
        print("\n[SUCCESS] Codestral integration working successfully!")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Error during analysis: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_codestral()
    sys.exit(0 if success else 1)
