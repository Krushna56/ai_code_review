"""
Setup and Installation Script

Run this script to set up the AI Code Review Platform
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"\n{'='*60}")
    print(f"[*] {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        print(f"[OK] {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {e}")
        print(e.stderr)
        return False


def check_python_version():
    """Check if Python version is 3.8+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"[ERROR] Python 3.8+ required. You have Python {version.major}.{version.minor}")
        return False
    print(f"[OK] Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def create_env_file():
    """Create .env file from .env.example if it doesn't exist"""
    if not Path('.env').exists():
        if Path('.env.example').exists():
            import shutil
            shutil.copy('.env.example', '.env')
            print("[OK] Created .env file from .env.example")
            print("[WARNING] Please edit .env and add your API keys!")
            return True
        else:
            print("[ERROR] .env.example not found")
            return False
    else:
        print("[INFO] .env file already exists")
        return True


def main():
    """Main setup function"""
    print("""
    ============================================================
       AI-Powered Code Review Platform - Setup Script
    ============================================================
    """)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not run_command(
        f"{sys.executable} -m pip install -r requirements.txt",
        "Installing dependencies"
    ):
        print("\n[WARNING] Some dependencies failed to install.")
        print("   Try: pip install -r requirements.txt")
    
    # Create .env file
    create_env_file()
    
    # Create necessary directories
    print("\n[*] Creating directories...")
    directories = ['uploads', 'processed', 'models', 'vector_db', 'vector_db/embedding_cache']
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"   [OK] {dir_name}/")
    
    print(f"\n{'='*60}")
    print("[SUCCESS] Setup Complete!")
    print(f"{'='*60}")
    print("\nNext Steps:")
    print("   1. Edit .env file and add your API keys:")
    print("      - OPENAI_API_KEY (for OpenAI)")
    print("      - ANTHROPIC_API_KEY (for Claude)")
    print("   2. Configure feature flags in .env")
    print("   3. Run the application:")
    print("      python app.py")
    print("\nDocumentation: README.md")
    print("GitHub: https://github.com/Krushna56/ai_code_review")
    print()


if __name__ == "__main__":
    main()
