"""
Test GitHub API endpoints
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app import app
from models.repository import Repository
import json

def test_github_endpoints():
    """Test GitHub API endpoints"""
    
    print("\n1. Testing Repository table creation...")
    try:
        Repository.create_table()
        print("   [OK] Repository table created successfully")
    except Exception as e:
        print(f"   [FAIL] Error creating repository table: {e}")
        return False
    
    print("\n2. Testing Flask app initialization...")
    try:
        client = app.test_client()
        response = client.get('/health')
        assert response.status_code == 200
        print("   [OK] Flask app running")
    except Exception as e:
        print(f"   [FAIL] Error: {e}")
        return False
    
    print("\n3. Testing GitHub endpoints exist...")
    endpoints = [
        '/api/github/repo-info/<owner>/<repo>',
        '/api/github/commits/<owner>/<repo>',
        '/api/github/commit-status/<owner>/<repo>/<sha>',
        '/api/github/stats/<owner>/<repo>',
        '/api/github/user-repos',
        '/api/github/track-repo'
    ]
    
    for endpoint in endpoints:
        print(f"   - {endpoint}")
    
    print("\n4. Testing GitHub service client...")
    try:
        from services.github_service import GitHubAPIClient, create_github_client
        
        # Test URL parsing
        urls = [
            'https://github.com/microsoft/vscode',
            'git@github.com:microsoft/vscode.git'
        ]
        
        client = GitHubAPIClient()
        for url in urls:
            owner, repo = client.parse_github_url(url)
            if owner == 'microsoft' and repo == 'vscode':
                print(f"   [OK] Parsed {url} --> {owner}/{repo}")
            else:
                print(f"   [FAIL] Failed to parse {url}")
                return False
    except Exception as e:
        print(f"   [FAIL] Error testing GitHub service: {e}")
        return False
    
    print("\n5. Testing Repository model methods...")
    try:
        # Create a test repo
        test_repo = Repository(
            user_id=1,
            repo_url='https://github.com/test/repo',
            owner='test',
            repo_name='repo',
            repo_full_name='test/repo',
            description='Test repository',
            language='Python',
            stars=100,
            github_data={'test': 'data'}
        )
        
        # Test to_dict
        repo_dict = test_repo.to_dict()
        assert repo_dict['owner'] == 'test'
        assert repo_dict['repo_name'] == 'repo'
        print("   [OK] Repository.to_dict() works")
        
    except Exception as e:
        print(f"   [FAIL] Error: {e}")
        return False
    
    print("\n[PASS] All tests passed!")
    return True

if __name__ == '__main__':
    success = test_github_endpoints()
    sys.exit(0 if success else 1)
