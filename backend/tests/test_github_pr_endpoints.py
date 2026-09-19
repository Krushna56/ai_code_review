"""
Tests for 1-Click GitHub PR Creation and Fix Remediation
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, session
from services.github_service import GitHubAPIClient
from api.github_routes import github_bp
from auth.jwt_utils import JWTManager


@pytest.fixture
def pr_test_app():
    """Create Flask application configured for PR testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-for-github-pr'
    app.config['UPLOAD_FOLDER'] = 'test_uploads'
    app.register_blueprint(github_bp)
    return app


@pytest.fixture
def pr_test_client(pr_test_app):
    return pr_test_app.test_client()


def test_create_security_pr_unit():
    """Test GitHubAPIClient.create_security_pr with mocked GitHub HTTP calls"""
    client = GitHubAPIClient(access_token="ghp_mock_token_12345")

    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.put') as mock_put:

        # 1. Mock base branch ref check
        mock_ref_resp = MagicMock()
        mock_ref_resp.status_code = 200
        mock_ref_resp.json.return_value = {'object': {'sha': 'base_sha_abc123'}}
        mock_get.side_effect = [
            mock_ref_resp,  # heads/main
            MagicMock(status_code=404)  # contents/test.py (new file, no sha)
        ]

        # 2. Mock create branch ref
        mock_branch_resp = MagicMock()
        mock_branch_resp.status_code = 201
        mock_branch_resp.json.return_value = {'ref': 'refs/heads/security-patch-test'}
        
        # 3. Mock PR creation
        mock_pr_resp = MagicMock()
        mock_pr_resp.status_code = 201
        mock_pr_resp.json.return_value = {
            'html_url': 'https://github.com/octocat/Hello-World/pull/42',
            'number': 42,
            'title': 'Fix: Patch vulnerability',
            'state': 'open'
        }
        mock_post.side_effect = [mock_branch_resp, mock_pr_resp]

        # 4. Mock commit file
        mock_put_resp = MagicMock()
        mock_put_resp.status_code = 200
        mock_put_resp.json.return_value = {'commit': {'sha': 'new_commit_sha'}}
        mock_put.return_value = mock_put_resp

        result = client.create_security_pr(
            owner="octocat",
            repo="Hello-World",
            title="Fix: Patch vulnerability",
            body="Remediating vulnerability",
            file_path="./src/app.py",
            file_content="# safe code here\n",
            commit_message="Security patch",
            base_branch="main"
        )

        assert result is not None
        assert result['number'] == 42
        assert result['url'] == 'https://github.com/octocat/Hello-World/pull/42'
        assert result['base_branch'] == 'main'


def test_raise_pr_unauthorized(pr_test_client):
    """Test /api/github/raise-pr requires authentication"""
    resp = pr_test_client.post('/api/github/raise-pr', json={
        'owner': 'test',
        'repo': 'repo',
        'file_path': 'test.py',
        'file_content': 'code'
    })
    assert resp.status_code == 401
    assert 'Authentication required' in resp.get_json()['error']


def test_raise_pr_validation(pr_test_app, pr_test_client):
    """Test validation errors on /api/github/raise-pr"""
    valid_token = JWTManager.generate_tokens(user_id=1, email='test@example.com')['access_token']

    with pr_test_client.session_transaction() as sess:
        sess['jwt_access_token'] = valid_token
        sess['github_access_token'] = 'ghp_mock'

    # Missing repo
    resp = pr_test_client.post('/api/github/raise-pr', json={
        'file_path': 'test.py',
        'file_content': 'code'
    })
    assert resp.status_code == 400
    assert 'Target repository' in resp.get_json()['error']

    # Missing file path
    resp = pr_test_client.post('/api/github/raise-pr', json={
        'owner': 'owner',
        'repo': 'repo',
        'file_content': 'code'
    })
    assert resp.status_code == 400
    assert 'File path' in resp.get_json()['error']


def test_raise_pr_success(pr_test_client):
    """Test successful PR dispatch via endpoint"""
    valid_token = JWTManager.generate_tokens(user_id=1, email='test@example.com')['access_token']

    with pr_test_client.session_transaction() as sess:
        sess['jwt_access_token'] = valid_token
        sess['github_access_token'] = 'ghp_mock_token_123'

    with patch.object(GitHubAPIClient, 'create_security_pr') as mock_create_pr:
        mock_create_pr.return_value = {
            'url': 'https://github.com/test-org/test-repo/pull/101',
            'html_url': 'https://github.com/test-org/test-repo/pull/101',
            'number': 101,
            'branch': 'security-patch-abcd1234',
            'base_branch': 'main'
        }

        resp = pr_test_client.post('/api/github/raise-pr', json={
            'owner': 'test-org',
            'repo': 'test-repo',
            'file_path': 'src/security.py',
            'file_content': 'def safe_method(): pass\n',
            'title': 'Fix: Hardcoded credential'
        })

        assert resp.status_code == 201
        data = resp.get_json()
        assert data['status'] == 'success'
        assert data['pr_number'] == 101
        assert 'https://github.com/test-org/test-repo/pull/101' in data['url']


def test_generate_fix_endpoint(pr_test_client):
    """Test /api/github/generate-fix generates diff and explanation"""
    valid_token = JWTManager.generate_tokens(user_id=1, email='test@example.com')['access_token']

    with pr_test_client.session_transaction() as sess:
        sess['jwt_access_token'] = valid_token

    sample_original = 'import os\npassword = "secret_password_123"\n'
    
    resp = pr_test_client.post('/api/github/generate-fix', json={
        'file_path': 'config.py',
        'original_content': sample_original,
        'finding': {
            'title': 'Hardcoded Secret Detected',
            'type': 'hardcoded_secret',
            'severity': 'HIGH',
            'description': 'Found API key or secret in plain text'
        }
    })

    assert resp.status_code == 200
    data = resp.get_json()
    assert data['status'] == 'success'
    assert 'explanation' in data
    assert 'diff' in data
    assert 'difficulty' in data
