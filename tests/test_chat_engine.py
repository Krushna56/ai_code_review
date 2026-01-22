"""
Test Chat Engine

Unit tests for chat engine functionality
"""

from llm_agents.chat_engine import ChatEngine
from services.conversation_manager import ConversationManager
import pytest
import os
import tempfile
from pathlib import Path

# Set up test environment before imports
os.environ['LLM_PROVIDER'] = 'openai'
os.environ['OPENAI_API_KEY'] = 'test-key'  # Mock key for testing


class TestConversationManager:
    """Test conversation manager"""

    @pytest.fixture
    def manager(self):
        """Create a conversation manager with temporary database"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path = f.name

        manager = ConversationManager(db_path)
        yield manager

        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_create_session(self, manager):
        """Test session creation"""
        session_id = manager.create_session('test_user')

        assert session_id is not None
        assert len(session_id) > 0

        # Verify session exists
        session_info = manager.get_session_info(session_id)
        assert session_info is not None
        assert session_info['user_id'] == 'test_user'

    def test_add_message(self, manager):
        """Test adding messages to session"""
        session_id = manager.create_session('test_user')

        # Add user message
        msg_id = manager.add_message(
            session_id=session_id,
            role='user',
            content='Hello, AI!'
        )

        assert msg_id is not None

        # Get history
        history = manager.get_conversation_history(session_id)
        assert len(history) == 1
        assert history[0]['role'] == 'user'
        assert history[0]['content'] == 'Hello, AI!'

    def test_conversation_history(self, manager):
        """Test conversation history retrieval"""
        session_id = manager.create_session('test_user')

        # Add multiple messages
        manager.add_message(session_id, 'user', 'First message')
        manager.add_message(session_id, 'assistant', 'First response')
        manager.add_message(session_id, 'user', 'Second message')
        manager.add_message(session_id, 'assistant', 'Second response')

        # Get full history
        history = manager.get_conversation_history(session_id)
        assert len(history) == 4

        # Get limited history
        history_limited = manager.get_conversation_history(session_id, limit=2)
        assert len(history_limited) == 2
        assert history_limited[0]['content'] == 'First message'

    def test_delete_session(self, manager):
        """Test session deletion"""
        session_id = manager.create_session('test_user')
        manager.add_message(session_id, 'user', 'Test message')

        # Delete session
        result = manager.delete_session(session_id)
        assert result is True

        # Verify deleted
        session_info = manager.get_session_info(session_id)
        assert session_info is None

    def test_total_tokens(self, manager):
        """Test token counting"""
        session_id = manager.create_session('test_user')

        manager.add_message(session_id, 'user', 'Message', tokens_used=10)
        manager.add_message(session_id, 'assistant',
                            'Response', tokens_used=20)

        total = manager.get_total_tokens(session_id)
        assert total == 30


class TestChatEngine:
    """Test chat engine"""

    @pytest.fixture
    def engine(self):
        """Create chat engine with temporary database"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as f:
            db_path = f.name

        # Monkey patch the conversation manager
        original_init = ChatEngine.__init__

        def patched_init(self):
            original_init(self)
            self.conversation_manager = ConversationManager(db_path)

        ChatEngine.__init__ = patched_init
        engine = ChatEngine()
        ChatEngine.__init__ = original_init

        yield engine

        # Cleanup
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_start_session(self, engine):
        """Test starting a chat session"""
        session_id = engine.start_session('test_user')

        assert session_id is not None
        assert len(session_id) > 0

    def test_detect_intent(self, engine):
        """Test intent detection"""
        # Security intent
        intent = engine._detect_intent(
            "Are there any security vulnerabilities?")
        assert intent == 'security'

        # Refactor intent
        intent = engine._detect_intent("How can I refactor this code?")
        assert intent == 'refactor'

        # Explain intent
        intent = engine._detect_intent("Explain how this function works")
        assert intent == 'explain'

        # General intent
        intent = engine._detect_intent("What is this?")
        assert intent == 'general'

    def test_build_context(self, engine):
        """Test context building"""
        session_id = engine.start_session('test_user')

        # Add some history
        engine.conversation_manager.add_message(
            session_id, 'user', 'First question')
        engine.conversation_manager.add_message(
            session_id, 'assistant', 'First answer')

        # Build context
        context = engine._build_context(
            session_id, code_context='def foo(): pass')

        assert 'conversation_history' in context
        assert len(context['conversation_history']) == 2
        assert context['code'] == 'def foo(): pass'

    def test_conversation_export(self, engine):
        """Test conversation export"""
        session_id = engine.start_session('test_user')

        engine.conversation_manager.add_message(session_id, 'user', 'Hello')
        engine.conversation_manager.add_message(
            session_id, 'assistant', 'Hi there!')

        # Export as markdown
        markdown = engine.export_conversation(session_id, 'markdown')
        assert '# Chat Session' in markdown
        assert 'Hello' in markdown
        assert 'Hi there!' in markdown

        # Export as JSON
        import json
        json_str = engine.export_conversation(session_id, 'json')
        data = json.loads(json_str)
        assert 'session_info' in data
        assert 'messages' in data
        assert len(data['messages']) == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
