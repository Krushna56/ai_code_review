"""
API v2 Routes

Enhanced API endpoints for chat, streaming, and real-time analysis.
"""

import logging
from flask import Blueprint, request, jsonify
from services.conversation_manager import ConversationManager
from services.streaming_service import StreamingService, create_sse_response
from llm_agents.chat_engine import ChatEngine

logger = logging.getLogger(__name__)

# Create blueprint
api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')

# Initialize services
conversation_manager = ConversationManager()
chat_engine = ChatEngine()
streaming_service = StreamingService()


@api_v2.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0',
        'features': ['chat', 'streaming', 'analysis']
    }), 200


# ============================================================================
# Chat Endpoints
# ============================================================================

@api_v2.route('/chat/session', methods=['POST'])
def create_chat_session():
    """
    Create a new chat session

    Request Body:
        {
            "user_id": "string",
            "metadata": {  # optional
                "repository": "string",
                "files": ["string"]
            }
        }

    Response:
        {
            "session_id": "string",
            "created_at": "timestamp"
        }
    """
    try:
        data = request.get_json()

        if not data or 'user_id' not in data:
            return jsonify({'error': 'user_id is required'}), 400

        user_id = data['user_id']
        metadata = data.get('metadata')

        session_id = chat_engine.start_session(user_id, metadata)
        session_info = conversation_manager.get_session_info(session_id)

        return jsonify({
            'session_id': session_id,
            'created_at': session_info['created_at']
        }), 201

    except Exception as e:
        logger.error(f"Error creating chat session: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/message', methods=['POST'])
def send_chat_message():
    """
    Send a message in a chat session

    Request Body:
        {
            "session_id": "string",
            "message": "string",
            "code_context": "string"  # optional
        }

    Response:
        {
            "content": "string",
            "message_id": "string",
            "tokens_used": int,
            "intent": "string",
            "agent": "string"
        }
    """
    try:
        data = request.get_json()

        if not data or 'session_id' not in data or 'message' not in data:
            return jsonify({'error': 'session_id and message are required'}), 400

        session_id = data['session_id']
        message = data['message']
        code_context = data.get('code_context')

        response = chat_engine.send_message(
            session_id=session_id,
            message=message,
            code_context=code_context,
            stream=False
        )

        return jsonify(response), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error sending message: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/stream', methods=['GET'])
def stream_chat():
    """
    Stream chat responses via Server-Sent Events

    Query Parameters:
        session_id: string (required)
        message: string (required)
        code_context: string (optional)

    Response:
        Server-Sent Events stream
    """
    try:
        session_id = request.args.get('session_id')
        message = request.args.get('message')
        code_context = request.args.get('code_context')

        if not session_id or not message:
            return jsonify({'error': 'session_id and message are required'}), 400

        # Get streaming generator from chat engine
        chat_generator = chat_engine.send_message(
            session_id=session_id,
            message=message,
            code_context=code_context,
            stream=True
        )

        # Convert to SSE format
        sse_generator = streaming_service.stream_chat_response(chat_generator)

        return create_sse_response(sse_generator)

    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error streaming chat: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/history/<session_id>', methods=['GET'])
def get_chat_history(session_id):
    """
    Get conversation history for a session

    Query Parameters:
        limit: int (optional) - Max messages to return

    Response:
        {
            "session_id": "string",
            "messages": [
                {
                    "message_id": "string",
                    "role": "user|assistant",
                    "content": "string",
                    "timestamp": "string",
                    "tokens_used": int
                }
            ]
        }
    """
    try:
        limit = request.args.get('limit', type=int)

        history = chat_engine.get_conversation_history(session_id, limit)

        return jsonify({
            'session_id': session_id,
            'messages': history
        }), 200

    except Exception as e:
        logger.error(f"Error getting history: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/session/<session_id>', methods=['DELETE'])
def delete_chat_session(session_id):
    """
    Delete a chat session

    Response:
        {
            "status": "deleted"
        }
    """
    try:
        success = chat_engine.end_session(session_id)

        if success:
            return jsonify({'status': 'deleted'}), 200
        else:
            return jsonify({'error': 'Session not found'}), 404

    except Exception as e:
        logger.error(f"Error deleting session: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/sessions/<user_id>', methods=['GET'])
def get_user_sessions(user_id):
    """
    Get all sessions for a user

    Query Parameters:
        active_only: bool (optional) - Only return active sessions

    Response:
        {
            "user_id": "string",
            "sessions": [
                {
                    "session_id": "string",
                    "created_at": "string",
                    "last_active": "string"
                }
            ]
        }
    """
    try:
        active_only = request.args.get(
            'active_only', 'false').lower() == 'true'

        sessions = conversation_manager.get_user_sessions(user_id, active_only)

        return jsonify({
            'user_id': user_id,
            'sessions': sessions
        }), 200

    except Exception as e:
        logger.error(f"Error getting user sessions: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@api_v2.route('/chat/export/<session_id>', methods=['GET'])
def export_conversation(session_id):
    """
    Export conversation to markdown or JSON

    Query Parameters:
        format: 'markdown' or 'json' (default: markdown)

    Response:
        Text or JSON based on format
    """
    try:
        format_type = request.args.get('format', 'markdown')

        exported = chat_engine.export_conversation(session_id, format_type)

        if format_type == 'markdown':
            return exported, 200, {'Content-Type': 'text/markdown'}
        else:
            return exported, 200, {'Content-Type': 'application/json'}

    except Exception as e:
        logger.error(f"Error exporting conversation: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Query Endpoints
# ============================================================================

@api_v2.route('/query/semantic', methods=['POST'])
def semantic_query():
    """
    Perform semantic code search

    Request Body:
        {
            "question": "string",
            "max_results": int (optional),
            "filters": {}  (optional)
        }

    Response:
        {
            "question": "string",
            "answer": "string",
            "sources": [...],
            "intent": "string"
        }
    """
    try:
        data = request.get_json()

        if not data or 'question' not in data:
            return jsonify({'error': 'question is required'}), 400

        question = data['question']
        max_results = data.get('max_results', 5)
        filters = data.get('filters')

        # Import here to avoid circular dependencies
        from query.query_handler import QueryHandler
        from indexing.code_indexer import CodeIndexer

        indexer = CodeIndexer()
        handler = QueryHandler(indexer=indexer)

        response = handler.query(question, k=max_results, filters=filters)

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Semantic query error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
