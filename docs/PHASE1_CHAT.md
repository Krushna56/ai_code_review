# Phase 1 - Chat Infrastructure

## Overview

Phase 1 adds interactive chat capabilities to the AI Code Review Platform, enabling conversational AI for code discussions with context retention, streaming responses, and persistent conversation history.

## ✅ Implemented Features

### 1. Conversation Management

- **SQLite Database**: Persistent storage for chat sessions and messages
- **Session Management**: Create, retrieve, and delete chat sessions
- **Message History**: Full conversation history with timestamps
- **Token Tracking**: Track LLM token usage per message and session

### 2. Chat Engine

- **Multi-turn Conversations**: Context retention across messages
- **Intent Detection**: Automatically detect security, refactoring, or explanation queries
- **Agent Selection**: Route queries to appropriate LLM agent (SecurityReviewer, RefactorAgent)
- **Context Building**: Include conversation history and code snippets in prompts
- **Export**: Export conversations to Markdown or JSON

### 3. Streaming Support

- **LLM Streaming**: Real-time token-by-token responses from OpenAI, Anthropic, and Mistral
- **Server-Sent Events (SSE)**: Standard SSE format for web streaming
- **Progress Tracking**: Real-time progress updates for long operations
- **Heartbeat**: Automatic keep-alive for long connections

### 4. API v2 Endpoints

#### Chat Endpoints

```
POST   /api/v2/chat/session              - Create chat session
POST   /api/v2/chat/message               - Send message (non-streaming)
GET    /api/v2/chat/stream                - Stream chat responses (SSE)
GET    /api/v2/chat/history/<session_id>  - Get conversation history
DELETE /api/v2/chat/session/<session_id> - Delete session
GET    /api/v2/chat/sessions/<user_id>   - Get user's sessions
GET    /api/v2/chat/export/<session_id>  - Export conversation
```

#### Query Endpoints

```
POST   /api/v2/query/semantic             - Semantic code search
```

## Usage Examples

### 1. Start a Chat Session

```bash
curl -X POST http://localhost:5000/api/v2/chat/session \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "developer123",
    "metadata": {
      "repository": "my-app",
      "files": ["app.py", "utils.py"]
    }
  }'
```

**Response:**

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2026-01-20T14:30:00"
}
```

### 2. Send a Message (Non-Streaming)

```bash
curl -X POST http://localhost:5000/api/v2/chat/message \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "message": "What security vulnerabilities are in this code?",
    "code_context": "password = \"hardcoded123\""
  }'
```

**Response:**

```json
{
  "content": "I found a serious security vulnerability...",
  "message_id": "msg-123",
  "tokens_used": 45,
  "intent": "security",
  "agent": "SecurityReviewer"
}
```

### 3. Stream Chat Response (SSE)

```bash
curl -N http://localhost:5000/api/v2/chat/stream?session_id=550e8400...&message=Explain%20this%20code
```

**Response (SSE Stream):**

```
event: message
data: {"type":"content","content":"This","done":false}

event: message
data: {"type":"content","content":" code","done":false}

event: complete
data: {"type":"done","message_id":"msg-124","tokens_used":50,"done":true}
```

### 4. Get Conversation History

```bash
curl http://localhost:5000/api/v2/chat/history/550e8400...?limit=10
```

**Response:**

```json
{
  "session_id": "550e8400...",
  "messages": [
    {
      "message_id": "msg-1",
      "role": "user",
      "content": "What security issues exist?",
      "timestamp": "2026-01-20T14:30:00",
      "tokens_used": 10
    },
    {
      "message_id": "msg-2",
      "role": "assistant",
      "content": "I found 3 security issues...",
      "timestamp": "2026-01-20T14:30:05",
      "tokens_used": 45
    }
  ]
}
```

### 5. Export Conversation

```bash
# Export as Markdown
curl http://localhost:5000/api/v2/chat/export/550e8400...?format=markdown

# Export as JSON
curl http://localhost:5000/api/v2/chat/export/550e8400...?format=json
```

## Python Usage

### Using ChatEngine Directly

```python
from llm_agents.chat_engine import ChatEngine

# Initialize
engine = ChatEngine()

# Start session
session_id = engine.start_session('user123')

# Send message (non-streaming)
response = engine.send_message(
    session_id=session_id,
    message="Are there SQL injection vulnerabilities?",
    code_context="query = f'SELECT * FROM users WHERE id={user_id}'",
    stream=False
)

print(response['content'])
print(f"Intent: {response['intent']}")
print(f"Tokens used: {response['tokens_used']}")

# Get history
history = engine.get_conversation_history(session_id)
for msg in history:
    print(f"{msg['role']}: {msg['content']}")

# Export
markdown = engine.export_conversation(session_id, 'markdown')
with open('conversation.md', 'w') as f:
    f.write(markdown)
```

### Using Streaming

```python
# Send message with streaming
stream_gen = engine.send_message(
    session_id=session_id,
    message="Explain this vulnerability",
    stream=True
)

# Process stream
for chunk in stream_gen:
    if chunk['type'] == 'content':
        print(chunk['content'], end='', flush=True)
    elif chunk['type'] == 'done':
        print(f"\n\nMessage ID: {chunk['message_id']}")
        print(f"Tokens: {chunk['tokens_used']}")
```

## Configuration

Add to your `.env` file:

```bash
# Chat Configuration
CHAT_MAX_HISTORY=50           # Max messages to keep in context
CHAT_CONTEXT_WINDOW=4000      # Max tokens for conversation context
CHAT_SESSION_TIMEOUT=3600     # Session timeout in seconds

# Streaming Configuration
ENABLE_STREAMING=true
SSE_RETRY_TIMEOUT=3000        # Client retry timeout (ms)
SSE_HEARTBEAT_INTERVAL=30     # Heartbeat interval (seconds)
```

## Database Schema

### Sessions Table

```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
);
```

### Messages Table

```sql
CREATE TABLE messages (
    message_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    code_context TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tokens_used INTEGER DEFAULT 0,
    metadata TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
```

## Testing

Run the test suite:

```bash
# Install pytest if not already installed
pip install pytest pytest-mock

# Run chat engine tests
pytest tests/test_chat_engine.py -v

# Run with coverage
pytest tests/test_chat_engine.py -v --cov=services --cov=llm_agents
```

## Architecture

```
┌─────────────────┐
│   Flask App     │
│   app.py        │
└────────┬────────┘
         │
         │ registers
         ▼
┌─────────────────┐
│ API v2 Routes   │
│ api/v2_routes.py│
└────────┬────────┘
         │
         │ uses
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Chat Engine    │─────▶│ BaseAgent        │
│ chat_engine.py  │      │ (with streaming) │
└────────┬────────┘      └──────────────────┘
         │                         │
         │ uses                    │ inherits
         ▼                         ▼
┌─────────────────┐      ┌──────────────────┐
│ Conversation    │      │ SecurityReviewer │
│ Manager         │      │ RefactorAgent    │
│ (SQLite)        │      └──────────────────┘
└─────────────────┘
```

## Next Steps (Phase 2)

- [ ] Build modern web UI for chat interface
- [ ] Add WebSocket support for real-time updates
- [ ] Create interactive code viewer
- [ ] Implement syntax highlighting
- [ ] Add dark/light theme toggle

## Troubleshooting

### Database Locked Error

If you see "database is locked" errors:

- Ensure only one process is accessing the database
- Check file permissions on `vector_db/conversations.db`

### Streaming Not Working

- Verify `ENABLE_STREAMING=true` in `.env`
- Check that your LLM provider API key is valid
- Ensure Flask is not running in debug mode with auto-reload

### Memory Issues with Long Conversations

- Reduce `CHAT_MAX_HISTORY` to limit context size
- Lower `CHAT_CONTEXT_WINDOW` to use fewer tokens
- Implement periodic session cleanup with `cleanup_old_sessions()`
