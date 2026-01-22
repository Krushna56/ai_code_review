"""
Chat Engine

Interactive conversational AI engine for code discussions with context retention.
"""

import logging
from typing import Dict, Any, Optional, List, Generator
from services.conversation_manager import ConversationManager
from llm_agents.security_reviewer import SecurityReviewer
from llm_agents.refactor_agent import RefactorAgent
import config

logger = logging.getLogger(__name__)


class ChatEngine:
    """Interactive chat engine for code analysis discussions"""

    def __init__(self):
        """Initialize chat engine with conversation manager and agents"""
        self.conversation_manager = ConversationManager()
        self.security_reviewer = SecurityReviewer()
        self.refactor_agent = RefactorAgent()

        # Context window management (in tokens)
        self.max_context_tokens = getattr(config, 'CHAT_CONTEXT_WINDOW', 4000)
        self.max_history_messages = getattr(config, 'CHAT_MAX_HISTORY', 50)

        logger.info("Initialized ChatEngine")

    def start_session(self, user_id: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Start a new chat session

        Args:
            user_id: User identifier
            metadata: Optional session metadata (e.g., repository info, file paths)

        Returns:
            session_id: Unique session identifier
        """
        session_id = self.conversation_manager.create_session(
            user_id, metadata)
        logger.info(f"Started chat session {session_id} for user {user_id}")
        return session_id

    def send_message(
        self,
        session_id: str,
        message: str,
        code_context: Optional[str] = None,
        stream: bool = False
    ) -> Dict[str, Any]:
        """
        Send a message and get AI response

        Args:
            session_id: Session identifier
            message: User message
            code_context: Optional code snippet for context
            stream: Whether to stream the response (returns generator)

        Returns:
            Response dict with 'content', 'tokens_used', 'message_id'
            Or Generator if stream=True
        """
        # Validate session exists
        session_info = self.conversation_manager.get_session_info(session_id)
        if not session_info:
            raise ValueError(f"Session {session_id} not found")

        # Add user message to history
        user_message_id = self.conversation_manager.add_message(
            session_id=session_id,
            role='user',
            content=message,
            code_context=code_context
        )

        # Detect intent and select appropriate agent
        intent = self._detect_intent(message)
        agent = self._select_agent(intent)

        # Build context from conversation history
        context = self._build_context(session_id, code_context)

        # Build prompt with context
        prompt = self._build_prompt(message, context, intent)

        if stream:
            # Return streaming generator
            return self._generate_streaming_response(
                session_id, agent, prompt, context
            )
        else:
            # Generate response
            response_content = agent.generate(
                prompt=prompt,
                system_prompt=agent.system_prompt
            )

            if not response_content:
                response_content = "I apologize, but I encountered an error generating a response. Please try again."

            # Estimate tokens (rough approximation)
            tokens_used = len(message.split()) + len(response_content.split())

            # Add assistant response to history
            assistant_message_id = self.conversation_manager.add_message(
                session_id=session_id,
                role='assistant',
                content=response_content,
                tokens_used=tokens_used,
                metadata={'intent': intent, 'agent': agent.__class__.__name__}
            )

            return {
                'content': response_content,
                'tokens_used': tokens_used,
                'message_id': assistant_message_id,
                'intent': intent,
                'agent': agent.__class__.__name__
            }

    def _generate_streaming_response(
        self,
        session_id: str,
        agent: Any,
        prompt: str,
        context: Dict[str, Any]
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Generate streaming response

        Args:
            session_id: Session identifier
            agent: LLM agent to use
            prompt: Formatted prompt
            context: Context dictionary

        Yields:
            Chunks of response data
        """
        full_response = ""
        tokens_used = 0

        try:
            # Stream from agent
            for chunk in agent.generate_stream(prompt=prompt, system_prompt=agent.system_prompt):
                full_response += chunk
                tokens_used += 1  # Rough approximation

                yield {
                    'type': 'content',
                    'content': chunk,
                    'done': False
                }

            # Save complete response to database
            assistant_message_id = self.conversation_manager.add_message(
                session_id=session_id,
                role='assistant',
                content=full_response,
                tokens_used=tokens_used,
                metadata={'intent': context.get(
                    'intent'), 'agent': agent.__class__.__name__}
            )

            # Send completion signal
            yield {
                'type': 'done',
                'content': full_response,
                'message_id': assistant_message_id,
                'tokens_used': tokens_used,
                'done': True
            }

        except Exception as e:
            logger.error(f"Streaming error: {e}", exc_info=True)
            yield {
                'type': 'error',
                'content': f"Error: {str(e)}",
                'done': True
            }

    def get_conversation_history(
        self,
        session_id: str,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get conversation history

        Args:
            session_id: Session identifier
            limit: Maximum messages to return (default: all)

        Returns:
            List of messages
        """
        return self.conversation_manager.get_conversation_history(
            session_id,
            limit=limit or self.max_history_messages
        )

    def end_session(self, session_id: str) -> bool:
        """
        End a chat session

        Args:
            session_id: Session identifier

        Returns:
            True if deleted, False if not found
        """
        return self.conversation_manager.delete_session(session_id)

    def _detect_intent(self, message: str) -> str:
        """
        Detect user intent from message

        Returns:
            'security', 'refactor', 'explain', 'general'
        """
        message_lower = message.lower()

        # Security-related
        if any(kw in message_lower for kw in [
            'security', 'vulnerability', 'exploit', 'injection', 'xss',
            'hardcoded', 'secret', 'password', 'token', 'unsafe', 'cve'
        ]):
            return 'security'

        # Refactoring-related
        if any(kw in message_lower for kw in [
            'refactor', 'improve', 'optimize', 'clean', 'simplify',
            'performance', 'best practice', 'code smell'
        ]):
            return 'refactor'

        # Explanation-related
        if any(kw in message_lower for kw in [
            'explain', 'what does', 'how does', 'why', 'understand',
            'describe', 'tell me about'
        ]):
            return 'explain'

        return 'general'

    def _select_agent(self, intent: str):
        """Select appropriate agent based on intent"""
        if intent == 'security':
            return self.security_reviewer
        elif intent == 'refactor':
            return self.refactor_agent
        else:
            # Default to security reviewer for general queries
            return self.security_reviewer

    def _build_context(self, session_id: str, code_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Build context from conversation history and code

        Args:
            session_id: Session identifier
            code_context: Optional code snippet

        Returns:
            Context dictionary
        """
        # Get recent conversation history
        history = self.conversation_manager.get_conversation_history(
            session_id,
            limit=10  # Last 10 messages for context
        )

        context = {
            'conversation_history': history,
            'total_messages': len(history)
        }

        if code_context:
            context['code'] = code_context

        return context

    def _build_prompt(self, message: str, context: Dict[str, Any], intent: str) -> str:
        """
        Build prompt with conversation history and context

        Args:
            message: User message
            context: Context dictionary
            intent: Detected intent

        Returns:
            Formatted prompt
        """
        prompt_parts = []

        # Add conversation history if available
        if context.get('conversation_history'):
            prompt_parts.append("# Previous Conversation\n")
            for msg in context['conversation_history'][-5:]:  # Last 5 messages
                role = msg['role'].capitalize()
                content = msg['content'][:200]  # Truncate long messages
                prompt_parts.append(f"**{role}**: {content}\n")
            prompt_parts.append("\n---\n\n")

        # Add code context if available
        if context.get('code'):
            prompt_parts.append("# Code Context\n")
            prompt_parts.append("```python\n")
            prompt_parts.append(context['code'])
            prompt_parts.append("\n```\n\n")

        # Add current message
        prompt_parts.append("# Current Question\n")
        prompt_parts.append(message)

        return ''.join(prompt_parts)

    def export_conversation(self, session_id: str, format: str = 'markdown') -> str:
        """
        Export conversation to a formatted string

        Args:
            session_id: Session identifier
            format: 'markdown' or 'json'

        Returns:
            Formatted conversation string
        """
        session_info = self.conversation_manager.get_session_info(session_id)
        history = self.conversation_manager.get_conversation_history(
            session_id)

        if format == 'markdown':
            lines = [
                f"# Chat Session: {session_id}",
                f"**Created**: {session_info['created_at']}",
                f"**User**: {session_info['user_id']}",
                "",
                "---",
                ""
            ]

            for msg in history:
                role = "🧑 **User**" if msg['role'] == 'user' else "🤖 **AI Assistant**"
                lines.append(f"## {role}")
                lines.append(f"*{msg['timestamp']}*\n")
                lines.append(msg['content'])
                lines.append("\n---\n")

            return '\n'.join(lines)

        elif format == 'json':
            import json
            return json.dumps({
                'session_info': session_info,
                'messages': history
            }, indent=2)

        else:
            raise ValueError(f"Unknown format: {format}")
