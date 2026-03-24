"""
Chat Engine

Interactive conversational AI engine for code discussions with context retention.
"""

import logging
import os
import json
from typing import Dict, Any, Optional, List, Generator
from services.conversation_manager import ConversationManager
from services.report_service import get_report_service
from llm_agents.security_reviewer import SecurityReviewer
from llm_agents.refactor_agent import RefactorAgent
import config

logger = logging.getLogger(__name__)


class ChatEngine:
    """Interactive chat engine — uses Gemini exclusively for chatbot conversations."""

    def __init__(self):
        """Initialize chat engine with Gemini LLM and supporting agents."""
        from llm_agents.llm_factory import LLMClientFactory

        self.conversation_manager = ConversationManager()
        self.security_reviewer = SecurityReviewer()
        self.refactor_agent = RefactorAgent()
        self.report_service = get_report_service()

        # Strictly enforce Gemini for chat
        try:
            self._chat_llm = LLMClientFactory.create_chat_client()
            logger.info(f"[ChatEngine] Chat LLM: {self._chat_llm.provider}/{self._chat_llm.model}")
        except Exception as e:
            logger.warning(f"[ChatEngine] create_chat_client failed ({e}), falling back to security_reviewer")
            self._chat_llm = None

        # Context window management (in tokens)
        self.max_context_tokens = getattr(config, 'CHAT_CONTEXT_WINDOW', 4000)
        self.max_history_messages = getattr(config, 'CHAT_MAX_HISTORY', 50)

        logger.info("Initialized ChatEngine with dashboard integration")

    @property
    def provider_name(self) -> str:
        """Return the active chat LLM provider name."""
        if self._chat_llm:
            return self._chat_llm.provider
        return getattr(self.security_reviewer, 'provider', 'unknown')

    @property
    def model_name(self) -> str:
        """Return the active chat LLM model name."""
        if self._chat_llm:
            return self._chat_llm.model
        return getattr(self.security_reviewer, 'model', 'unknown')

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
            return self._generate_streaming_response(session_id, agent, prompt, context)
        else:
            # Use Gemini client directly when available
            if self._chat_llm is not None and intent not in ('security', 'refactor'):
                response_content = self._chat_llm.complete(
                    prompt=prompt,
                    system_prompt=agent.system_prompt if hasattr(agent, 'system_prompt') else None,
                    temperature=0.5,
                    max_tokens=2000
                )
            else:
                response_content = agent.generate(
                    prompt=prompt,
                    system_prompt=agent.system_prompt
                )

            if not response_content:
                response_content = "I apologize, but I encountered an error generating a response. Please try again."

            tokens_used = len(message.split()) + len(response_content.split())

            assistant_message_id = self.conversation_manager.add_message(
                session_id=session_id,
                role='assistant',
                content=response_content,
                tokens_used=tokens_used,
                metadata={'intent': intent, 'agent': agent.__class__.__name__,
                          'llm_provider': self.provider_name}
            )

            return {
                'content': response_content,
                'tokens_used': tokens_used,
                'message_id': assistant_message_id,
                'intent': intent,
                'agent': agent.__class__.__name__,
                'llm_provider': self.provider_name,
                'llm_model': self.model_name,
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
        Detect user intent from message.
        Returns: 'security', 'refactor', 'explain', 'bounty', 'extract', 'general'
        """
        message_lower = message.lower()

        # Bug bounty / vulnerability hunting
        if any(kw in message_lower for kw in [
            'bug bounty', 'bounty', 'owasp', 'cve', 'cvss', 'exploit', 'poc',
            'vulnerability scan', 'vuln scan', 'penetration', 'pentest', 'hack',
            'xss', 'sqli', 'sql injection', 'ssrf', 'rce', 'command injection',
            'hardcoded secret', 'jwt', 'open redirect', 'path traversal'
        ]):
            return 'bounty'

        # Data extraction from code
        if any(kw in message_lower for kw in [
            'extract data', 'extract code', 'list functions', 'list classes',
            'find imports', 'find endpoints', 'what functions', 'what classes'
        ]):
            return 'extract'

        # Security-related
        if any(kw in message_lower for kw in [
            'security', 'vulnerability', 'injection', 'unsafe', 'password', 'token',
            'secret', 'hardcoded', 'auth'
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
    
    def _load_analysis_context(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Load analysis findings for a specific UID
        
        Args:
            uid: Unique identifier for the analysis
            
        Returns:
            Dictionary with findings data or None if not found
        """
        try:
            # Try to load from processed folder
            processed_path = os.path.join('processed', uid, 'security_report.json')
            if os.path.exists(processed_path):
                with open(processed_path, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                    
                security_findings = report_data.get('security_findings', [])
                cve_findings = report_data.get('cve_findings', [])
                executive_summary = report_data.get('executive_summary', {})
                
                logger.info(f"Loaded UID-specific findings for {uid}: {len(security_findings)} findings")
                
                return {
                    'summary': executive_summary,
                    'security_findings': security_findings[:10],  # Top 10 findings
                    'cve_findings': cve_findings[:5],  # Top 5 CVEs
                    'total_findings': len(security_findings),
                    'total_cves': len(cve_findings),
                    'has_data': True,
                    'uid': uid
                }
        except Exception as e:
            logger.warning(f"Could not load UID-specific findings for {uid}: {e}")
        
        return None

    def _build_context(self, session_id: str, code_context: Optional[str] = None) -> Dict[str, Any]:
        """
        Build context from conversation history, code, and dashboard data

        Args:
            session_id: Session identifier
            code_context: Optional code snippet

        Returns:
            Context dictionary with dashboard data included
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
        
        # Try to load UID-specific findings first
        session_info = self.conversation_manager.get_session_info(session_id)
        uid = None
        if session_info and session_info.get('metadata'):
            uid = session_info['metadata'].get('uid')
        
        if uid:
            # Load UID-specific findings
            uid_findings = self._load_analysis_context(uid)
            if uid_findings:
                context['dashboard_data'] = uid_findings
                logger.debug(f"Loaded UID-specific findings for {uid}")
                return context
        
        # Fallback to latest analysis data from dashboard
        try:
            latest_report = self.report_service.get_latest_report()
            if latest_report and latest_report.get('executive_summary'):
                security_findings = latest_report.get('security_findings', [])
                cve_findings = latest_report.get('cve_findings', [])
                
                context['dashboard_data'] = {
                    'summary': latest_report.get('executive_summary', {}),
                    'security_findings': security_findings[:10],  # Top 10 findings
                    'cve_findings': cve_findings[:5],  # Top 5 CVEs
                    'total_findings': len(security_findings),
                    'total_cves': len(cve_findings),
                    'has_data': True
                }
                logger.debug(f"Loaded dashboard data: {len(security_findings)} findings, {len(cve_findings)} CVEs")
        except Exception as e:
            logger.warning(f"Could not load dashboard data for chat context: {e}")
            context['dashboard_data'] = {'has_data': False}

        return context

    def _build_prompt(self, message: str, context: Dict[str, Any], intent: str) -> str:
        """
        Build prompt with dashboard data, conversation history, and context

        Args:
            message: User message
            context: Context dictionary (now includes dashboard_data)
            intent: Detected intent

        Returns:
            Formatted prompt with dashboard stats
        """
        prompt_parts = []
        
        # Add instruction header
        prompt_parts.append("=== ANALYSIS DATA PROVIDED BELOW ===\n")
        prompt_parts.append("Answer the user's question using ONLY the data provided below. Be concise and specific.\n\n")

        # Add dashboard summary if available (FIRST - most important context)
        if context.get('dashboard_data', {}).get('has_data'):
            dashboard = context['dashboard_data']
            summary = dashboard.get('summary', {})
            
            prompt_parts.append("# Security Analysis Summary\n")
            prompt_parts.append(f"Total Security Findings: {dashboard.get('total_findings', 0)}\n")
            prompt_parts.append(f"CVE Vulnerabilities: {dashboard.get('total_cves', 0)}\n")
            prompt_parts.append(f"Risk Score: {summary.get('risk_score', 'N/A')}\n")
            prompt_parts.append(f"Risk Level: {summary.get('overall_risk_level', 'UNKNOWN')}\n")
            
            # Add severity breakdown
            severity_dist = summary.get('severity_distribution', {})
            if severity_dist:
                prompt_parts.append(f"Critical Issues: {severity_dist.get('CRITICAL', 0)}\n")
                prompt_parts.append(f"High Issues: {severity_dist.get('HIGH', 0)}\n")
                prompt_parts.append(f"Medium Issues: {severity_dist.get('MEDIUM', 0)}\n")
                prompt_parts.append(f"Low Issues: {severity_dist.get('LOW', 0)}\n")
            
            # Add top security findings if available
            security_findings = dashboard.get('security_findings', [])
            if security_findings:
                prompt_parts.append("\n## Detailed Security Findings:\n")
                for i, finding in enumerate(security_findings[:10], 1):  # Top 10
                    title = finding.get('title', 'Unknown Issue')
                    severity = finding.get('severity', 'UNKNOWN')
                    file_path = finding.get('file_path', 'N/A')
                    line = finding.get('line_number', 'N/A')
                    description = finding.get('description', '')
                    remediation = finding.get('remediation', '')
                    owasp_cat = finding.get('owasp_category', '')
                    owasp_name = finding.get('owasp_name', '')
                    
                    prompt_parts.append(f"{i}. {title} ({severity})\n")
                    prompt_parts.append(f"   File: {file_path}:{line}\n")
                    if description:
                        prompt_parts.append(f"   Description: {description}\n")
                    if remediation:
                        prompt_parts.append(f"   Fix: {remediation}\n")
                    if owasp_cat:
                        prompt_parts.append(f"   OWASP: {owasp_cat} - {owasp_name}\n")
                    prompt_parts.append("\n")
            
            # Add CVE findings if available
            cve_findings = dashboard.get('cve_findings', [])
            if cve_findings:
                prompt_parts.append("## CVE Vulnerabilities:\n")
                for i, cve in enumerate(cve_findings[:5], 1):  # Top 5
                    cve_id = cve.get('cve_id', 'Unknown')
                    package = cve.get('package', 'Unknown')
                    severity = cve.get('severity', 'UNKNOWN')
                    description = cve.get('description', '')
                    prompt_parts.append(f"{i}. {cve_id} in {package} ({severity})\n")
                    if description:
                        prompt_parts.append(f"   {description}\n")
                    prompt_parts.append("\n")
            
            prompt_parts.append("---\n\n")
        else:
            prompt_parts.append("# No Analysis Data Available\n")
            prompt_parts.append("No security analysis has been performed yet.\n\n")

        # Add conversation history if available (condensed)
        if context.get('conversation_history'):
            recent_history = context['conversation_history'][-3:]  # Last 3 messages only
            if recent_history:
                prompt_parts.append("## Recent Conversation:\n")
                for msg in recent_history:
                    role = msg['role'].capitalize()
                    content = msg['content'][:150]  # Truncate
                    prompt_parts.append(f"{role}: {content}\n")
                prompt_parts.append("\n")

        # Add code context if available
        if context.get('code'):
            prompt_parts.append("## Code Being Viewed:\n")
            prompt_parts.append("```\n")
            prompt_parts.append(context['code'][:1000])  # Limit code context
            prompt_parts.append("\n```\n\n")

        # Add current message with emphasis
        prompt_parts.append("=== USER QUESTION ===\n")
        prompt_parts.append(message)
        prompt_parts.append("\n\nRemember: Answer concisely using ONLY the data provided above. If the question is about something not in the data, say 'I don't have data about that in the current analysis.'")

        return ''.join(prompt_parts)

    def export_conversation(self, session_id: str, export_format: str = 'markdown') -> str:
        """
        Export conversation to a formatted string

        Args:
            session_id: Session identifier
            export_format: 'markdown' or 'json'

        Returns:
            Formatted conversation string
        """
        session_info = self.conversation_manager.get_session_info(session_id)
        history = self.conversation_manager.get_conversation_history(
            session_id)

        if export_format == 'markdown':
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

        elif export_format == 'json':
            import json
            return json.dumps({
                'session_info': session_info,
                'messages': history
            }, indent=2)

        else:
            raise ValueError(f"Unknown export format: {export_format}")
