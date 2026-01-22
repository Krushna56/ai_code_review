/**
 * Chat Interface
 * 
 * Handles chat functionality, file uploads, and UI interactions
 */

class ChatInterface {
    constructor() {
        this.sessionId = null;
        this.currentCode = '';
        this.currentFilename = '';
        this.streamHandler = new StreamHandler();
        
        this.initializeElements();
        this.attachEventListeners();
        this.initializeSession();
    }

    initializeElements() {
        // Code panel elements
        this.fileInput = document.getElementById('file-input');
        this.uploadCodeBtn = document.getElementById('upload-code');
        this.clearCodeBtn = document.getElementById('clear-code');
        this.codeViewer = document.getElementById('code-viewer');
        this.codeContent = document.getElementById('code-content');
        this.codeDisplay = document.getElementById('code-display');
        this.filenameDisplay = document.getElementById('filename');
        this.fileSizeDisplay = document.getElementById('file-size');
        
        // Chat panel elements
        this.chatMessages = document.getElementById('chat-messages');
        this.chatInput = document.getElementById('chat-input');
        this.sendButton = document.getElementById('send-button');
        this.typingIndicator = document.getElementById('typing-indicator');
        this.exportChatBtn = document.getElementById('export-chat');
        this.newSessionBtn = document.getElementById('new-session');
        
        // Overlays
        this.loadingOverlay = document.getElementById('loading-overlay');
        this.toastContainer = document.getElementById('toast-container');
    }

    attachEventListeners() {
        // File upload
        this.fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
        this.uploadCodeBtn.addEventListener('click', () => this.fileInput.click());
        this.clearCodeBtn.addEventListener('click', () => this.clearCode());
        
        // Chat input
        this.chatInput.addEventListener('keydown', (e) => this.handleKeyDown(e));
        this.chatInput.addEventListener('input', () => this.autoResizeInput());
        this.sendButton.addEventListener('click', () => this.sendMessage());
        
        // Actions
        this.exportChatBtn.addEventListener('click', () => this.exportConversation());
        this.newSessionBtn.addEventListener('click', () => this.createNewSession());
        
        // Hint items
        document.querySelectorAll('.hint-item').forEach(hint => {
            hint.addEventListener('click', (e) => {
                const text = e.target.textContent.replace('💡 Try: ', '').replace(/"/g, '');
                this.chatInput.value = text;
                this.chatInput.focus();
                this.autoResizeInput();
            });
        });
    }

    async initializeSession() {
        this.showLoading(true, 'Initializing chat session...');
        
        try {
            const response = await fetch('/api/v2/chat/session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: this.getUserId(),
                    metadata: { source: 'web_interface' }
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to create session');
            }
            
            const data = await response.json();
            this.sessionId = data.session_id;
            this.showToast('Chat session ready!', 'success');
        } catch (error) {
            console.error('Session initialization error:', error);
            this.showToast('Failed to initialize chat. Please refresh the page.', 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async createNewSession() {
        if (confirm('Start a new chat session? Current conversation will be saved.')) {
            this.chatMessages.innerHTML = '';
            await this.initializeSession();
            this.addWelcomeMessage();
        }
    }

    handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            this.currentCode = e.target.result;
            this.currentFilename = file.name;
            this.displayCode(this.currentCode, this.currentFilename, file.size);
            this.showToast(`Loaded ${file.name}`, 'success');
        };
        reader.readAsText(file);
    }

    displayCode(code, filename, size) {
        // Show code content, hide empty state
        this.codeViewer.querySelector('.empty-state').style.display = 'none';
        this.codeContent.style.display = 'block';
        
        // Update displays
        this.filenameDisplay.textContent = filename;
        this.fileSizeDisplay.textContent = this.formatFileSize(size);
        this.codeDisplay.textContent = code;
        
        // Detect language and apply syntax highlighting
        const language = this.detectLanguage(filename);
        this.codeDisplay.className = `language-${language}`;
        
        // Apply Prism highlighting
        if (window.Prism) {
            Prism.highlightElement(this.codeDisplay);
        }
    }

    clearCode() {
        this.currentCode = '';
        this.currentFilename = '';
        this.codeContent.style.display = 'none';
        this.codeViewer.querySelector('.empty-state').style.display = 'flex';
        this.fileInput.value = '';
        this.showToast('Code cleared', 'success');
    }

    detectLanguage(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        const languageMap = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'jsx': 'jsx',
            'tsx': 'tsx',
            'java': 'java',
            'go': 'go',
            'cpp': 'cpp',
            'c': 'c',
            'rb': 'ruby',
            'php': 'php'
        };
        return languageMap[ext] || 'javascript';
    }

    handleKeyDown(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            this.sendMessage();
        }
    }

    autoResizeInput() {
        this.chatInput.style.height = 'auto';
        this.chatInput.style.height = this.chatInput.scrollHeight + 'px';
    }

    async sendMessage() {
        const message = this.chatInput.value.trim();
        if (!message || !this.sessionId) return;
        
        // Add user message to UI
        this.addMessage('user', message);
        this.chatInput.value = '';
        this.autoResizeInput();
        
        // Show typing indicator
        this.showTypingIndicator(true);
        
        // Prepare code context
        const codeContext = this.currentCode || null;
        
        // Build streaming URL
        const params = new URLSearchParams({
            session_id: this.sessionId,
            message: message
        });
        
        if (codeContext) {
            params.append('code_context', codeContext);
        }
        
        const streamUrl = `/api/v2/chat/stream?${params.toString()}`;
        
        // Create message container for streaming
        const messageContainer = this.createMessageContainer('assistant');
        const contentElement = messageContainer.querySelector('.message-text');
        
        let fullResponse = '';
        
        // Start streaming
        this.streamHandler.connect(streamUrl, {
            onMessage: (content, data) => {
                fullResponse += content;
                contentElement.innerHTML = this.renderMarkdown(fullResponse);
                this.scrollToBottom();
                
                // Highlight code blocks
                contentElement.querySelectorAll('pre code').forEach((block) => {
                    if (window.Prism) {
                        Prism.highlightElement(block);
                    }
                });
            },
            onComplete: (data) => {
                this.showTypingIndicator(false);
                this.scrollToBottom();
            },
            onError: (error) => {
                this.showTypingIndicator(false);
                contentElement.textContent = `Error: ${error}`;
                contentElement.style.color = 'var(--chat-danger)';
                this.showToast('Failed to get response', 'error');
            }
        });
    }

    createMessageContainer(role) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role}-message`;
        
        const avatar = document.createElement('div');
        avatar.className = `${role}-avatar`;
        avatar.textContent = role === 'user' ? '👤' : '🤖';
        
        const content = document.createElement('div');
        content.className = 'message-content';
        
        const text = document.createElement('div');
        text.className = 'message-text';
        
        content.appendChild(text);
        messageDiv.appendChild(avatar);
        messageDiv.appendChild(content);
        
        // Insert before typing indicator
        this.chatMessages.appendChild(messageDiv);
        
        return messageDiv;
    }

    addMessage(role, content) {
        const messageContainer = this.createMessageContainer(role);
        const contentElement = messageContainer.querySelector('.message-text');
        
        if (role === 'assistant') {
            contentElement.innerHTML = this.renderMarkdown(content);
            
            // Highlight code blocks
            contentElement.querySelectorAll('pre code').forEach((block) => {
                if (window.Prism) {
                    Prism.highlightElement(block);
                }
            });
        } else {
            contentElement.textContent = content;
        }
        
        this.scrollToBottom();
    }

    addWelcomeMessage() {
        const welcomeHTML = `
            <div class="welcome-message">
                <div class="ai-avatar">🤖</div>
                <div class="message-content">
                    <h3>Welcome to AI Code Chat!</h3>
                    <p>I'm your AI assistant for code security and quality analysis. I can help you:</p>
                    <ul>
                        <li>🔒 Find security vulnerabilities</li>
                        <li>🔄 Suggest refactoring improvements</li>
                        <li>📖 Explain complex code patterns</li>
                        <li>🐛 Identify potential bugs</li>
                    </ul>
                    <p class="hint">Upload some code to get started, or ask me anything!</p>
                </div>
            </div>
        `;
        this.chatMessages.innerHTML = welcomeHTML;
    }

    renderMarkdown(text) {
        if (window.marked) {
            return marked.parse(text);
        }
        // Fallback: simple formatting
        return text
            .replace(/\n/g, '<br>')
            .replace(/`([^`]+)`/g, '<code>$1</code>');
    }

    showTypingIndicator(show) {
        this.typingIndicator.style.display = show ? 'flex' : 'none';
        if (show) {
            this.scrollToBottom();
        }
    }

    scrollToBottom() {
        setTimeout(() => {
            this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
        }, 100);
    }

    showLoading(show, message = 'Loading...') {
        this.loadingOverlay.style.display = show ? 'flex' : 'none';
        if (show && message) {
            this.loadingOverlay.querySelector('p').textContent = message;
        }
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        this.toastContainer.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    async exportConversation() {
        if (!this.sessionId) return;
        
        try {
            const response = await fetch(`/api/v2/chat/export/${this.sessionId}?format=markdown`);
            if (!response.ok) throw new Error('Export failed');
            
            const markdown = await response.text();
            const blob = new Blob([markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `chat-${this.sessionId.substr(0, 8)}.md`;
            a.click();
            
            URL.revokeObjectURL(url);
            this.showToast('Conversation exported!', 'success');
        } catch (error) {
            console.error('Export error:', error);
            this.showToast('Failed to export conversation', 'error');
        }
    }

    getUserId() {
        // Get or create user ID
        let userId = localStorage.getItem('chat_user_id');
        if (!userId) {
            userId = 'user_' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('chat_user_id', userId);
        }
        return userId;
    }

    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }
}

// Initialize chat interface when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.chatInterface = new ChatInterface();
});
