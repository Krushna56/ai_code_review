/**
 * Stream Handler
 * 
 * Handles Server-Sent Events (SSE) for streaming responses
 */

class StreamHandler {
    constructor() {
        this.eventSource = null;
        this.onMessage = null;
        this.onComplete = null;
        this.onError = null;
    }

    /**
     * Connect to SSE endpoint
     * @param {string} url - SSE endpoint URL
     * @param {Object} callbacks - Event callbacks {onMessage, onComplete, onError}
     */
    connect(url, callbacks = {}) {
        this.onMessage = callbacks.onMessage;
        this.onComplete = callbacks.onComplete;
        this.onError = callbacks.onError;

        // Close existing connection
        this.disconnect();

        // Create new EventSource
        this.eventSource = new EventSource(url);

        // Handle message events
        this.eventSource.addEventListener('message', (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === 'content' && this.onMessage) {
                    this.onMessage(data.content, data);
                } else if (data.type === 'done' && this.onComplete) {
                    this.onComplete(data);
                    this.disconnect();
                }
            } catch (error) {
                console.error('Error parsing SSE message:', error);
                if (this.onError) {
                    this.onError(error);
                }
            }
        });

        // Handle complete events
        this.eventSource.addEventListener('complete', (event) => {
            try {
                const data = JSON.parse(event.data);
                if (this.onComplete) {
                    this.onComplete(data);
                }
                this.disconnect();
            } catch (error) {
                console.error('Error parsing complete event:', error);
            }
        });

        // Handle error events
        this.eventSource.addEventListener('error', (event) => {
            try {
                const data = JSON.parse(event.data);
                if (this.onError) {
                    this.onError(data.error || 'Stream error');
                }
            } catch (error) {
                if (this.onError) {
                    this.onError('Connection error');
                }
            }
            this.disconnect();
        });

        // Handle connection errors
        this.eventSource.onerror = (error) => {
            console.error('SSE connection error:', error);
            if (this.onError) {
                this.onError('Connection failed');
            }
            this.disconnect();
        };
    }

    /**
     * Disconnect from SSE endpoint
     */
    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
    }

    /**
     * Check if currently connected
     */
    isConnected() {
        return this.eventSource !== null && this.eventSource.readyState === EventSource.OPEN;
    }
}

/**
 * Progress Tracker
 * 
 * Tracks and displays progress for long operations
 */
class ProgressTracker {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.streamHandler = new StreamHandler();
    }

    /**
     * Start tracking progress
     * @param {string} url - Progress SSE endpoint
     * @param {Function} onUpdate - Callback for progress updates
     * @param {Function} onComplete - Callback on completion
     */
    start(url, onUpdate, onComplete) {
        this.streamHandler.connect(url, {
            onMessage: (content, data) => {
                if (onUpdate) {
                    onUpdate(data);
                }
            },
            onComplete: (data) => {
                if (onComplete) {
                    onComplete(data);
                }
            },
            onError: (error) => {
                console.error('Progress tracking error:', error);
                if (onComplete) {
                    onComplete({ error });
                }
            }
        });
    }

    /**
     * Stop tracking
     */
    stop() {
        this.streamHandler.disconnect();
    }
}

// Export for use in other scripts
window.StreamHandler = StreamHandler;
window.ProgressTracker = ProgressTracker;
