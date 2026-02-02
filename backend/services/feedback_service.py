import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class FeedbackService:
    def __init__(self, feedback_dir: str = "feedback"):
        self.feedback_dir = Path(feedback_dir)
        self.feedback_file = self.feedback_dir / "user_feedback.json"
        self._ensure_dir()

    def _ensure_dir(self):
        """Ensure the feedback directory exists."""
        if not self.feedback_dir.exists():
            self.feedback_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created feedback directory: {self.feedback_dir}")

    def save_feedback(self, finding_id: str, feedback_type: str, comment: str = "", code_snippet: str = "") -> bool:
        """
        Save user feedback for a specific finding.
        
        Args:
            finding_id: Unique identifier for the finding
            feedback_type: 'positive' (Correct) or 'negative' (False Positive)
            comment: Optional user comment
            code_snippet: The code associated with the finding
        """
        try:
            feedback_data = self.get_all_feedback()
            
            # Create feedback entry
            entry = {
                "finding_id": finding_id,
                "feedback_type": feedback_type,
                "comment": comment,
                "code_snippet": code_snippet,
                "timestamp": datetime.now().isoformat()
            }
            
            # Update or add feedback
            # We use finding_id as key for easy lookup
            feedback_data[finding_id] = entry
            
            with open(self.feedback_file, 'w') as f:
                json.dump(feedback_data, f, indent=2)
            
            logger.info(f"Saved feedback for finding {finding_id}: {feedback_type}")
            return True
        except Exception as e:
            logger.error(f"Error saving feedback: {e}")
            return False

    def get_all_feedback(self) -> Dict[str, Any]:
        """Retrieve all user feedback."""
        if not self.feedback_file.exists():
            return {}
        
        try:
            with open(self.feedback_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading feedback: {e}")
            return {}

    def get_feedback_by_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get feedback for a specific finding."""
        feedback_data = self.get_all_feedback()
        return feedback_data.get(finding_id)

# Singleton instance
_feedback_service = None

def get_feedback_service() -> FeedbackService:
    global _feedback_service
    if _feedback_service is None:
        _feedback_service = FeedbackService()
    return _feedback_service
