import json
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("FeedbackProcessor")

def process_feedback(feedback_file="feedback/user_feedback.json", output_dir="output"):
    """
    Process user feedback to generate patterns for improvements.
    """
    feedback_path = Path(feedback_file)
    output_path = Path(output_dir)
    
    if not feedback_path.exists():
        logger.warning(f"No feedback file found at {feedback_file}")
        return
    
    try:
        with open(feedback_path, 'r') as f:
            feedback_data = json.load(f)
    except Exception as e:
        logger.error(f"Error reading feedback file: {e}")
        return

    if not feedback_data:
        logger.info("Feedback file is empty.")
        return

    # 1. Statistics
    total_entries = len(feedback_data)
    positives = sum(1 for f in feedback_data.values() if f['feedback_type'] == 'positive')
    negatives = sum(1 for f in feedback_data.values() if f['feedback_type'] == 'negative')
    
    accuracy = (positives / total_entries) * 100 if total_entries > 0 else 0
    
    logger.info(f"Processing {total_entries} feedback entries...")
    logger.info(f"Accuracy: {accuracy:.2f}% ({positives} Correct, {negatives} False Positives)")

    # 2. Extract False Positive Patterns (Simplified)
    # In a real system, we might use NLP or pattern matching here.
    # For now, we'll just identifiers that were flagged as false positives.
    false_positives = [f['finding_id'] for f in feedback_data.values() if f['feedback_type'] == 'negative']
    
    # 3. Generate Local Exclusions
    # These can be used by the meta-reasoner or directly by analysis tools.
    exclusions = {
        "finding_ids": false_positives,
        "patterns": [], # Placeholder for future logic
        "last_updated": datetime.now().isoformat(),
        "total_excluded": len(false_positives)
    }
    
    exclusion_file = output_path / "local_exclusions.json"
    try:
        output_path.mkdir(parents=True, exist_ok=True)
        with open(exclusion_file, 'w') as f:
            json.dump(exclusions, f, indent=2)
        logger.info(f"Generated exclusions at {exclusion_file}")
    except Exception as e:
        logger.error(f"Error saving exclusions: {e}")

    # 4. Generate Feedback Summary
    summary = {
        "stats": {
            "total": total_entries,
            "correct": positives,
            "false_positives": negatives,
            "accuracy_percent": round(accuracy, 2)
        },
        "processed_at": datetime.now().isoformat(),
        "recent_feedback": list(feedback_data.values())[-10:] # Last 10
    }
    
    summary_file = output_path / "feedback_summary.json"
    try:
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Generated feedback summary at {summary_file}")
    except Exception as e:
        logger.error(f"Error saving summary: {e}")

if __name__ == "__main__":
    process_feedback()
