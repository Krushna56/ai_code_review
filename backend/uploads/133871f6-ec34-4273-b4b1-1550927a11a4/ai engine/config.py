import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Application configuration settings"""

    # Google Gemini API Configuration
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_MODEL = 'gemini-2.5-flash'  # Latest Gemini Flash model (NEW API)

    # File Upload Settings
    UPLOAD_FOLDER = 'uploads'
    MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
    ALLOWED_EXTENSIONS = {
        # Document files
        'pdf', 'docx', 'txt', 'doc',
        # Code files
        'py', 'js', 'java', 'cpp', 'c', 'cs', 'go', 'rb', 'php', 'ts',
        'jsx', 'tsx', 'swift', 'kt', 'rs', 'scala', 'r', 'm', 'h',
        'html', 'css', 'sql', 'sh', 'bash', 'json', 'xml', 'yaml', 'yml'
    }

    # Code file extensions (for type detection)
    CODE_EXTENSIONS = {
        'py', 'js', 'java', 'cpp', 'c', 'cs', 'go', 'rb', 'php', 'ts',
        'jsx', 'tsx', 'swift', 'kt', 'rs', 'scala', 'r', 'm', 'h',
        'html', 'css', 'sql', 'sh', 'bash'
    }

    # Language mapping for syntax highlighting
    LANGUAGE_MAP = {
        'py': 'Python', 'js': 'JavaScript', 'ts': 'TypeScript',
        'java': 'Java', 'cpp': 'C++', 'c': 'C', 'cs': 'C#',
        'go': 'Go', 'rb': 'Ruby', 'php': 'PHP', 'swift': 'Swift',
        'kt': 'Kotlin', 'rs': 'Rust', 'scala': 'Scala', 'r': 'R',
        'jsx': 'React JSX', 'tsx': 'React TSX', 'html': 'HTML',
        'css': 'CSS', 'sql': 'SQL', 'sh': 'Shell', 'bash': 'Bash',
        'm': 'Objective-C', 'h': 'C/C++ Header'
    }

    # Summarization Settings
    MIN_SUMMARY_LINES = 3  # Minimum lines for any summary
    DEFAULT_LINES_PER_PAGE = 4  # Default lines per page if user doesn't specify
    MAX_KEY_ELEMENTS = 20
    DETAILED_OVERVIEW_LINES = 7  # Lines for "what happened" overview section

    # Document Types for specialized analysis
    DOCUMENT_TYPES = {
        'general': 'General Document',
        'legal': 'Legal Document',
        'code': 'Code/Technical File',
        'book': 'Book/Novel',
        'letter': 'Letter/Email',
        'research': 'Research Paper'
    }

    # Code Analysis Settings
    CODE_LINES_PER_PAGE = 100  # Estimate 100 lines as 1 "page" for code
    MAX_CODE_PREVIEW_LINES = 50  # Maximum lines to show in preview
    CODE_DIAGRAM_COMPLEXITY = 'medium'  # low, medium, high

    # Flask Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True') == 'True'

    # Character estimation for plain text (average characters per page)
    CHARS_PER_PAGE = 2000


def allowed_file(filename):
    """Check if uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
