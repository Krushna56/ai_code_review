from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from werkzeug.utils import secure_filename
from config import Config, allowed_file
from document_processor import DocumentProcessor
from summarizer import Summarizer
from code_analyzer import CodeAnalyzer

app = Flask(__name__, static_folder='static', static_url_path='')
app.config.from_object(Config)

# Create upload folder if it doesn't exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# Initialize summarizer and code analyzer
summarizer = None
code_analyzer = None

def get_summarizer():
    """Lazy initialization of summarizer"""
    global summarizer
    if summarizer is None:
        try:
            summarizer = Summarizer()
        except Exception as e:
            print(f"Warning: Could not initialize Gemini API: {str(e)}")
            print("Please set GEMINI_API_KEY in your .env file")
    return summarizer

def get_code_analyzer():
    """Lazy initialization of code analyzer"""
    global code_analyzer
    if code_analyzer is None:
        try:
            code_analyzer = CodeAnalyzer()
        except Exception as e:
            print(f"Warning: Could not initialize Code Analyzer: {str(e)}")
            print("Please set GEMINI_API_KEY in your .env file")
    return code_analyzer

@app.route('/')
def index():
    """Serve the main page"""
    return send_from_directory('static', 'index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle document/code upload and return summary or analysis"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({
                'error': f'Invalid file type. Allowed types: {", ".join(Config.ALLOWED_EXTENSIONS)}'
            }), 400
        
        # Save file securely
        filename = secure_filename(file.filename)
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Detect file extension
        file_extension = os.path.splitext(filename)[1].lower().lstrip('.')
        
        try:
            # Check if it's a code file
            is_code_file = file_extension in Config.CODE_EXTENSIONS
            
            if is_code_file:
                # Handle code file analysis
                print(f"Processing code file: {filename}")
                
                # Process code document
                result = DocumentProcessor.process_document(file_path)
                
                # Unpack code file results
                code_content, page_count, line_count, language, ext = result
                
                # Validate code has content
                if not code_content or len(code_content.strip()) < 10:
                    return jsonify({'error': 'Code file appears to be empty'}), 400
                
                # Get code analyzer instance
                analyzer = get_code_analyzer()
                if analyzer is None:
                    return jsonify({
                        'error': 'AI service not configured. Please set GEMINI_API_KEY in .env file'
                    }), 500
                
                # Perform complete code analysis
                analysis = analyzer.analyze_complete(code_content, language, filename)
                
                # Clean up uploaded file
                os.remove(file_path)
                
                # Return code analysis results
                response_data = {
                    'success': True,
                    'file_type': 'code',
                    'filename': filename,
                    'language': language,
                    'metrics': analysis.get('metrics', {}),
                    'logic_summary': analysis.get('logic_summary', {}),
                    'architecture': analysis.get('architecture', {}),
                    'diagram': analysis.get('diagram', ''),
                    'line_count': line_count,
                    'page_count': page_count
                }
                
                return jsonify(response_data)
                
            else:
                # Handle regular document (PDF, DOCX, TXT)
                print(f"Processing document: {filename}")
                
                # Process document
                text, page_count = DocumentProcessor.process_document(file_path)
                
                # Validate document has content
                if not text or len(text.strip()) < 10:
                    return jsonify({'error': 'Document appears to be empty'}), 400
                
                # Get summarizer instance
                ai_summarizer = get_summarizer()
                if ai_summarizer is None:
                    return jsonify({
                        'error': 'AI service not configured. Please set GEMINI_API_KEY in .env file'
                    }), 500
                
                # Get user's summary type preference
                summary_type = request.form.get('summary_type', 'auto')
                
                # Convert summary type to line count
                requested_lines = None
                if summary_type == 'quick':
                    requested_lines = 5  # Always 5 lines for quick
                elif summary_type == 'detailed':
                    requested_lines = max(10, page_count * 6)  # 6 lines per page, min 10
                # For 'auto', leave as None to use default (4 lines per page)
                
                # Get user's selected document type (default: general)
                document_type = request.form.get('document_type', 'general')
                
                # Analyze document with document type
                result = ai_summarizer.analyze_document(text, page_count, requested_lines, document_type)
                
                # Check if user requested too few lines
                warning_message = None
                if requested_lines and requested_lines < result['minimum_lines']:
                    warning_message = f"Note: {summary_type.capitalize()} summary requested, but minimum recommended is {result['minimum_lines']} lines for a {page_count}-page document. Using {result['actual_lines']} lines."
                
                # Clean up uploaded file
                os.remove(file_path)
                
                # Return results
                response_data = {
                    'success': True,
                    'file_type': 'document',
                    'filename': filename,
                    'page_count': result['page_count'],
                    'summary': result['summary'],
                    'key_elements': result['key_elements'],
                    'word_count': len(text.split()),
                    'minimum_lines': result['minimum_lines'],
                    'actual_lines': result['actual_lines']
                }
                
                if warning_message:
                    response_data['warning'] = warning_message
                
                return jsonify(response_data)
            
        except Exception as e:
            # Clean up file on error
            if os.path.exists(file_path):
                os.remove(file_path)
            raise e
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print("=" * 60)
        print("ERROR PROCESSING FILE:")
        print(error_details)
        print("=" * 60)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'gemini_configured': bool(Config.GEMINI_API_KEY)
    })

if __name__ == '__main__':
    print("=" * 60)
    print("AI Document Summarization Engine")
    print("=" * 60)
    print(f"Server starting on http://localhost:5000")
    print(f"Gemini API configured: {bool(Config.GEMINI_API_KEY)}")
    print("=" * 60)
    
    # Run with extra_files to exclude uploads directory from auto-reload
    from werkzeug.serving import run_simple
    if Config.DEBUG:
        # In debug mode, exclude uploads directory from file watching
        run_simple('0.0.0.0', 5000, app, use_reloader=True, 
                   use_debugger=True, extra_files=[])
    else:
        app.run(debug=False, host='0.0.0.0', port=5000)
