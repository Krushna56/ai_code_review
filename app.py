from flask import Flask, render_template, request, redirect, send_from_directory, jsonify, send_file
import os
import shutil
import zipfile
import uuid
import logging

from code_analysis import analyze_codebase
from services.report_service import get_report_service
from services.feedback_service import get_feedback_service


# Import API v2 routes
from api.v2_routes import api_v2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Register API v2 blueprint
app.register_blueprint(api_v2)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)


def extract_zip(zip_path, extract_to):
    """Extract ZIP file to directory"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        logger.info(f"Extracted ZIP to {extract_to}")
    except Exception as e:
        logger.error(f"Error extracting ZIP: {e}")
        raise


@app.route('/', methods=['GET', 'POST'])
def index():
    """Main route for file upload and analysis"""
    if request.method == 'POST':
        try:
            # Validate file upload
            if 'codebase' not in request.files:
                logger.warning("No file part in request")
                return render_template('index.html', error="No file uploaded")

            uploaded_file = request.files['codebase']
            if uploaded_file.filename == '':
                logger.warning("Empty filename")
                return render_template('index.html', error="No file selected")

            # Generate unique ID for this analysis
            uid = str(uuid.uuid4())
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

            os.makedirs(input_path, exist_ok=True)
            os.makedirs(output_path, exist_ok=True)

            # Save uploaded file
            filename = uploaded_file.filename if uploaded_file.filename else 'upload'
            file_path = os.path.join(input_path, filename)
            uploaded_file.save(file_path)
            logger.info(f"Saved file: {filename}")

            # Extract if ZIP
            if zipfile.is_zipfile(file_path):
                extract_zip(file_path, input_path)

            # Run analysis
            logger.info(f"Starting analysis for {uid}")
            analysis_result = analyze_codebase(input_path, output_path)
            logger.info(f"Analysis complete for {uid}")

            # Store UID in session for downloads
            analysis_result['uid'] = uid

            return render_template('results.html',
                                   summary=analysis_result['summary'],
                                   details=analysis_result['details'],
                                   security=analysis_result['security'],
                                   linter_results=analysis_result.get(
                                       'linter_results', {}),
                                   comprehensive_report=analysis_result.get(
                                       'comprehensive_report'),
                                   uid=uid)

        except Exception as e:
            logger.error(f"Error during analysis: {e}", exc_info=True)
            return render_template('index.html', error=f"Analysis failed: {str(e)}")

    return render_template('index.html')


@app.route('/chat')
def chat():
    """Interactive chat interface route"""
    return render_template('chat.html')


@app.route('/download/<uid>/<filename>')
def download_report(uid, filename):
    """Download generated reports"""
    try:
        file_path = os.path.join(app.config['PROCESSED_FOLDER'], uid, filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            logger.warning(f"File not found: {file_path}")
            return "File not found", 404
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return str(e), 500


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic access"""
    try:
        if 'codebase' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        uploaded_file = request.files['codebase']
        if uploaded_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        uid = str(uuid.uuid4())
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

        os.makedirs(input_path, exist_ok=True)
        os.makedirs(output_path, exist_ok=True)

        filename = uploaded_file.filename
        file_path = os.path.join(input_path, filename)
        uploaded_file.save(file_path)

        if zipfile.is_zipfile(file_path):
            extract_zip(file_path, input_path)

        analysis_result = analyze_codebase(input_path, output_path)

        return jsonify({
            'uid': uid,
            'summary': analysis_result['summary'],
            'comprehensive_report': analysis_result.get('comprehensive_report'),
            'download_url': f'/download/{uid}/comprehensive_report.json'
        })

    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '1.0'}), 200


@app.route('/api/query', methods=['POST'])
def api_query():
    """API endpoint for natural language security queries"""
    try:
        data = request.get_json()
        if not data or 'question' not in data:
            return jsonify({'error': 'No question provided'}), 400

        question = data['question']
        max_results = data.get('max_results', 5)

        logger.info(f"API query: {question}")

        # Import here to avoid circular dependencies
        from query.query_handler import QueryHandler
        from indexing.code_indexer import CodeIndexer

        indexer = CodeIndexer()
        handler = QueryHandler(indexer=indexer)

        response = handler.query(question, k=max_results)

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Query API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ====================
# Phase 6: Dashboard Routes
# ====================

@app.route('/dashboard')
def dashboard():
    """Security dashboard page"""
    try:
        service = get_report_service()
        summary = service.get_summary()
        return render_template('dashboard.html', summary=summary)
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return render_template('dashboard.html', error=str(e))


@app.route('/api/security/summary')
def api_security_summary():
    """Get executive summary data"""
    try:
        service = get_report_service()
        summary = service.get_summary()
        return jsonify(summary), 200
    except Exception as e:
        logger.error(f"Summary API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/charts')
def api_security_charts():
    """Get all dashboard charts data"""
    try:
        service = get_report_service()
        charts = service.get_dashboard_data()
        return jsonify(charts), 200
    except Exception as e:
        logger.error(f"Charts API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/findings')
def api_security_findings():
    """Get security findings with filtering and pagination"""
    try:
        service = get_report_service()

        # Get query parameters
        severity = request.args.get('severity')
        owasp_category = request.args.get('owasp_category')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        findings = service.get_findings(
            severity=severity,
            owasp_category=owasp_category,
            limit=limit,
            offset=offset
        )

        return jsonify(findings), 200
    except Exception as e:
        logger.error(f"Findings API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/finding/<finding_id>')
def api_security_finding_detail(finding_id):
    """Get detailed information for a specific finding"""
    try:
        service = get_report_service()
        finding = service.get_finding_by_id(finding_id)

        if finding:
            return jsonify(finding), 200
        else:
            return jsonify({'error': 'Finding not found'}), 404
    except Exception as e:
        logger.error(f"Finding detail API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/remediation')
def api_security_remediation():
    """Get prioritized remediation plan"""
    try:
        service = get_report_service()
        plan = service.get_remediation_plan()
        return jsonify({'remediation_plan': plan}), 200
    except Exception as e:
        logger.error(f"Remediation API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/refresh')
def api_security_refresh():
    """Clear cache and refresh dashboard data"""
    try:
        service = get_report_service()
        service.clear_cache()
        return jsonify({'status': 'cache cleared'}), 200
    except Exception as e:
        logger.error(f"Refresh API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback', methods=['POST'])
def api_save_feedback():
    """Save user feedback for a finding"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        finding_id = data.get('finding_id')
        feedback_type = data.get('feedback_type')
        comment = data.get('comment', '')
        code_snippet = data.get('code_snippet', '')
        
        if not finding_id or not feedback_type:
            return jsonify({'error': 'finding_id and feedback_type are required'}), 400
            
        service = get_feedback_service()
        success = service.save_feedback(finding_id, feedback_type, comment, code_snippet)
        
        if success:
            return jsonify({'message': 'Feedback saved successfully'}), 200
        else:
            return jsonify({'error': 'Failed to save feedback'}), 500
            
    except Exception as e:
        logger.error(f"Feedback API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    return render_template('index.html', error="File too large. Maximum size is 50MB"), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal error: {error}")
    return render_template('index.html', error="Internal server error occurred"), 500


if __name__ == '__main__':
    logger.info("Starting AI Code Review Platform...")
    # Disable auto-reload to prevent connection resets during uploads
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
