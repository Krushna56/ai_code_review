from flask import Flask, render_template, request, redirect, send_from_directory
import os
import shutil
import zipfile
import uuid

from code_analysis import analyze_codebase

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'


def extract_zip(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        uploaded_file = request.files['codebase']
        if uploaded_file.filename == '':
            return redirect(request.url)

        uid = str(uuid.uuid4())
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

        os.makedirs(input_path, exist_ok=True)
        os.makedirs(output_path, exist_ok=True)

        file_path = os.path.join(input_path, uploaded_file.filename)
        uploaded_file.save(file_path)

        if zipfile.is_zipfile(file_path):
            extract_zip(file_path, input_path)

        analysis_result = analyze_codebase(input_path, output_path)

        return render_template('results.html',
                               summary=analysis_result['summary'],
                               details=analysis_result['details'],
                               security=analysis_result['security'])

    return render_template('index.html')


@app.route('/download/<path:filename>')
def download_report(filename):
    return send_from_directory(app.config['PROCESSED_FOLDER'], filename, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)