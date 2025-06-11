from flask import Flask, render_template, request, redirect, url_for
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
        uploaded_files = request.files.getlist('files')  # list of files

        if not uploaded_files or uploaded_files[0].filename == '':
            return "No files uploaded", 400

        uid = str(uuid.uuid4())
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

        os.makedirs(input_path, exist_ok=True)
        os.makedirs(output_path, exist_ok=True)

        # Save each uploaded file
        for file in uploaded_files:
            file_path = os.path.join(input_path, file.filename)
            file.save(file_path)

        # Check if a zip file is among uploaded files — if yes, extract it and delete originals to avoid duplicates
        for file in uploaded_files:
            if file.filename.endswith('.zip'):
                zip_path = os.path.join(input_path, file.filename)
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(input_path)
                    os.remove(zip_path)  # remove the zip after extracting
                except zipfile.BadZipFile:
                    # Just keep the zip file if invalid or corrupted
                    pass

        # Now analyze whatever is inside input_path — raw files or extracted zip contents
        analysis_result = analyze_codebase(input_path, output_path)

        return render_template('results.html',
                               summary=analysis_result['summary'],
                               details=analysis_result['details'],
                               security=analysis_result['security'])

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
