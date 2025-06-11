from flask import Flask, render_template, request, redirect, url_for
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'codebase' not in request.files:
        return "No file uploaded", 400

    file = request.files['codebase']
    if file.filename == '':
        return "No selected file", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Get selected review goals (optional for now)
    goals = request.form.getlist('goals')
    print("Selected goals:", goals)

    return redirect(url_for('processing'))

@app.route('/processing')
def processing():
    return render_template('processing.html')

@app.route('/results')
def results():
    return render_template('results.html')  # dummy for now

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
