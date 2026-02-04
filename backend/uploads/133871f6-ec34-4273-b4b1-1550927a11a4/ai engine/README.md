# AI Document Summarization Engine

An intelligent web application that extracts key elements from uploaded documents and generates AI-powered summaries proportional to document size.

## ✨ Features

-  **Multi-Format Support**: PDF, DOCX, and TXT files
-  **AI-Powered**: Uses Google Gemini 1.5 Pro for intelligent summarization
-  **Adaptive Summaries**: Automatically generates 3-4 lines per page
-  **Key Element Extraction**: Identifies important topics and concepts
-  **Beautiful UI**: Modern, responsive design with drag-and-drop upload
-  **Secure**: Files are processed and deleted immediately

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Google Gemini API key (get it free at [Google AI Studio](https://makersuite.google.com/app/apikey))

### Installation

1. **Clone or download this repository**

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Set up environment variables**:

```bash
# Copy the example env file
copy .env.example .env

# Edit .env and add your Gemini API key
# GEMINI_API_KEY=your_actual_api_key_here
```

4. **Run the application**:

```bash
python app.py
```

5. **Open your browser** and navigate to:

```
http://localhost:5000
```

## 🎯 How to Use

1. **Upload a Document**: Drag and drop or click to browse for PDF, DOCX, or TXT files
2. **Wait for Analysis**: The AI will process your document (usually takes 5-15 seconds)
3. **View Results**: See the generated summary and extracted key elements
4. **Analyze Another**: Click the button to analyze more documents

## 📁 Project Structure

```
ai engine/
├── app.py                 # Flask application server
├── config.py             # Configuration settings
├── document_processor.py # Document parsing utilities
├── summarizer.py         # AI summarization engine
├── requirements.txt      # Python dependencies
├── .env.example         # Environment template
├── static/
│   ├── index.html       # Web interface
│   ├── style.css        # Styling
│   └── script.js        # Client-side logic
└── uploads/             # Temporary file storage (auto-created)
```

## 🔧 Configuration

Edit `config.py` to customize:

- **LINES_PER_PAGE**: Summary length (default: 4 lines per page)
- **MAX_KEY_ELEMENTS**: Maximum key elements to extract (default: 8)
- **MAX_FILE_SIZE**: Maximum upload size (default: 50MB)
- **ALLOWED_EXTENSIONS**: Supported file types

## 🌐 API Endpoints

### `POST /upload`

Upload and analyze a document.

**Request**: Multipart form data with `file` field

**Response**:

```json
{
  "success": true,
  "filename": "document.pdf",
  "page_count": 3,
  "word_count": 1234,
  "summary": "Generated summary text...",
  "key_elements": ["Element 1", "Element 2", ...]
}
```

### `GET /health`

Check service health status.

**Response**:

```json
{
  "status": "healthy",
  "gemini_configured": true
}
```

## 🔑 Getting Your Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Get API Key"
4. Copy the key and add it to your `.env` file

**Note**: Gemini 1.5 Pro has a generous free tier with high rate limits.

## 🎨 Technology Stack

- **Backend**: Flask (Python)
- **AI Model**: Google Gemini 1.5 Pro
- **Document Processing**: PyPDF2, python-docx
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Design**: Custom glassmorphism with gradient themes

## 📊 Example Use Cases

- **Research Papers**: Get quick summaries of academic papers
- **Business Reports**: Extract key insights from lengthy reports
- **Documentation**: Understand technical docs quickly
- **Meeting Notes**: Summarize and extract action items
- **Articles & Essays**: Get the main points at a glance

## 🛡️ Security & Privacy

- Files are temporarily stored only during processing
- All uploaded files are deleted immediately after analysis
- No data is stored or logged permanently
- API keys are kept secure in environment variables

## 🐛 Troubleshooting

**Error: "GEMINI_API_KEY not found"**

- Make sure you've created a `.env` file with your API key

**Error: "Document appears to be empty"**

- Check that your PDF/DOCX is not password-protected or corrupted

**Error: "Invalid file type"**

- Only PDF, DOCX, and TXT files are supported

**Slow processing**

- Large documents (20+ pages) may take 15-30 seconds to process
- Check your internet connection for API calls

## 📝 License

This project is open source and available for personal and commercial use.

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Report bugs
- Suggest new features
- Submit pull requests

## 💡 Future Enhancements

- [ ] Support for more file formats (PPTX, Excel)
- [ ] Batch processing multiple documents
- [ ] Export summaries as PDF/DOCX
- [ ] Multi-language support
- [ ] Custom summary length options
- [ ] Document comparison feature

## 📧 Support

If you encounter any issues or have questions, please open an issue on the repository.

---

**Built with ❤️ using Google Gemini 1.5 Pro**
