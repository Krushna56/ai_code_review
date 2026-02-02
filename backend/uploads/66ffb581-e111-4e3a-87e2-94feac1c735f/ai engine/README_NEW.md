# AI Document Summarization Engine 🤖

> Intelligent document and code analysis powered by Google Gemini 2.5 Flash API

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-purple.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🎯 What It Does

An AI-powered platform that **automatically analyzes and summarizes** documents and code files, providing:

- 📄 **Smart Summaries** - Auto-scaled based on document length
- 💻 **Code Analysis** - Architecture diagrams, metrics, and logic breakdown
- ⚖️ **Legal Insights** - Conflict detection, loopholes, and law references
- 🎨 **Beautiful UI** - Modern glassmorphic design with dark theme

## ✨ Key Features

| Feature                  | Description                                     |
| ------------------------ | ----------------------------------------------- |
| **Multi-Format Support** | PDF, DOCX, TXT + 20+ programming languages      |
| **Document Types**       | General, Legal, Code, Books, Letters, Research  |
| **Legal Analysis**       | Detects conflicts, loopholes, and explains laws |
| **Code Visualization**   | Auto-generates Mermaid architecture diagrams    |
| **Adaptive Summaries**   | 4 lines per page (customizable)                 |
| **Large Files**          | Supports up to 10GB                             |

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Key

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY from https://aistudio.google.com/app/apikey
```

### 3. Run

```bash
python app.py
```

### 4. Open Browser

```
http://localhost:5000
```

## 📁 Project Structure

```
ai-engine/
├── app.py                   # Main Flask application
├── config.py                # Configuration settings
├── document_processor.py    # File parsing (PDF, DOCX, TXT, code)
├── summarizer.py            # AI summarization engine
├── code_analyzer.py         # Code analysis & diagram generation
├── static/
│   ├── index.html          # Frontend UI
│   ├── style.css           # Glassmorphic styling
│   └── script.js           # Client-side logic
├── uploads/                 # Temp file storage
└── .env                     # API keys (not in repo)
```

## 🛠️ Tech Stack

**Backend**

- Python 3.8+
- Flask (Web Framework)
- Google Gemini 2.5 Flash API
- PyPDF2, python-docx

**Frontend**

- Vanilla HTML5, CSS3, JavaScript
- Mermaid.js (Diagrams)
- No external CSS frameworks

## 💡 Usage Examples

### General Document

Upload a PDF/DOCX → Get concise summary + key elements

### Code File

Upload .py/.js/.java → Get:

- Code metrics (lines, functions, classes)
- Logic summary (what it does)
- Architecture analysis (design patterns, components)
- Visual diagram (Mermaid flowchart/class diagram)

### Legal Document

Upload contract/agreement → Get:

- Summary of terms
- Conflicting clauses
- Potential loopholes
- Referenced laws (with plain language explanations)

## 🎨 Screenshots

_[Add screenshots of UI here]_

## 📊 Example Output

**For a 5-page document:**

- Quick Summary: 20 lines (4 per page)
- Detailed Overview: 7 lines narrative
- Key Elements: Up to 20 extracted topics
- Document-specific analysis (legal/code insights)

## 🔐 Environment Variables

```env
GEMINI_API_KEY=your_api_key_here
SECRET_KEY=your_flask_secret_key
DEBUG=True
```

## 🌟 Highlights for Interviewers

1. **AI/LLM Integration** - Advanced prompt engineering for domain-specific analysis
2. **Full-Stack Development** - Backend (Python/Flask) + Frontend (HTML/CSS/JS)
3. **Production-Ready** - Error handling, lazy initialization, configuration management
4. **Problem-Solving** - Solved encoding issues, auto-reloader conflicts, adaptive summarization
5. **Modern UI** - Custom glassmorphism, no CSS frameworks, responsive design

## 📝 Skills Demonstrated

✅ Python & Flask  
✅ REST API Development  
✅ AI/LLM Integration (Gemini API)  
✅ Frontend Development (HTML/CSS/JS)  
✅ Document Processing (PDF, DOCX)  
✅ Code Architecture Design  
✅ UX/UI Design  
✅ Environment Configuration

## 📖 Documentation

For detailed technical documentation, architecture details, and pitch materials, see:

- **[PITCH.md](./PITCH.md)** - Comprehensive project documentation for interviews

## 🤝 Contributing

This is a portfolio/interview project. Feel free to fork and adapt for your own use!

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Credits

- Google Gemini API for AI capabilities
- Mermaid.js for diagram rendering
- Inter font for typography

---

**Built by [Your Name]** | [GitHub](https://github.com/yourusername) | [LinkedIn](https://linkedin.com/in/yourprofile)
