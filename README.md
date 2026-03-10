# 🔍 AI-Powered Code Review Platform

An intelligent, enterprise-grade AI code analysis platform that combines multi-layered static analysis, machine learning, and specialized LLM agents to provide comprehensive security reviews, code quality assessments, and interactive code discussions.

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ✨ Key Features

### 🔐 Security Analysis

- **Multi-layered Static Analysis**: Integrated with **Bandit**, **Semgrep**, and **Ruff**.
- **CVE Detection**: Automatic vulnerability scanning for dependencies using the **OSV database**.
- **Secret Detection**: Regex and entropy-based identification of hardcoded credentials/API keys.
- **OWASP Top 10 Mapping**: Every finding is categorized by **OWASP 2021** standards.

### 🤖 AI Intelligence

- **LLM Specialized Agents**: Context-aware agents for **Security Review** and **Code Refactoring**.
- **Multi-Provider Support**: Compatible with **OpenAI**, **Anthropic**, **Mistral**, and **Gemini**.
- **Interactive Chat**: Conversational AI interface for discussing code security with context.
- **RAG-Enhanced Retrieval**: Retrieval-Augmented Generation using **Qdrant** for high-accuracy answers.

### 🔍 Code Quality & Insights

- **AST Metrics**: extraction of cyclomatic complexity, maintainability index, and LOC.
- **Automated Refactoring**: AI-generated suggestions for design pattern improvements and code cleanup.
- **Semantic Code Search**: Find similar code patterns using vector-based similarity search.

---

## 🏗️ Architecture Breakdown

### High-Level System Architecture

The platform follows a modular, 6-phase hybrid architecture that integrates traditional static analysis with modern AI/ML layers.

```mermaid
graph TB
    subgraph "User Interface Layer"
        WEB[Web Dashboard<br/>Port 5000]
        CHAT[Chat Interface<br/>Real-time]
        API[REST API v2<br/>/api/v2/*]
    end

    subgraph "Application Layer"
        FLASK[Flask Application<br/>app.py]
        ROUTES[Route Handlers]
        SERVICES[Service Layer]
    end

    subgraph "Analysis Pipeline"
        ANALYZER[Code Analyzer<br/>code_analysis.py]
        AST[AST Parser<br/>Metrics Extraction]
        LINTERS[Multi-Linter<br/>Bandit/Semgrep/Ruff]
        EMBEDDINGS[Code Embeddings<br/>Semantic Vectors]
        LLM[LLM Agents<br/>Security/Refactor]
    end

    subgraph "Security Intelligence Layer"
        CVE[CVE Tracker<br/>OSV API]
        SECRETS[Secret Detector<br/>Pattern Matching]
        DEPS[Dependency Analyzer<br/>Maven/npm/Python]
        OWASP[OWASP Mapper<br/>Top 10 2021]
    end

    subgraph "AI/ML Layer"
        SECURITY_AGENT[Security Reviewer<br/>GPT-4/Claude]
        REFACTOR_AGENT[Refactor Agent<br/>Code Quality]
        CHAT_ENGINE[Chat Engine<br/>Context-Aware]
        RETRIEVAL[Hybrid Retriever<br/>RAG System]
    end

    subgraph "Data Layer"
        VECTOR_DB[(Vector DB<br/>Qdrant/FAISS)]
        CHAT_DB[(Chat History<br/>SQLite)]
        CACHE[(Report Cache<br/>In-Memory)]
        FILES[(File Storage<br/>uploads/processed)]
    end

    subgraph "Reporting Layer"
        REPORT_GEN[Security Report<br/>Generator]
        FIX_GEN[Fix Suggestion<br/>Generator]
        DASHBOARD_EXPORT[Dashboard<br/>Exporter]
    end

    WEB --> FLASK
    CHAT --> FLASK
    API --> ROUTES

    FLASK --> ANALYZER
    FLASK --> SERVICES

    ANALYZER --> AST
    ANALYZER --> LINTERS
    ANALYZER --> EMBEDDINGS
    ANALYZER --> LLM

    ANALYZER --> CVE
    ANALYZER --> SECRETS
    ANALYZER --> DEPS

    LLM --> SECURITY_AGENT
    LLM --> REFACTOR_AGENT

    SERVICES --> CHAT_ENGINE
    SERVICES --> RETRIEVAL
    SERVICES --> REPORT_GEN

    EMBEDDINGS --> VECTOR_DB
    CHAT_ENGINE --> CHAT_DB
    REPORT_GEN --> CACHE

    CVE --> OWASP
    DEPS --> CVE

    REPORT_GEN --> DASHBOARD_EXPORT
    REPORT_GEN --> FIX_GEN

    ANALYZER --> FILES
```

### 6-Phase Integration Pipeline

```mermaid
flowchart LR
    subgraph "Phase 1: Static Analysis"
        P1[AST Parsing<br/>Multi-Linter<br/>Metrics]
    end

    subgraph "Phase 2: Semantic Understanding"
        P2[Code Embeddings<br/>Vector Store<br/>Semantic Search]
    end

    subgraph "Phase 3: LLM Intelligence"
        P3[Security Agent<br/>Refactor Agent<br/>RAG Context]
    end

    subgraph "Phase 4: CVE Detection"
        P4[Dependency Scan<br/>CVE Tracking<br/>OWASP Mapping]
    end

    subgraph "Phase 5: Security Reporting"
        P5[Report Generation<br/>Fix Suggestions<br/>Dashboard Export]
    end

    subgraph "Phase 6: Web Dashboard"
        P6[Interactive UI<br/>Real-time Charts<br/>Findings Explorer]
    end

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P5 --> P6

    P6 -.Refresh.-> P1
```

### Key Components

#### Backend Core

- **`app.py`**: Main Flask application with routes and middleware
- **`code_analysis.py`**: Orchestrates the entire analysis pipeline
- **`config.py`**: Centralized configuration management

#### Analysis Pipeline

- **Static Analysis**: AST parsing, linting (Bandit, Semgrep, Ruff)
- **CVE Detection**: Dependency scanning via OSV database
- **Secret Detection**: Regex and entropy-based credential detection
- **LLM Analysis**: AI-powered security review and refactoring

#### AI/ML Components

- **Chat Engine**: Context-aware conversational AI
- **LLM Agents**: Specialized agents for different tasks
- **Vector Store**: Qdrant-based semantic code search
- **RAG System**: Retrieval-Augmented Generation for accurate responses

#### Reporting

- **Meta Reasoner**: Aggregates findings from multiple sources
- **Report Generator**: Creates JSON and Markdown reports
- **Dashboard Exporter**: Formats data for UI visualization
- **Fix Generator**: Provides actionable remediation steps

---

## 🛠️ Technology Stack

### Backend & Frameworks

| Category     | Technology                                |
| :----------- | :---------------------------------------- |
| **Core**     | Python 3.9+, Flask 3.0.0                  |
| **WSGI**     | Gunicorn (Production)                     |
| **Database** | SQLite (Auth/Chat), Qdrant (Vector Store) |

### Static Analysis Tools

| Tool        | Purpose                                 |
| :---------- | :-------------------------------------- |
| **Bandit**  | Python security vulnerability detection |
| **Semgrep** | Multi-language pattern-based analysis   |
| **Ruff**    | Ultra-fast Python linter (Rust)         |
| **Radon**   | Code complexity and cyclomatic metrics  |

### AI & Machine Learning

| Component         | Technology                                            |
| :---------------- | :---------------------------------------------------- |
| **LLM Providers** | OpenAI (GPT-4), Anthropic (Claude 3), Google (Gemini) |
| **Embeddings**    | Sentence-Transformers (Local), OpenAI Embeddings      |
| **Vector DB**     | Qdrant, FAISS                                         |
| **RAG**           | Hybrid Retrieval (Vector + Keyword)                   |

---

## 🔒 Security Features

### Multi-Layer Security Analysis

1. **Static Analysis**
   - Bandit: Python-specific security issues
   - Semgrep: Pattern-based vulnerability detection
   - Ruff: Fast Python linter with security rules

2. **Dependency Scanning**
   - OSV database integration
   - Real-time CVE lookups
   - Version-specific vulnerability matching

3. **Secret Detection**
   - Regex-based pattern matching
   - Entropy analysis for random strings
   - Context-aware false positive reduction

4. **LLM-Powered Review**
   - Deep semantic analysis
   - Context-aware vulnerability detection
   - Business logic flaw identification

### OWASP Top 10 Coverage

All findings are mapped to OWASP categories:

| Category                                    | Detection Method           |
| :------------------------------------------ | :------------------------- |
| **A01: Broken Access Control**              | Semgrep, LLM Agent         |
| **A02: Cryptographic Failures**             | Secret Detector, Bandit    |
| **A03: Injection**                          | Bandit, Semgrep, LLM Agent |
| **A04: Insecure Design**                    | LLM Agent                  |
| **A05: Security Misconfiguration**          | Semgrep, LLM Agent         |
| **A06: Vulnerable Components**              | CVE Tracker, OSV database  |
| **A07: Identification & Auth Failures**     | Semgrep, LLM Agent         |
| **A08: Software & Data Integrity Failures** | Dependency Analysis        |
| **A09: Logging & Monitoring Failures**      | LLM Agent                  |
| **A10: Server-Side Request Forgery**        | Semgrep, LLM Agent         |

---

## 📁 Project Structure

```
ai_code_review/
├── backend/
│   ├── api/                      # REST API Endpoints (v2, file issues)
│   ├── auth/                     # GitHub OAuth & user management
│   ├── embeddings/               # Semantic vectors & Qdrant logic
│   ├── llm_agents/               # Core AI logic (Chat, Security Reviewer)
│   ├── security/                 # CVE tracker, secret detector, OWASP mapper
│   ├── static_analysis/          # AST parsing & multi-linter orchestrator
│   ├── query/                    # RAG retrieval system
│   ├── reporting/                # Fix generator & dashboard exporter
│   └── app.py                    # Main Flask entry point
├── frontend/
│   ├── static/                   # Modern UI assets (CSS/JS)
│   └── templates/                # HTML5 templates (Dashboard, Chat)
├── docs/                         # Detailed technical documentation
└── docker-compose.yml            # Containerized orchestration
```

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.9+
- Docker & Docker Compose (for Qdrant)

### 2. Installation

```bash
git clone https://github.com/Krushna56/ai_code_review.git
cd ai_code_review
pip install -r backend/requirements.txt
```

### 3. Configuration

Copy `.env.example` to `.env` and configure your API keys:

```bash
cp backend/.env.example backend/.env
# Edit backend/.env and add your OPENAI_API_KEY or ANTHROPIC_API_KEY
```

### 4. Run the Application

```bash
# Start Qdrant first (Recommended)
docker-compose up -d qdrant

# Launch the Flask server
python backend/app.py
```

Open `http://localhost:5000` to start your first analysis.

---

## 📚 Documentation & Guides

- 🐳 **[Docker Deployment Guide](docs/README_DOCKER.md)**
- 🔑 **[Authentication Setup](docs/AUTHENTICATION_SETUP.md)**
- 🏗️ **[Deep Architecture Dive](docs/README_ARCHITECTURE.md)**

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide for Python code
- Add unit tests for new features
- Update documentation for API changes
- Ensure all tests pass before submitting PR

---

## 🙏 Acknowledgments

- **OpenAI** for GPT models
- **Anthropic** for Claude
- **Mistral AI** for Mistral models
- **Google** for Gemini
- **Qdrant** for vector database
- **Semgrep** for static analysis
- **OSV** for vulnerability database

---

## 📞 Support

For issues, questions, or contributions:

- 🐛 [Report a Bug](https://github.com/Krushna56/ai_code_review/issues)
- 💡 [Request a Feature](https://github.com/Krushna56/ai_code_review/issues)
- 📧 Email: krushanakumbhar314@gmail.com

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
