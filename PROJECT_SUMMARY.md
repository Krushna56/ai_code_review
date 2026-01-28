# AI Code Review Platform - Quick Reference Guide

## 📋 Project Overview

**Name:** AI-Powered Code Review Platform  
**Type:** Security Analysis & Code Review System  
**Architecture:** 6-Phase Hybrid ML + LLM Pipeline  
**Language:** Python 3.8+  
**Framework:** Flask 3.0.0

---

## 🎯 What Does This Platform Do?

This platform automatically analyzes codebases to find security vulnerabilities, code quality issues, and provides AI-powered recommendations. It's like having a senior security engineer and code reviewer working 24/7.

### Key Capabilities:

✅ **Security Vulnerability Detection** - SQL injection, XSS, hardcoded secrets, etc.  
✅ **Dependency CVE Scanning** - Detects known vulnerabilities in packages  
✅ **Code Quality Analysis** - Complexity, metrics, anti-patterns  
✅ **AI-Powered Insights** - LLM agents provide context-aware recommendations  
✅ **Natural Language Queries** - Ask questions like "Are there any hardcoded API keys?"  
✅ **Interactive Dashboard** - Real-time visualization of security posture  
✅ **Chat Interface** - Conversational code review with streaming responses

---

## 🏗️ System Architecture (High-Level)

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Web    │  │   Chat   │  │   API    │  │Dashboard │   │
│  │ Upload   │  │Interface │  │  v2      │  │  (Phase  │   │
│  │  (Zip)   │  │(Streaming)│  │          │  │    6)    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│              ANALYSIS PIPELINE (6 Phases)                    │
│                                                               │
│  Phase 1: Static Analysis (AST, Linters)                    │
│  Phase 2: Semantic Understanding (Embeddings, Vectors)       │
│  Phase 3: LLM Intelligence (Security Agent, Refactor)        │
│  Phase 4: CVE Detection (Dependencies, OSV API)              │
│  Phase 5: Reporting (Reports, Fixes, Dashboard Data)         │
│  Phase 6: Web Dashboard (Charts, Findings, Remediation)      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   DATA STORAGE                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Vector  │  │  SQLite  │  │   File   │  │  Report  │   │
│  │Database  │  │  (Chat)  │  │ Storage  │  │  Cache   │   │
│  │(Qdrant)  │  │          │  │          │  │          │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Analysis Flow

1. **User uploads code** (ZIP file or GitHub repo URL)
2. **Static analysis runs** - AST parsing, complexity metrics, code formatting
3. **Linters execute** - Bandit (security), Semgrep (patterns), Ruff (style)
4. **Dependencies scanned** - Detects Maven, npm, Python packages
5. **CVE database queried** - Checks for known vulnerabilities via OSV API
6. **Secrets detected** - Regex patterns find hardcoded credentials
7. **Code embedded** - Generates semantic vectors for RAG
8. **LLM agents analyze** - Security and refactoring suggestions
9. **Reports generated** - JSON, Markdown, dashboard-ready data
10. **Dashboard displays** - Interactive charts, findings, remediation plan

---

## 🔧 Technology Stack Summary

### Backend Core

- **Python 3.8+** - Core language
- **Flask 3.0** - Web framework
- **Gunicorn** - WSGI server (production)

### Static Analysis

- **Bandit** - Python security scanner
- **Semgrep** - Multi-language pattern matching
- **Ruff** - Fast Python linter (Rust-based)
- **Pylint** - Code quality (optional)
- **Radon** - Complexity metrics

### AI/ML Stack

- **OpenAI GPT-4** - Primary LLM (or Anthropic Claude, Mistral)
- **Sentence-Transformers** - Local embeddings (all-MiniLM-L6-v2)
- **Qdrant** - Vector database for semantic search
- **FAISS** - Alternative vector store (CPU-optimized)

### Security Tools

- **detect-secrets** - Secret scanning
- **OSV API** - CVE vulnerability database
- **Custom OWASP Mapper** - Top 10 2021 categorization

### Frontend

- **Vanilla JavaScript** - No framework overhead
- **Chart.js** - Interactive visualizations
- **Highlight.js** - Code syntax highlighting
- **Markdown-it** - Markdown rendering

### Data Storage

- **SQLite** - Chat conversation history
- **File System** - Code uploads, processed results
- **In-Memory Cache** - Report caching

---

## 📁 Critical Files

| File                              | Size  | Purpose                            |
| --------------------------------- | ----- | ---------------------------------- |
| `app.py`                          | 18KB  | Flask web application, all routes  |
| `code_analysis.py`                | 24KB  | Main analysis pipeline (6 phases)  |
| `config.py`                       | 5.6KB | Configuration management           |
| `query/query_handler.py`          | 7.7KB | Natural language query processing  |
| `security/cve_tracker.py`         | 16KB  | CVE detection via OSV              |
| `security/dependency_analyzer.py` | 21KB  | Multi-language dependency scanning |
| `security/owasp_mapper.py`        | 21KB  | OWASP Top 10 mapping               |
| `llm_agents/chat_engine.py`       | 12KB  | Conversational AI with streaming   |
| `services/report_service.py`      | 14KB  | Report caching and dashboard API   |
| `templates/dashboard.html`        | 7KB   | Dashboard UI                       |
| `static/js/dashboard.js`          | -     | Chart.js visualizations            |

---

## 🚀 Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Configure (edit .env with API keys)
copy .env.example .env

# Run web server
python app.py
# Open http://localhost:5000

# Or use CLI
python main.py analyze ./my-project -o ./results

# Or launch dashboard directly
python main.py web
```

---

## 🔐 Security Features by Category

### Vulnerability Detection

- ✅ SQL Injection (CWE-89)
- ✅ Cross-Site Scripting (CWE-79)
- ✅ Command Injection (CWE-78)
- ✅ Path Traversal (CWE-22)
- ✅ Hardcoded Secrets (CWE-798)
- ✅ Insecure Deserialization (CWE-502)
- ✅ XML External Entities (CWE-611)
- ✅ Security Misconfiguration

### Cryptographic Issues

- ✅ Weak Algorithms (MD5, SHA1)
- ✅ Hardcoded Keys
- ✅ Insecure Random
- ✅ Missing Encryption

### Authentication & Authorization

- ✅ Broken Access Control
- ✅ Session Management
- ✅ Weak Passwords
- ✅ Missing Auth Checks

### Dependency Security

- ✅ CVE Detection (OSV)
- ✅ Outdated Packages
- ✅ Known Vulnerabilities
- ✅ Severity Scoring (CVSS)

---

## 📊 Dashboard Features

### Executive Summary

- Total findings count
- Severity breakdown (Critical/High/Medium/Low)
- Risk score (0-100)
- Files analyzed count
- CVE vulnerabilities count

### Interactive Charts

1. **Severity Distribution** - Pie chart
2. **OWASP Top 10 Coverage** - Bar chart
3. **Vulnerability Trends** - Line chart (over time)
4. **File Risk Heatmap** - Top risky files
5. **Remediation Effort** - Effort vs. impact matrix

### Findings Explorer

- Filterable table (by severity, OWASP category)
- Pagination support
- Drill-down to detailed view
- Code snippets with syntax highlighting
- Remediation guidance

### Remediation Plan

- Prioritized action items
- Effort estimates (hours)
- Impact assessment
- Fix suggestions with code patches

---

## 🤖 LLM Agents

### Security Reviewer Agent

**Purpose:** Deep security analysis beyond static rules

**Capabilities:**

- Context-aware vulnerability detection
- Business logic flaw identification
- Design pattern anti-patterns
- Security best practices recommendations

**Prompt Strategy:**

- Chain-of-thought reasoning
- Injects code metrics and static issues as context
- Structured JSON output

### Refactor Agent

**Purpose:** Code quality improvements

**Capabilities:**

- Code smell detection
- Performance optimization suggestions
- Design pattern recommendations
- Duplication reduction

### Chat Engine

**Purpose:** Conversational code review

**Features:**

- Multi-turn conversations
- Intent detection (security vs. refactoring)
- Context retention (SQLite history)
- Streaming responses (SSE)
- Export to Markdown/JSON

---

## 🔍 Query System (RAG)

### Hybrid Retrieval Architecture

1. **Vector Search** - Semantic similarity (embeddings)
2. **Keyword Search** - Exact pattern matching
3. **Re-ranking** - Combines scores
4. **Context Building** - Top-k results
5. **LLM Generation** - Answer with citations

### Supported Query Types

- **Hardcoded Secrets:** "Are there any API keys in the code?"
- **SQL Injection:** "Show me SQL injection vulnerabilities"
- **XSS:** "Find cross-site scripting risks"
- **CVE:** "Which dependencies have known vulnerabilities?"
- **Location:** "Where is authentication implemented?"
- **General:** "What are the main security concerns?"

### Intent Detection

```python
# Example intents
'hardcoded_secrets' → Searches for credential patterns
'sql_injection'     → Focuses on SQLi vectors
'xss'               → Looks for XSS vulnerabilities
'cve'               → Queries dependency vulnerabilities
'location'          → Code navigation queries
'general'           → Broad security questions
```

---

## 📈 Performance Metrics

| Metric             | Small Project | Medium Project | Large Project |
| ------------------ | ------------- | -------------- | ------------- |
| **Files**          | 10            | 100            | 1,000         |
| **Lines of Code**  | 1,000         | 10,000         | 100,000       |
| **Analysis Time**  | <30 seconds   | <3 minutes     | <15 minutes   |
| **Memory Usage**   | ~500 MB       | ~1.5 GB        | ~4 GB         |
| **Findings (avg)** | 5-15          | 30-100         | 200-500       |

---

## ⚙️ Configuration Options

### Feature Flags (Enable/Disable)

```bash
ENABLE_BANDIT=true           # Security scanning
ENABLE_SEMGREP=true          # Pattern matching
ENABLE_RUFF=true             # Fast linting
ENABLE_PYLINT=false          # Slow, disabled by default
ENABLE_LLM_AGENTS=true       # AI analysis
ENABLE_SEMANTIC_SEARCH=true  # Vector search
ENABLE_CVE_DETECTION=true    # Dependency scanning
ENABLE_STREAMING=true        # SSE for chat
```

### LLM Provider Options

```bash
# Choose one:
LLM_PROVIDER=openai          # GPT-4 (best quality)
LLM_PROVIDER=anthropic       # Claude 3 (good alternative)
LLM_PROVIDER=mistral         # Codestral (code-specific)
```

### Embedding Provider Options

```bash
# Choose one:
EMBEDDING_PROVIDER=local     # Free, sentence-transformers
EMBEDDING_PROVIDER=openai    # Paid, higher quality
EMBEDDING_PROVIDER=codestral # Code-optimized
```

---

## 🗂️ Output Files

### After Analysis

```
processed/<uuid>/
├── security_report.json      # Comprehensive security data
├── security_report.md         # Human-readable report
├── dashboard_data.json        # Dashboard visualization data
├── linter_results.json        # Static analysis results
├── cve_results.json           # CVE vulnerabilities
├── fix_suggestions.json       # Automated fix recommendations
└── comprehensive_report.json  # Meta-reasoner output
```

### Dashboard Data Structure

```json
{
  "summary": {
    "total_findings": 42,
    "critical": 5,
    "high": 15,
    "medium": 18,
    "low": 4,
    "risk_score": 78.5
  },
  "findings": [...],
  "charts": {
    "severity_distribution": {...},
    "owasp_coverage": {...}
  },
  "remediation_plan": [...]
}
```

---

## 🔗 API Endpoints Reference

### Analysis

- `POST /api/analyze` - Upload ZIP and analyze
- `POST /api/analyze/repo` - Clone GitHub repo and analyze

### Dashboard

- `GET /api/security/summary` - Executive summary
- `GET /api/security/charts` - All chart data
- `GET /api/security/findings` - Paginated findings
- `GET /api/security/finding/<id>` - Detailed finding
- `GET /api/security/remediation` - Remediation plan
- `GET /api/security/refresh` - Trigger re-scan

### Chat (API v2)

- `POST /api/v2/chat/message` - Send message
- `GET /api/v2/chat/stream` - SSE streaming
- `GET /api/v2/chat/conversations` - List conversations
- `DELETE /api/v2/chat/conversation/<id>` - Delete conversation

### Query

- `POST /api/query` - Natural language security query

---

## 🎓 Use Cases

### 1. Enterprise Security Audits

- Full codebase scanning before deployment
- Compliance reporting (OWASP Top 10)
- Risk scoring for prioritization

### 2. Open Source Project Scanning

- Scan public repositories
- CVE detection in dependencies
- Contribution quality checks

### 3. Educational Code Review

- Learn security best practices
- Understand vulnerability patterns
- AI-explained security issues

### 4. CI/CD Integration

- Automated security gates
- PR review automation
- Continuous monitoring

### 5. Startup Pre-Investment Audit

- Technical due diligence
- Security posture assessment
- Risk quantification

---

## 🛡️ OWASP Top 10 2021 Coverage

| OWASP Category                     | Detection Methods       | Coverage     |
| ---------------------------------- | ----------------------- | ------------ |
| **A01: Broken Access Control**     | Semgrep, LLM Agent      | ✅ High      |
| **A02: Cryptographic Failures**    | Secret Detector, Bandit | ✅ High      |
| **A03: Injection**                 | Bandit, Semgrep, LLM    | ✅ Very High |
| **A04: Insecure Design**           | LLM Agent               | ✅ Medium    |
| **A05: Security Misconfiguration** | Linters, LLM            | ✅ High      |
| **A06: Vulnerable Components**     | CVE Tracker, OSV        | ✅ Very High |
| **A07: Auth Failures**             | Bandit, Semgrep         | ✅ High      |
| **A08: Data Integrity Failures**   | Semgrep, LLM            | ✅ Medium    |
| **A09: Logging Failures**          | LLM Agent               | ✅ Low       |
| **A10: SSRF**                      | Semgrep, LLM            | ✅ Medium    |

---

## 💡 Tips & Best Practices

### For Best Results:

1. **Configure API Keys** - Set OpenAI/Anthropic key for LLM features
2. **Enable All Phases** - Best results with all 6 phases enabled
3. **Use Local Embeddings** - Save costs with `EMBEDDING_PROVIDER=local`
4. **Start with Small Repos** - Test on small projects first
5. **Review Dashboard** - Interactive dashboard is the best way to explore findings
6. **Ask Questions** - Use chat/query for specific concerns
7. **Refresh Regularly** - Use refresh button for latest scan

### Performance Tips:

- Disable `ENABLE_PYLINT` for faster scans
- Use `CHUNK_STRATEGY=function` for better granularity
- Set `MAX_WORKERS=8` on powerful machines
- Enable `CACHE_EMBEDDINGS=true` to avoid regeneration

---

## 📚 Additional Resources

- **Detailed Architecture**: See `README_ARCHITECTURE.md`
- **User Guide**: See `README.md`
- **Configuration**: See `.env.example`
- **API Documentation**: Check inline API docs in `app.py`

---

## 🏆 Project Highlights

### Achievements:

- ✅ 6-phase pipeline fully integrated
- ✅ Multi-LLM provider support (OpenAI, Anthropic, Mistral)
- ✅ RAG-enhanced query system
- ✅ Real-time dashboard with Chart.js
- ✅ Conversational AI with streaming
- ✅ CVE detection with OWASP mapping
- ✅ Automated fix generation
- ✅ Production-ready architecture

### Code Metrics:

- **Total Python Files**: ~50+
- **Total Lines of Code**: ~10,000+
- **Core Components**: 8 major modules
- **API Endpoints**: 20+ routes
- **Supported Languages**: Python, Java, JavaScript, Go, C++, Ruby, PHP
- **Linters Integrated**: 4 (Bandit, Semgrep, Ruff, Pylint)
- **LLM Providers**: 3 (OpenAI, Anthropic, Mistral)
- **Vector Stores**: 2 (Qdrant, FAISS)

---

**Last Updated:** January 2026  
**Status:** Production-Ready (6 Phases Complete)  
**Maintainer:** Krushna56/ai_code_review
