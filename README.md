# AI-Powered Code Review Platform

A next-generation AI-driven code review platform using hybrid ML + LLM architecture. Combines classical machine learning, deep learning models, semantic embeddings, and specialized LLM agents to provide comprehensive, context-aware code reviews.

Features

**Dependency Vulnerability Scanning** (Phase 4 - NEW!)

- Automatic dependency detection (Maven, Gradle, npm, Python)
- CVE detection using OSV API
- OWASP Top 10 2021 category mapping
- Severity-based risk scoring
- Comprehensive security reports

**Security Reporting & Recommendations** (Phase 5 - NEW!)

- Executive security summaries with risk scoring
- Automated fix suggestions for common vulnerabilities
- Multi-format reports (JSON, Markdown)
- Dashboard-ready data exports for visualization
- OWASP Top 10 breakdown and analysis
- Remediation plans with effort estimates

**Multi-Layer Static Analysis**

- AST parsing with comprehensive code metrics (LOC, WMC, DIT, LCOM, Complexity)
- Multiple linters: Bandit (security), Semgrep (patterns), Pylint (quality), Ruff (style)
- Automated code formatting with autopep8

**Semantic Code Understanding**

- Code embeddings using OpenAI or local sentence-transformers
- FAISS vector store for semantic code search
- RAG-enhanced context for LLM agents

**Intelligent LLM Agents**

- SecurityReviewer: Deep security vulnerability analysis
- RefactorAgent: Code quality and refactoring suggestions
- Chain-of-thought prompting with contextual awareness

**Flexible Configuration**

- CPU-optimized for systems without GPU
- Feature flags to enable/disable components
- Support for OpenAI and Anthropic LLMs
- Local or API-based embeddings

**Comprehensive Reporting**

- Detailed metrics and analysis results
- Before/after code diffs with highlighting
- Severity-based issue prioritization
- JSON, Markdown, and HTML export

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

1. **Clone the repository**

```bash
git clone https://github.com/Krushna56/ai_code_review.git
cd ai_code_review
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Configure environment**

```bash
# Copy the example environment file
copy .env.example .env

# Edit .env and add your API keys
# Required: OPENAI_API_KEY or ANTHROPIC_API_KEY
# Optional: Configure embedding provider, models, feature flags
```

### Configuration Options

Edit `.env` to customize:

**LLM Provider** (choose one):

- `LLM_PROVIDER=openai` with `OPENAI_API_KEY`
- `LLM_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`

**Embedding Provider**:

- `EMBEDDING_PROVIDER=local` (free, uses sentence-transformers)
- `EMBEDDING_PROVIDER=openai` (paid, higher quality)

**Feature Flags**:

- `ENABLE_BANDIT=true` - Security scanning
- `ENABLE_SEMGREP=true` - Pattern-based analysis
- `ENABLE_PYLINT=false` - Code quality (can be slow)
- `ENABLE_RUFF=true` - Fast Python linter
- `ENABLE_LLM_AGENTS=true` - AI-powered insights
- `ENABLE_SEMANTIC_SEARCH=true` - Vector-based code search

## Usage

### Web Interface

```bash
python app.py
```

Navigate to `http://localhost:5000` and upload a ZIP file containing your codebase.

### Command-Line Interface

```python
from code_analysis import analyze_codebase

results = analyze_codebase(
    input_path="path/to/code",
    output_path="path/to/output"
)

print(results['summary'])
print(results['security'])
```

### CVE Detection

```bash
# Scan project dependencies for CVEs
python cli.py cve-check ./my-java-project

# Save results to JSON
python cli.py cve-check ./my-nodejs-app --output cve-results.json
```

Supported dependency files:

- Maven: `pom.xml`
- Gradle: `build.gradle`, `build.gradle.kts`
- npm: `package.json`, `package-lock.json`
- Python: `requirements.txt`, `Pipfile`, `pyproject.toml`

````

### Python API

```python
from static_analysis import analyze_file
from llm_agents import SecurityReviewer, RefactorAgent

# Analyze a single file
metrics = analyze_file("example.py")
print(f"Complexity: {metrics['complexity']}")

# Use LLM agents
security_agent = SecurityReviewer()
with open("example.py") as f:
    code = f.read()

result = security_agent.analyze(code)
print(result['analysis'])
````

## Architecture

### Layers

1. **Static Intelligence Layer**

   - AST parsing and metrics extraction
   - Multi-linter integration (Bandit, Semgrep, Pylint, Ruff)

2. **Embedding Layer**

   - Code embeddings (OpenAI or local)
   - FAISS vector store for semantic search

3. **LLM Agent Layer**

   - SecurityReviewer for vulnerability analysis
   - RefactorAgent for code quality improvements
   - RAG-enhanced context

4. **Meta-Reasoning Layer** (coming soon)
   - Issue deduplication and prioritization
   - Confidence scoring
   - Structured reporting

## Static Analysis Tools

### Bandit (Security)

- Identifies common security issues in Python code
- Checks for SQL injection, XSS, insecure crypto, etc.

### Semgrep (Patterns)

- Multi-language pattern-based scanner
- Supports Python, JavaScript, Java, Go, and more
- Custom rule definitions

### Pylint (Code Quality)

- Comprehensive Python linter
- Checks coding standards, refactoring opportunities
- Can be slow on large codebases (disabled by default)

### Ruff (Style)

- Extremely fast Python linter written in Rust
- Replaces Flake8, isort, and more
- Recommended for quick feedback

## Performance

**CPU-Optimized:**

- Uses pre-trained models (no GPU training required)
- Smaller model variants (CodeBERT-base, MiniLM)
- Batch processing for efficiency
- Optional ONNX runtime for faster inference

**Expected Analysis Time:**

- Small repo (10 files, ~1000 LOC): < 30 seconds
- Medium repo (100 files, ~10,000 LOC): < 3 minutes
- Large repo (1000 files, ~100,000 LOC): < 15 minutes

## Project Structure

```
ai_code_review/
├── config.py                 # Configuration management
├── app.py                    # Flask web application
├── code_analysis.py          # Main analysis pipeline
├── requirements.txt          # Dependencies
├── .env.example              # Environment template
├── static_analysis/          # AST parser, multi-linter
├── embeddings/               # Code embedder, vector store
├── llm_agents/               # LLM agent implementations
├── ml_models/                # ML models (future)
├── dl_models/                # Deep learning models (future)
├── meta_reasoner/            # Issue aggregation (future)
├── templates/                # HTML templates
├── static/                   # CSS, JS
└── tests/                    # Unit and integration tests
```

## API Costs

**OpenAI (if using API-based features):**

- Embeddings: `text-embedding-3-small` (~$0.02 per 1M tokens)
- LLM: `gpt-4-turbo-preview` (~$10 per 1M input tokens)

**Free Alternatives:**

- Use `EMBEDDING_PROVIDER=local` for free embeddings
- Caching reduces redundant API calls
- Feature flags allow disabling expensive components

## Future Enhancements

- [x] Dependency vulnerability scanning (Phase 4 - COMPLETE)
- [x] CVE detection with OSV API (Phase 4 - COMPLETE)
- [x] OWASP Top 10 mapping (Phase 4 - COMPLETE)
- [x] Security reporting with fix suggestions (Phase 5 - COMPLETE)
- [x] Dashboard data exports (Phase 5 - COMPLETE)
- [ ] Web dashboard UI (Phase 6)
- [ ] ML risk prediction models
- [ ] Deep learning with CodeBERT/GraphCodeBET
- [ ] GitHub integration and PR review bot
- [ ] Interactive web dashboard
- [ ] Feedback loop and model retraining
- [ ] Multi-language support expansion
- [ ] IDE plugin integration

## Contributing

Contributions are welcome!

1. Fork the repo
2. Create your branch (`git checkout -b feature/xyz`)
3. Commit your changes (`git commit -m "Add feature"`)
4. Push to the branch (`git push origin feature/xyz`)
5. Open a Pull Request

## License

MIT License

## Acknowledgments

- Built with OpenAI GPT-4 and Anthropic Claude
- Uses HuggingFace Transformers
- FAISS for vector search
- Bandit, Semgrep, Pylint, Ruff for static analysis
