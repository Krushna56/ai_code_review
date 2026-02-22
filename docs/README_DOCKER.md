# Docker Deployment Guide - AI Code Review Platform

This guide explains how to deploy the AI Code Review Platform using Docker and Docker Compose.

## 📋 Prerequisites

- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 2.0 or higher
- **API Keys**: At least one LLM provider API key (OpenAI, Anthropic, or Mistral)

## 🚀 Quick Start

### 1. Configure Environment Variables

Copy the example environment file and configure your settings:

```bash
cp .env.docker .env
```

Edit `.env` and add your API keys:

```bash
# Required: At least one LLM API key
OPENAI_API_KEY=sk-your-openai-api-key-here
# OR
ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key-here
# OR
MISTRAL_API_KEY=your-mistral-api-key-here

# Important: Change this in production!
SECRET_KEY=your-secure-random-secret-key
```

### 2. Build and Start Services

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check service status
docker-compose ps
```

### 3. Access the Application

- **Web Interface**: http://localhost:5000
- **Qdrant Dashboard**: http://localhost:6333/dashboard
- **Health Check**: http://localhost:5000/health

### 4. Create Your First User

Navigate to http://localhost:5000 and register a new account.

## 🏗️ Architecture

The Docker deployment consists of two main services:

### 1. **app** - AI Code Review Platform

- Flask web application
- Python 3.11 slim base image
- Runs on port 5000
- Includes all analysis tools (Bandit, Semgrep, Ruff)

### 2. **qdrant** - Vector Database

- Stores code embeddings for semantic search
- Runs on ports 6333 (HTTP) and 6334 (gRPC)
- Persistent storage via Docker volume

## 📦 Docker Commands

### Starting Services

```bash
# Start in background
docker-compose up -d

# Start with rebuild
docker-compose up -d --build

# Start specific service
docker-compose up -d app
```

### Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

### Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f app
docker-compose logs -f qdrant

# Last 100 lines
docker-compose logs --tail=100 app
```

### Accessing Container Shell

```bash
# Access app container
docker-compose exec app bash

# Access as root (for debugging)
docker-compose exec -u root app bash
```

### Rebuilding Images

```bash
# Rebuild without cache
docker-compose build --no-cache

# Rebuild and restart
docker-compose up -d --build
```

## 🔧 Configuration

### Environment Variables

All configuration is done via environment variables in the `.env` file:

#### Authentication

- `SECRET_KEY`: Flask secret key (change in production!)
- `GITHUB_CLIENT_ID`: GitHub OAuth client ID (optional)
- `GITHUB_CLIENT_SECRET`: GitHub OAuth secret (optional)

#### LLM Configuration

- `LLM_PROVIDER`: `openai`, `anthropic`, or `mistral`
- `LLM_MODEL`: Model name (e.g., `gpt-4-turbo-preview`)
- `LLM_TEMPERATURE`: Temperature for generation (0.0-1.0)
- `LLM_MAX_TOKENS`: Maximum tokens for responses

#### Embedding Configuration

- `EMBEDDING_PROVIDER`: `local` (free) or `openai`
- `LOCAL_EMBEDDING_MODEL`: Model for local embeddings
- `OPENAI_EMBEDDING_MODEL`: OpenAI embedding model

#### Feature Flags

- `ENABLE_ML_ANALYSIS`: Enable ML-based analysis
- `ENABLE_LLM_AGENTS`: Enable LLM agents
- `ENABLE_CVE_DETECTION`: Enable CVE detection
- `ENABLE_SEMANTIC_SEARCH`: Enable semantic code search

### Persistent Data

The following directories are mounted as volumes for data persistence:

- `./uploads`: Uploaded code repositories
- `./processed`: Analysis results
- `./output`: Generated reports
- `./instance`: SQLite database
- `./models`: ML models
- `./vector_db`: Vector database cache
- `qdrant_storage`: Qdrant data (Docker volume)

## 🔒 Security Best Practices

### 1. Change Default Secrets

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

Add to `.env`:

```
SECRET_KEY=<generated-key>
```

### 2. Use Environment-Specific Configurations

For production, create a separate `.env.production` file:

```bash
docker-compose --env-file .env.production up -d
```

### 3. Restrict Network Access

Modify `docker-compose.yml` to only expose necessary ports:

```yaml
services:
  app:
    ports:
      - "127.0.0.1:5000:5000" # Only localhost
```

### 4. Run with Limited Resources

Add resource limits to `docker-compose.yml`:

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 4G
```

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs app

# Check if ports are already in use
netstat -an | grep 5000
netstat -an | grep 6333

# Restart services
docker-compose restart
```

### Database Issues

```bash
# Reinitialize database
docker-compose exec app python -c "from models.user import User; User.init_db()"

# Reset database (WARNING: deletes all users)
rm -rf instance/users.db
docker-compose restart app
```

### Qdrant Connection Issues

```bash
# Check Qdrant health
curl http://localhost:6333/health

# Restart Qdrant
docker-compose restart qdrant

# Check Qdrant logs
docker-compose logs qdrant
```

### Out of Memory

```bash
# Check container resource usage
docker stats

# Increase Docker memory limit in Docker Desktop settings
# Or add memory limits to docker-compose.yml
```

### Permission Issues

```bash
# Fix permissions on mounted volumes
sudo chown -R 1000:1000 uploads processed output instance models vector_db
```

## 📊 Monitoring

### Health Checks

```bash
# App health
curl http://localhost:5000/health

# Qdrant health
curl http://localhost:6333/health
```

### Resource Usage

```bash
# Real-time stats
docker stats

# Container inspection
docker-compose exec app top
```

### Logs

```bash
# Follow all logs
docker-compose logs -f

# Export logs
docker-compose logs > app.log
```

## 🔄 Updates and Maintenance

### Updating the Application

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

### Backup Data

```bash
# Backup volumes
docker run --rm -v ai_code_review_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar czf /backup/qdrant-backup.tar.gz /data

# Backup application data
tar czf backup-$(date +%Y%m%d).tar.gz uploads processed output instance models
```

### Restore Data

```bash
# Restore Qdrant volume
docker run --rm -v ai_code_review_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar xzf /backup/qdrant-backup.tar.gz -C /

# Restore application data
tar xzf backup-YYYYMMDD.tar.gz
```

## 🌐 Production Deployment

### Using a Reverse Proxy (Nginx)

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Using HTTPS with Let's Encrypt

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
```

### Environment-Specific Compose Files

Create `docker-compose.prod.yml`:

```yaml
version: "3.8"

services:
  app:
    restart: always
    environment:
      - FLASK_ENV=production
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: 8G
```

Run with:

```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## 📝 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Qdrant Documentation](https://qdrant.tech/documentation/)

## 🆘 Support

If you encounter issues:

1. Check the logs: `docker-compose logs -f`
2. Verify environment variables: `docker-compose config`
3. Check service health: `docker-compose ps`
4. Review the main README.md for application-specific issues

## 📄 License

See the main project LICENSE file for details.
