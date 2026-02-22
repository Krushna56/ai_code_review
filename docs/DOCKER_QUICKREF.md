# Docker Quick Reference - AI Code Review Platform

## 🚀 Getting Started

```bash
# 1. Configure environment
cp .env.docker .env
# Edit .env with your API keys

# 2. Start services
docker-compose up -d

# 3. Access application
# Open http://localhost:5000 in your browser
```

## 📋 Essential Commands

### Service Management

```bash
# Start all services
docker-compose up -d

# Start with rebuild
docker-compose up -d --build

# Stop all services
docker-compose down

# Restart services
docker-compose restart

# Stop and remove volumes (⚠️ DELETES DATA)
docker-compose down -v
```

### Logs and Monitoring

```bash
# View all logs
docker-compose logs -f

# View app logs only
docker-compose logs -f app

# View Qdrant logs
docker-compose logs -f qdrant

# Last 100 lines
docker-compose logs --tail=100 app

# Check service status
docker-compose ps

# Resource usage
docker stats
```

### Container Access

```bash
# Access app container shell
docker-compose exec app bash

# Access as root (for debugging)
docker-compose exec -u root app bash

# Run Python in container
docker-compose exec app python

# Run one-off command
docker-compose exec app python -c "from models.user import User; User.init_db()"
```

### Building and Updating

```bash
# Rebuild without cache
docker-compose build --no-cache

# Rebuild specific service
docker-compose build app

# Pull latest images
docker-compose pull

# Update and restart
git pull
docker-compose up -d --build
```

## 🔧 Troubleshooting

### Check Health

```bash
# App health
curl http://localhost:5000/health

# Qdrant health
curl http://localhost:6333/health

# Service status
docker-compose ps
```

### Reset Database

```bash
# Reinitialize database
docker-compose exec app python -c "from models.user import User; User.init_db()"

# Or delete and restart
docker-compose down
rm -rf instance/users.db
docker-compose up -d
```

### Fix Permissions

```bash
# On Linux/Mac
sudo chown -R 1000:1000 uploads processed output instance models vector_db

# On Windows (PowerShell as Admin)
icacls uploads /grant Users:F /t
```

### Port Already in Use

```bash
# Find process using port 5000
# Windows
netstat -ano | findstr :5000

# Linux/Mac
lsof -i :5000

# Kill process or change port in docker-compose.yml
```

### Out of Memory

```bash
# Check memory usage
docker stats

# Add memory limit to docker-compose.yml:
# deploy:
#   resources:
#     limits:
#       memory: 4G
```

## 💾 Backup and Restore

### Backup

```bash
# Backup application data
tar czf backup-$(date +%Y%m%d).tar.gz uploads processed output instance models

# Backup Qdrant volume
docker run --rm -v ai_code_review_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar czf /backup/qdrant-backup.tar.gz /data
```

### Restore

```bash
# Restore application data
tar xzf backup-YYYYMMDD.tar.gz

# Restore Qdrant volume
docker run --rm -v ai_code_review_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar xzf /backup/qdrant-backup.tar.gz -C /
```

## 🔍 Debugging

### View Configuration

```bash
# Show resolved configuration
docker-compose config

# Check environment variables
docker-compose exec app env | grep -E "LLM|QDRANT|ENABLE"
```

### Test Components

```bash
# Test Qdrant connection
docker-compose exec app python -c "
from qdrant_client import QdrantClient
client = QdrantClient(host='qdrant', port=6333)
print(client.get_collections())
"

# Test LLM connection (requires API key)
docker-compose exec app python -c "
import config
print(f'LLM Provider: {config.LLM_PROVIDER}')
print(f'API Key Set: {bool(config.OPENAI_API_KEY)}')
"
```

### Clean Up

```bash
# Remove stopped containers
docker-compose rm

# Remove unused images
docker image prune

# Remove all unused resources
docker system prune -a

# Free up space (⚠️ removes everything not in use)
docker system prune -a --volumes
```

## 📊 Production Tips

### Resource Limits

Add to `docker-compose.yml`:

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 4G
        reservations:
          cpus: "1"
          memory: 2G
```

### Environment Files

```bash
# Use production environment
docker-compose --env-file .env.production up -d

# Override compose file
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Monitoring

```bash
# Continuous monitoring
watch -n 5 'docker-compose ps && docker stats --no-stream'

# Export logs
docker-compose logs > app-logs-$(date +%Y%m%d).log
```

## 🌐 URLs

- **Application**: http://localhost:5000
- **Dashboard**: http://localhost:5000/dashboard
- **Chat Interface**: http://localhost:5000/chat
- **Health Check**: http://localhost:5000/health
- **Qdrant UI**: http://localhost:6333/dashboard
- **Qdrant API**: http://localhost:6333

## 📚 More Information

See [README_DOCKER.md](README_DOCKER.md) for comprehensive documentation.
