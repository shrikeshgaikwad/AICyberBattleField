# Quick Start Guide - Docker Setup

## 🚀 Quick Launch (30 seconds)

```bash
# 1. Setup environment
cp .env.example .env

# 2. Build and start
docker-compose up -d

# 3. Verify health
python docker-health-check.py
# or
docker-compose ps
```

## 📋 What Gets Created

| Service | Port | Purpose |
|---------|------|---------|
| **Ollama** | 11434 | LLM inference engine |
| **PostgreSQL** | 5432 | Database |
| **Redis** | 6379 | Cache & sessions |
| **App** | 8000-8080 | Main application |
| **pgAdmin** | 5050 | DB management (dev) |

## 🛠️ Common Commands

```bash
# View logs
make logs              # All services
make logs-app         # Just the app

# Access containers
make shell            # App bash shell
make db-shell         # PostgreSQL shell

# Database operations
make db-backup        # Backup database
make db-reset         # Clear database

# Container management
make up               # Start
make down             # Stop
make rebuild          # Full rebuild
make clean            # Remove everything

# Database info
make ps               # Show containers
make health           # Check health
make stats            # Resource usage
```

## 🔍 Health Check

```bash
# Python (Windows/Mac/Linux)
python docker-health-check.py

# Bash (Linux/Mac)
bash docker-health-check.sh

# Manual checks
docker-compose ps
docker-compose logs
```

## 📦 Installation & Dependencies

The Docker setup installs:
- nmap, curl, net-tools, dnsutils, postgresql-client
- All Python packages from `requirements.txt`
- Ollama with LLM models

## 🔐 Security

Important: **Change default passwords in `.env`**
- `DB_PASSWORD` → PostgreSQL admin password
- `REDIS_PASSWORD` → Redis password  
- `PGADMIN_PASSWORD` → pgAdmin password

## 📚 Documentation

- **Full Guide**: Read [DOCKER_GUIDE.md](DOCKER_GUIDE.md)
- **Docker Compose**: [docker-compose.yml](docker-compose.yml)
- **Production Setup**: [docker-compose.prod.yml](docker-compose.prod.yml)
- **Database Schema**: [init_db.sql](init_db.sql)

## ⚡ Development Workflow

1. **Code changes** → Automatically reflected (volume mount)
2. **New dependencies** → Update `requirements.txt`, then rebuild
3. **Database changes** → Use `docker-compose exec postgres psql`
4. **Test code** → `docker-compose exec cyber_battle python -m pytest tests/`

## 🚨 Troubleshooting

| Issue | Solution |
|-------|----------|
| Services won't start | Check logs: `docker-compose logs` |
| Port already in use | Change port in `docker-compose.yml` |
| Out of memory | Increase Docker memory or reduce model size |
| Database locked | Run `make db-reset` |
| Permission denied | Run with appropriate user/sudo |

## 📱 Access Points

```
Application:   http://localhost:8000
              http://localhost:8080

Ollama API:    http://localhost:11434

pgAdmin:       http://localhost:5050
              (admin@cyberfield.local / admin123)

Database:      localhost:5432
              (cyber_user / dev_password)

Redis:         localhost:6379
              (password: dev_redis_pass)
```

## 🎯 Environment Variables

Key variables in `.env`:
```bash
# Application
DEBUG=true        # Enable debug mode
LOG_LEVEL=DEBUG   # Logging level

# Database
DB_HOST=postgres
DB_USER=cyber_user
DB_PASSWORD=dev_password

# Redis
REDIS_HOST=redis
REDIS_PASSWORD=dev_redis_pass

# Ollama  
OLLAMA_URL=http://ollama:11434/api/generate
MODEL=llama2:13b
```

## 🔄 Updating Services

```bash
# Update Docker images
docker-compose pull

# Restart with latest
docker-compose up -d

# Update Python packages
docker-compose build --no-cache
docker-compose up -d
```

## 📊 Monitoring

```bash
# Live stats
docker stats

# Log monitoring
docker-compose logs -f [service_name]

# Container inspection
docker-compose inspect [service_name]
```

## 🛑 Clean Up

```bash
# Stop containers (keep data)
docker-compose down

# Remove everything (danger!)
docker-compose down -v
docker system prune -a

# Remove specific volume
docker volume rm cyber_results
```

## 🎓 Learning Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Compose Guide](https://docs.docker.com/compose/)
- [PostgreSQL Tips](https://www.postgresql.org/docs/current/sql.html)
- [Redis Commands](https://redis.io/commands)

---

**Need help?** Check [DOCKER_GUIDE.md](DOCKER_GUIDE.md) for detailed documentation
