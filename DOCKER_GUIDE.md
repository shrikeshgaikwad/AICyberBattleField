# Docker Setup Guide for AI Cyber Battlefield

## Overview
This project uses Docker and Docker Compose to containerize the AI Cyber Battlefield application with support for:
- **Ollama** - LLM service for AI capabilities
- **PostgreSQL** - Data persistence
- **Redis** - Caching and session management
- **pgAdmin** - Database management UI (development)

## Quick Start

### Prerequisites
- Docker Desktop installed ([Download](https://www.docker.com/products/docker-desktop))
- 16GB+ RAM recommended
- 20GB+ disk space for images and data

### 1. Setup Environment Variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your specific values
# Important: Change all default passwords in production
```

### 2. Build and Start Containers
```bash
# Using Docker Compose directly
docker-compose build
docker-compose up -d

# Or using Makefile (easier)
make build
make up
```

### 3. Verify Services Are Running
```bash
docker-compose ps
# or
make ps
```

### 4. Wait for Health Checks
```bash
# Check service health
make health

# Expected output:
# cyber_battle_app      (running)
# ollama_service        (running)
# cyber_db              (running)
# cyber_redis           (running)
```

## Services

### Ollama (http://localhost:11434)
- **Purpose**: LLM inference engine
- **Models**: Llama2, Mistral, Neural Chat, etc.
- **Health Check**: `curl http://localhost:11434/api/tags`

### PostgreSQL (localhost:5432)
- **Purpose**: Data persistence
- **Credentials**: See `.env` file
- **Database**: cyber_battlefield
- **Shell Access**: `make db-shell`

### Redis (localhost:6379)
- **Purpose**: Caching and sessions
- **Password**: See `.env` file

### pgAdmin (http://localhost:5050)
- **Purpose**: Web-based database management
- **Credentials**: See `.env` file
- **Note**: Only available in development (use `make up`, not production)

### AI Cyber Battlefield App
- **Ports**: 8000, 8080
- **Logs**: `make logs-app`
- **Shell**: `make shell`

## Common Tasks

### Viewing Logs
```bash
# All services
make logs

# Specific service
make logs-app      # Application logs
make logs-db       # Database logs
make logs-ollama   # Ollama logs
```

### Database Operations
```bash
# Open database shell
make db-shell

# Reset database (careful!)
make db-reset

# Backup database
make db-backup
```

### Container Inspection
```bash
# View running containers
make ps

# Live resource usage
make stats

# Check container health
make health
```

### Ollama Model Management
```bash
# List installed models
make list-models

# Pull a model
make pull-models MODEL=mistral:latest

# Download common models
make install-models
```

## Development Workflow

### Interactive Shell Access
```bash
# Access application shell
make shell

# Run Python commands
docker-compose exec cyber_battle python -c "print('Hello')"

# Run tests
docker-compose exec cyber_battle python -m pytest tests/
```

### Code Hot-Reload
The application directory is mounted as a volume (`-v .:/app`), so:
- Changes to Python files are immediately reflected
- No container rebuild needed for code changes
- Restart the service if needed: `docker-compose restart cyber_battle`

### Install Python Dependencies
```bash
# Update requirements.txt, then rebuild
docker-compose build
docker-compose up -d

# Or in a running container
docker-compose exec cyber_battle pip install package_name
```

## Production Deployment

### Using Production Profile
```bash
# Uses docker-compose.prod.yml for production optimizations
make prod-up
make prod-logs
make prod-down
```

### Production Features
- Resource limits enforced
- No interactive TTY
- pgAdmin disabled
- Restart policies configured
- Optimized logging
- Port 5432 (DB) not exposed

### Environment Configuration
```bash
# Create production .env
cp .env.example .env.prod

# Update with production values:
# - Strong passwords
# - Production API keys
# - Resource settings
# - Domain names

# Deploy
export ENV_FILE=.env.prod
make prod-up
```

## Troubleshooting

### Services Not Starting
```bash
# Check logs
make logs

# Check health
make health

# Rebuild everything
make rebuild
```

### Database Connection Issues
```bash
# Verify database is running and healthy
docker-compose logs postgres

# Test connection
make db-shell

# Check environment variables
docker-compose config | grep DB_
```

### Out of Disk Space
```bash
# Clean up unused volumes
make volume-prune

# Clean unused images
make image-prune

# Full cleanup
docker system prune -a
```

### Memory Issues
- Reduce Ollama model size (use `mistral:7b-lite` instead of `llama2:13b`)
- Increase Docker memory allocation in Docker Desktop settings
- Check `make stats`

### Port Already in Use
```bash
# Find process using port (Windows PowerShell)
Get-NetTCPConnection -LocalPort 5432

# Change port in docker-compose.yml
# ports:
#   - "5433:5432"  # Use 5433 instead
```

## Advanced Configuration

### Custom Network Configuration
See `docker-compose.yml` - uses `cyber_network` bridge network

### Volume Management
```bash
# List volumes
docker volume ls | grep cyber

# Inspect volume
docker volume inspect cyber_results

# Delete specific volume
docker volume rm cyber_results
```

### Resource Limits (Production)
Set in `docker-compose.prod.yml`:
```yaml
cpus: '2'      # Max 2 CPU cores
memory: 2G     # Max 2GB RAM
```

## Security Best Practices

1. **Change All Passwords**
   - DB password
   - Redis password
   - pgAdmin password

2. **Use .env Files**
   - Don't commit `.env` to git
   - Use `.env.example` as template

3. **Network Isolation**
   - Don't expose internal services to internet
   - Use VPN/firewall in production

4. **Container Updates**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

5. **Log Rotation**
   - Configured in `docker-compose.yml`
   - Max file size: 50MB (production), 10MB (development)

## Database Schema

The database initialization script (`init_db.sql`) creates:
- `cyber_data` schema: Scan results and vulnerabilities
- `logs` schema: Audit trails and events
- Tables: `scan_results`, `vulnerabilities`, `agent_actions`, `ai_decisions`, `system_events`
- Views: `latest_scans`, `vulnerability_summary`

Connect to DB and explore:
```bash
make db-shell

# In psql:
\dt cyber_data.*
\dt logs.*
SELECT * FROM cyber_data.latest_scans;
```

## Backup and Restore

### Backup
```bash
make db-backup
# Creates: backup_YYYYMMDD_HHMMSS.sql
```

### Restore
```bash
# Copy backup file, then:
docker-compose exec -T postgres psql -U cyber_user cyber_battlefield < backup_YYYYMMDD_HHMMSS.sql
```

## Useful Docker Compose Commands

```bash
# View service configuration
docker-compose config

# Restart specific service
docker-compose restart cyber_battle

# Scale service (if configured)
docker-compose up -d --scale service_name=3

# Remove old data and rebuild
docker-compose down -v && docker-compose up -d

# Check service dependencies
docker-compose logs --tail=100 cyber_battle
```

## References

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Ollama Documentation](https://github.com/ollama/ollama)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Redis Documentation](https://redis.io/documentation)

## Support

For issues or questions:
1. Check logs: `make logs`
2. Verify services: `make health`
3. Review `.env` configuration
4. Check Docker Desktop settings (memory, disk)
